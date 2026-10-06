import json
import re
import threading
import zipfile
import os
import secrets
import subprocess
import tempfile
from urllib.request import urlopen
import ssl
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
import pexpect

# The only external request is the official CHR image download.
# Test API requests remain inside this container, via QEMU's user network.
version = "7.16.2"
artifacts = Path(os.environ.get("ARTIFACTS_DIR", "/artifacts"))
artifacts.mkdir(parents=True, exist_ok=True)
workspace = tempfile.TemporaryDirectory(prefix="po0fw-chr-")
work = Path(workspace.name)
production = Path("/repo/po0-firewall-whitelist.rsc").read_text()
cache = Path(os.environ.get("CACHE_DIR", "/cache"))
cache.mkdir(parents=True, exist_ok=True)
image_zip = cache / f"chr-{version}.img.zip"
if not image_zip.exists():
    print(f"Downloading official MikroTik CHR {version}...", flush=True)
    partial = image_zip.with_suffix(".zip.part")
    try:
        with urlopen(f"https://download.mikrotik.com/routeros/{version}/chr-{version}.img.zip", timeout=30) as response, partial.open("wb") as target:
            downloaded = 0
            while chunk := response.read(1024 * 1024):
                target.write(chunk)
                downloaded += len(chunk)
                print(f"Downloaded {downloaded // (1024 * 1024)} MiB", flush=True)
        partial.replace(image_zip)
    finally:
        partial.unlink(missing_ok=True)
else:
    print(f"Using cached official CHR {version} image", flush=True)
with zipfile.ZipFile(image_zip) as archive:
    image = work / f"chr-{version}.img"
    image.write_bytes(archive.read(image.name))

def openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
        "-subj", "/CN=po0fw-runtime-test", "-keyout", str(work / "ca.key"), "-out", str(work / "ca.crt"),
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
openssl("req", "-newkey", "rsa:2048", "-nodes", "-sha256", "-subj", "/CN=po0fw-test-api",
        "-keyout", str(work / "api.key"), "-out", str(work / "api.csr"))
(work / "api.ext").write_text("subjectAltName=IP:10.0.2.2\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
openssl("x509", "-req", "-in", str(work / "api.csr"), "-CA", str(work / "ca.crt"),
        "-CAkey", str(work / "ca.key"), "-CAcreateserial", "-out", str(work / "api.crt"),
        "-days", "2", "-sha256", "-extfile", str(work / "api.ext"))

requests = []
tokens = ["object", "legacy", "mixed", "mismatch", "exactmismatch", "pinned@0", "wrongpin@0", "disabled", "badjson", "badip", "forbidden", "limited", "bad/token", "slot10@10"]
source = production.replace(':local tokens {"pgnfw_REPLACE_ME"}', ':local tokens {' + ';'.join('"pgnfw_' + t + '"' for t in tokens) + '}')
source, replacements = re.subn(r':local apiBase "[^"\n]+"', ':local apiBase "https://10.0.2.2:18443/api/firewall/"', source)
assert replacements == 1, "Expected exactly one apiBase setting; refusing to test a live endpoint"
assert 'https://10.0.2.2:18443/api/firewall/' in source

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        self.send_response(200); self.end_headers()
        if self.path == '/production.rsc': body=production.encode()
        elif self.path == '/ca.crt': body=(work / 'ca.crt').read_bytes()
        elif self.path == '/test.rsc': body=source.encode()
        else: body=b''
        self.wfile.write(body)
    def do_POST(self):
        parsed = urlsplit(self.path)
        token = parsed.path.split('/')[-2]
        case = token.removeprefix('pgnfw_')
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        requests.append((case, parse_qs(parsed.query), body, self.headers.get('Authorization')))
        result = {'enabled':True, 'whitelist':[{'ip':'203.0.113.0/24', 'slot':None}], 'currentIp':'203.0.113.7', 'limit':5}
        status = 200
        if case == 'legacy': result['whitelist'] = ['203.0.113.7']
        if case == 'mixed': result['currentIp'] = '203.0.113.0/24'; result['whitelist'] = ['203.0.113.99']
        if case == 'mismatch': result['whitelist'] = ['198.51.100.0/24']
        if case == 'exactmismatch': result['whitelist'] = ['203.0.113.8']
        if case == 'pinned': result['whitelist'][0]['slot'] = 0
        if case == 'wrongpin': result['whitelist'][0]['slot'] = 1
        if case == 'slot10': result['whitelist'][0]['slot'] = 10; result['limit'] = 12
        if case == 'disabled': result['enabled'] = False
        if case == 'badip': result['currentIp'] = 'garbage'; result['whitelist'] = ['garbage']
        if case == 'forbidden': status = 403
        if case == 'limited': status = 429
        data = b'{' if case == 'badjson' else json.dumps(result).encode()
        self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)

server = ThreadingHTTPServer(('0.0.0.0',18080),Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
tls = ThreadingHTTPServer(('0.0.0.0',18443),Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(work / 'api.crt', work / 'api.key')
tls.socket=context.wrap_socket(tls.socket,server_side=True)
threading.Thread(target=tls.serve_forever,daemon=True).start()
boot = (artifacts / 'boot.log').open('w')
vm = pexpect.spawn('qemu-system-x86_64', ['-m','256','-smp','1','-accel','tcg','-drive',f'file={image},format=raw,if=virtio','-netdev','user,id=n0','-device','e1000,netdev=n0','-nographic','-monitor','none'],encoding='utf-8',timeout=120)
vm.logfile_read = boot
password = secrets.token_urlsafe(24)
vm.linesep = '\r'
try:
    vm.expect('Login:'); vm.sendline('admin+ct')
    vm.expect('Password:'); vm.sendline('')
    for _ in range(8):
        found = vm.expect([r'Do you want to see the software license[^\r\n]*', r'new password>', r'repeat new password>', r'\[admin@[^\]]+\] >'],timeout=120)
        if found == 0: vm.sendline('n')
        elif found == 1:
            vm.sendline(password)
            vm.expect('repeat new password>')
            vm.sendline(password)
            vm.expect('Password changed')
            vm.expect(r'\[admin@[^\]]+\] >')
            break
        elif found == 2: raise RuntimeError('Unexpected repeat password prompt')
        else: break
    else: raise RuntimeError('Cannot reach RouterOS prompt')

    def command(text, timeout=45):
        marker='DONE_'+str(command.counter)
        command.counter+=1
        vm.sendline(':onerror commandError in={ '+text+' } do={ :put ("COMMAND_" . "ERROR " . $commandError) }; :put "'+marker+'"')
        vm.expect(r'[\r\n]+'+marker+r'[\r\n]+',timeout=timeout)
        output=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',vm.before)
        vm.expect(r'\[admin@[^\]]+\] >',timeout=timeout)
        print(f'RouterOS command {command.counter - 1} completed', flush=True)
        assert not re.search(r'(?:^|[\r\n])COMMAND_ERROR ',output),output
        return output
    command.counter=0

    command('/system identity set name=po0fw-test')
    command('/interface print')
    command('/ip address print')
    command('/tool fetch url="http://10.0.2.2:18080/production.rsc" dst-path=production.rsc')
    syntax=command('/import production.rsc verbose=yes dry-run',timeout=90)
    assert 'No syntax errors found in the import file' in syntax,syntax
    command('/tool fetch url="http://10.0.2.2:18080/ca.crt" dst-path=ca.crt')
    command(':delay 2s; /file print')
    command('/certificate import file-name=ca.crt passphrase=""')
    command('/certificate set [find where common-name="po0fw-runtime-test"] trusted=yes')
    command('/tool fetch url="http://10.0.2.2:18080/test.rsc" dst-path=test.rsc')
    command(':delay 2s')
    command('/file print')
    command(':put [:len [/file get "test.rsc" contents]]')
    command('/system script add name=po0-firewall-whitelist policy=read,write,test source=[/file get "test.rsc" contents]')
    command('/system script run po0-firewall-whitelist',timeout=90)
    command('/system script run po0-firewall-whitelist use-script-permissions',timeout=90)
    state=command(':global po0FWState; :foreach k,v in=$po0FWState do={ :put ("STATE " . $k . "=" . $v) }')
    logs=command('/log print without-paging where topics~"script" and message~"po0fw"')
    expected={1:'203.0.113.7|1|5|',2:'203.0.113.7|1|5|',3:'203.0.113.0/24|1|5|',4:'not-applied',5:'not-applied',6:'203.0.113.7|1|5|0',7:'not-applied',8:'disabled',9:'invalid-response',10:'invalid-response',11:'request-failed',12:'request-failed',13:'invalid-config',14:'203.0.113.7|1|12|10'}
    for key,value in expected.items(): assert 'STATE '+str(key)+'='+value in state,(key,value,state)
    assert len(requests)==26,requests
    assert all(count==2 for count in Counter(x[0] for x in requests).values()),requests
    assert all(body==b'' for _,_,body,_ in requests),requests
    assert all(auth is None for _,_,_,auth in requests),requests
    assert all(query=={'slot':['0']} for case,query,_,_ in requests if case in ('pinned','wrongpin')),requests
    assert all(query=={'slot':['10']} for case,query,_,_ in requests if case=='slot10'),requests
    assert 'pgnfw_' not in logs and 'http://' not in logs and 'https://' not in logs and 'api/firewall' not in logs,logs
    assert 'HTTP 403' in logs and 'HTTP 429' in logs,logs
    assert logs.count('whitelist active for')==5,logs
    (artifacts / 'requests.json').write_text(json.dumps(requests, default=lambda value: value.decode(), indent=2))
    print('PASS: native RouterOS 7.16.2 syntax + 14 response/config cases, 26 empty-body HTTPS POSTs across two runs, CA validation, script permissions, slot=0 and slot=10, quiet success, sanitized errors.',flush=True)
finally:
    vm.close(force=True); boot.close(); server.shutdown(); tls.shutdown(); workspace.cleanup()
