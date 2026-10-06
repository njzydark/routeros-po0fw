FROM alpine:3.22

RUN apk --timeout 20 add --no-cache ca-certificates openssl python3 py3-pexpect qemu-system-x86_64

ENV PYTHONUNBUFFERED=1
WORKDIR /repo
CMD ["python3", "/repo/tests/run.py"]
