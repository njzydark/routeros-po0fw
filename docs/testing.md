# RouterOS 原生集成测试

测试在 Docker 内运行 QEMU，启动官方 MikroTik CHR 7.16.2，直接执行仓库根目录的 `.rsc`。支持 x86_64 和 ARM64 Docker 主机，使用 TCG 软件模拟，不需要 KVM、特权容器或开放宿主机端口。

## 运行

需要 Docker Engine / Docker Desktop 以及 Compose v2。在仓库根目录执行：

```sh
mkdir -p tests/artifacts tests/cache
docker compose run --build --rm test
```

首次构建需要下载 Alpine 软件包，首次测试会下载官方 CHR 镜像并缓存至 `tests/cache/`，后续复用该镜像压缩包；每次运行仍创建独立虚拟机磁盘：

```text
https://download.mikrotik.com/routeros/7.16.2/chr-7.16.2.img.zip
```

如果容器下载慢，也可在宿主机预下载同一官方镜像后再运行测试：

```sh
mkdir -p tests/cache
curl --fail --location --retry 3 --output tests/cache/chr-7.16.2.img.zip https://download.mikrotik.com/routeros/7.16.2/chr-7.16.2.img.zip
```

成功时末尾输出 `PASS: native RouterOS 7.16.2 syntax + 14 response/config cases...`，进程退出码为 0。断言失败或 RouterOS 命令错误会返回非零退出码。软件模拟通常需要数分钟。

## 测试机制

- 从根目录读取生产脚本，在内存副本中替换测试 token 和 API 地址。
- 自动生成临时 CA 与 API 证书，导入 CHR 并设为可信；生产脚本的 `check-certificate=yes` 保持启用。
- 容器内提供 HTTP 文件下载服务和 HTTPS 模拟加白接口。`10.0.2.2` 是 QEMU 用户网络的宿主侧地址，与个人网络无关；模拟响应只使用文档专用网段 `203.0.113.0/24` 和 `198.51.100.0/24`。
- 使用 CHR 串口控制台执行 `/import ... verbose=yes dry-run`，再安装命名脚本，分别普通运行和通过 `use-script-permissions` 运行。
- 模拟接口记录请求，断言 POST 次数、空 body、缺少 Authorization 头、固定槽位参数、全局状态和脚本日志。

生产接口不会被调用。测试中使用的 `pgnfw_*` 全为模拟 token；CHR 密码每次随机生成。虚拟机磁盘、证书和私钥位于容器临时目录，运行结束自动清理。

## 覆盖范围

| 场景 | 预期 |
| --- | --- |
| 对象格式白名单 | `/24` 网段匹配成功 |
| 旧版字符串格式 | 完整 IP 匹配成功 |
| 当前来源为 `/24`，条目为 IP | 同网段匹配成功 |
| 不同网段 | 不确认加白 |
| 同网段的不同完整 IP | 不确认加白 |
| 固定槽位 0 | 验证槽位与查询参数 |
| 固定槽位不匹配 | 不确认加白 |
| 防火墙未启用 | 记录 disabled 状态 |
| JSON 损坏 | 记录 invalid-response |
| 来源 IP 非法 | 记录 invalid-response |
| HTTP 403 | 记录脱敏错误 |
| HTTP 429 | 记录脱敏错误 |
| token 含非法字符 | 拒绝配置，不发请求 |
| 多位数槽位 10 | 验证解析与查询参数 |

两次运行总计发出 26 次 HTTPS POST。重复成功请求仍会发送，但成功日志仅记录首次或状态变化。测试断言脚本日志不含 token、URL 和接口路径，并验证 `read,write,test` 权限执行。

这些测试验证脚本逻辑和原生 RouterOS 7.16.2 执行，未验证服务商真实接口、个人设备的 WAN 路由或真实 token。

## 诊断与清理

`tests/artifacts/boot.log` 保留 CHR 串口输出；`requests.json` 保存模拟请求记录。这些文件已被 Git 忽略，不会随仓库发布。脚本失败时也保留启动日志，便于定位问题。

```sh
docker compose down
rm -rf tests/artifacts
```

`tests/cache/` 也已被 Git 忽略；需要重新下载时删除该目录即可。

测试代码在 [tests/run.py](../tests/run.py)，容器依赖在 [tests/Dockerfile](../tests/Dockerfile)。修改生产脚本后，重新运行同一条命令即可。
