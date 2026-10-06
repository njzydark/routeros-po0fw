# RouterOS 自动加白

适用于 RouterOS 7.16+。结构参考 [routeros-dnspod-ddns](https://github.com/njzydark/routeros-dnspod-ddns)，接口逻辑参考 [po0fw](https://github.com/reallinzc/po0fw)。

RouterOS 直接 POST `https://<API_IPV4>/api/firewall/<token>/add`，body 为空，无需 Authorization 头。服务端以请求源公网 IPv4 为准，按 `/24` 网段加入白名单并回显结果；不需要查询第三方 IP 服务，也不需要手工计算网段。

每次运行都会上报，重复 IP 由服务端幂等处理。即使本地 IP 没变，也不会跳过请求，因此被其他设备写入淘汰后能在下一次运行自动补回。支持多个机器 token 和 `@槽位`；成功后必须同时满足防火墙启用、当前 IP/网段存在于白名单，指定槽位时还会验证槽位。

文档中的 `<API_IPV4>` 是接口服务器地址占位符；实际地址来自脚本顶部 `apiBase` 的默认值（与 po0fw 原客户端一致），不是 BGP/Japan 机器或家宽的地址。命令执行前请将占位符替换为该接口地址。

## 配置与安装

1. 下载仓库根目录的 `po0-firewall-whitelist.rsc`，填写顶部参数。

```routeros
:local tokens {"pgnfw_你的机器token"}
:local apiBase "https://<API_IPV4>/api/firewall/"
:local sourceAddress "0.0.0.0"
:local apiVRF "main"
```

多台机器用 RouterOS 数组，条目用分号分隔；固定槽位示例：

```routeros
:local tokens {"pgnfw_第一台token@0";"pgnfw_第二台token"}
```

`@0` 表示钉在 0 号槽位。按现有服务的 5 个槽位，通常可用 `0` 到 `4`；选择未占用或确实要替换的槽位。本机网段已在另一固定槽位时，API 会返回 403，需要先在服务商面板删除旧槽位。

`sourceAddress` 是 RouterOS 本机的 WAN IPv4 地址，不是 NAT 后的公网 IP。默认自动选择；若配置了 VRF，可通过 `apiVRF` 选择已有 VRF。绑定源地址不会绕过策略路由，仍需配置 API 直连。

2. 在 WinBox / WebFig 的 **System → Scripts** 新建：

- Name：`po0-firewall-whitelist`
- Policy：`read,write,test`
- Source：粘贴整个 `.rsc` 文件内容。

也可先上传 `.rsc` 到 Files，再创建命名脚本：

```routeros
/system script add name=po0-firewall-whitelist policy=read,write,test source=[/file get "po0-firewall-whitelist.rsc" contents]
```

文件是脚本正文，`/import` 只会立即执行一次，不会创建命名脚本或定时任务。更新时编辑现有命名脚本的 Source，或者重新上传文件后执行：

```routeros
/system script set [find where name="po0-firewall-whitelist"] source=[/file get "po0-firewall-whitelist.rsc" contents]
```

3. 先配置下文的 WAN 直连，手动执行并确认成功：

```routeros
/system script run po0-firewall-whitelist
/log print where message~"po0fw"
```

4. 创建每 10 分钟运行的定时任务：

```routeros
/system scheduler add name=po0-fw-refresh start-time=startup interval=10m policy=read,write,test on-event="/system script run po0-firewall-whitelist"
```

RouterOS 的 `start-time=startup` 配合非零 interval 不保证在启动瞬间执行，因此安装后仍需手动运行一次。若要求重启后立即上报，可以再添加仅启动时触发的任务：

```routeros
/system scheduler add name=po0-fw-startup start-time=startup interval=0s policy=read,write,test on-event=":delay 30s; /system script run po0-firewall-whitelist"
```

WAN 尚未就绪导致启动上报失败时，10 分钟定时任务继续兜底。PPPoE 等 WAN 重连时也可以在现有连接事件脚本中加入 `/system script run po0-firewall-whitelist`；不要覆盖已有事件逻辑。脚本会阻止同一命名脚本并发执行。

## API 必须走 WAN 直连

上报请求经过 Japan 或其他代理时，服务端会加白代理的出口网段。即使请求成功，也无法给当前家宽入口解锁。

普通单 WAN 且默认路由直接出网时通常不需要增加规则。已有代理、全局隧道或策略路由时，应让 `<API_IPV4>/32` 明确走真实 WAN。下面以 PPPoE 接口 `pppoe-out1` 为例，按实际 WAN 替换；以太网 DHCP 接入应使用其真实网关地址：

```routeros
/ip route add dst-address=<API_IPV4>/32 gateway=pppoe-out1 routing-table=main comment="po0fw API direct"
```

若路由器自身的 output 流量也被 mangle 标记，需在这些标记规则**之前**排除 API 目的地址：

```routeros
/ip firewall mangle add chain=output dst-address=<API_IPV4>/32 action=accept comment="po0fw API bypass routing marks"
```

新规则默认加在最后，必须在 WinBox 中将它移到会标记这类 output 流量的规则之前；放在标记规则后面不能撤销已设置的 routing mark。多 WAN 上报所走的公网出口应与客户端实际访问 BGP 所用的出口一致。

## HTTPS 和日志

脚本启用 `check-certificate=yes`。请确保 RouterOS 时间正确，且 Fetch 能使用相应的受信任 CA。支持内置 CA 信任库的版本可检查 `/certificate settings print`；旧版 7.x 或已禁用 Fetch 信任库的配置需导入 API 证书对应的 CA 并设置 `trusted=yes`。

成功或白名单状态变化时记录一条日志，例如：

```text
po0fw #1: whitelist active for 203.0.113.0/24, 1/5, pinned slot 0
```

重复成功请求保持安静，但仍实际 POST。失败后会在后续定时运行重试，并在恢复时记录成功。脚本运行日志只包含 token 序号和白名单状态，不输出 token、请求 URL、原始响应或 Fetch 异常；这里指脚本自身的日志，不包括 RouterOS 的配置变更审计。

- `HTTP 403`：检查 token，或当前网段是否已经占用其他固定槽位。
- `HTTP 429`：等待下一次定时运行，避免设置过短的运行间隔。
- `request failed`：检查 WAN 直连、连通性、设备时间和 CA 信任。
- `firewall is disabled`：服务端防火墙未启用。
- `current subnet or requested slot absent`：响应没有确认当前来源/指定槽位已加入。
- `invalid API response`：JSON 或必要字段异常，不会误报加白成功。

## 验证范围

已在 RouterOS CHR 7.16.2 中通过原生语法校验和 14 类配置/响应测试，覆盖新旧白名单格式、`/24` 匹配、固定槽位、403/429、异常响应及重复运行。两次运行共完成 26 次空 body 的 HTTPS POST，并验证 CA 校验及 `read,write,test` 权限执行。测试使用独立模拟接口和临时 CA，未调用真实加白接口；实际设备仍需填写 token 并确认 WAN 直连。

## 停用

```routeros
/system scheduler remove [find where name="po0-fw-refresh"]
/system scheduler remove [find where name="po0-fw-startup"]
/system script remove [find where name="po0-firewall-whitelist"]
```

若已添加上面的专用直连规则，按其唯一 comment 删除即可；同时从自己配置的 WAN 事件脚本中移除调用。

## 开发与测试

Docker / QEMU 测试环境、运行命令和测试范围见 [测试说明](docs/testing.md)。
