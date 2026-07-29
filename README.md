# hy2-safe

[![Release](https://img.shields.io/github/v/release/elonjack/hy2-safe?display_name=tag)](https://github.com/elonjack/hy2-safe/releases)
[![CI](https://github.com/elonjack/hy2-safe/actions/workflows/ci.yml/badge.svg)](https://github.com/elonjack/hy2-safe/actions/workflows/ci.yml)
[![Debian](https://img.shields.io/badge/Debian-12%20%7C%2013-A81D33?logo=debian&logoColor=white)](https://www.debian.org/)

面向 Debian 12/13 的 Hysteria 2 服务端一键安装与管理脚本。

它使用你自己的域名和公开可信证书，默认开启 UDP 端口跳跃、每周自动更新 Hysteria 2，并可选启用 Telegram 成功连接提醒。本文按 `root` 用户编写，命令不需要添加 `sudo`。

> [!IMPORTANT]
> 本项目会尽量减少常见配置错误和权限风险，但任何脚本都不能承诺“绝对没有漏洞”“永远不会被封”或“运营商一定不做 UDP QoS”。安装后仍需及时更新 Debian、保护 SSH、保管好 Hy2 密码和 Telegram Bot Token。

## 目录

- [主要功能](#主要功能)
- [开始前准备](#开始前准备)
- [Cloudflare DNS 设置](#cloudflare-dns-设置)
- [防火墙和安全组](#防火墙和安全组)
- [一行命令开始使用](#一行命令开始使用)
- [安装时怎么填写](#安装时怎么填写)
- [管理菜单](#管理菜单)
- [客户端怎么连接](#客户端怎么连接)
- [上传下载速度和 QoS](#上传下载速度和-qos)
- [端口跳跃](#端口跳跃)
- [域名、证书和双栈](#域名证书和双栈)
- [伪装页面](#伪装页面)
- [Telegram 连接提醒](#telegram-连接提醒)
- [版本和自动更新](#版本和自动更新)
- [hysteria 服务账号是什么](#hysteria-服务账号是什么)
- [完整卸载与重新安装](#完整卸载与重新安装)
- [安全设计](#安全设计)
- [隐私与敏感信息](#隐私与敏感信息)
- [文件位置](#文件位置)
- [常用命令](#常用命令)
- [常见问题](#常见问题)
- [官方资料](#官方资料)

## 主要功能

- 仅支持 Debian 12/13，避免在未经验证的系统上盲目修改。
- 从 Hysteria 官方仓库安装最新稳定版。
- 校验 GitHub Release 元数据、文件大小、Asset SHA-256、官方 `hashes.txt` 和二进制报告版本。
- 使用自己的域名，由 Hysteria ACME 自动申请并续期公开可信证书。
- 客户端保持证书验证，不设置 `insecure: true`。
- 默认开启原生 UDP 端口跳跃：`50000-50500`（共 501 个端口）。
- 不硬编码客户端上传/下载 Mbps，使用较保守的自适应 BBR。
- Hysteria 使用独立无登录权限账号运行；每次服务启动前都会检查密码锁定、登录 Shell 和 SSH 密钥入口。
- 默认使用本机固定小页面作为伪装，不反向代理 Bing 等第三方大站。
- 每周自动检查 Hysteria 官方稳定版，失败时恢复上一版本。
- 输出官方客户端 YAML、官方分享链接及 v2rayN/v2rayNG 兼容链接。
- 可选启用 Telegram 成功连接提醒，并合并频繁重连消息。
- 提供中文菜单完成安装、修改、更新、查看版本、Telegram 管理和完整卸载。

## 开始前准备

你需要：

1. 一台全新的 Debian 12 或 Debian 13 VPS。
2. VPS 的 `root` 权限。
3. 一个自己管理的域名。
4. 一个专门给 Hy2 使用的子域名，例如 `hy2.example.com`。
5. 如果使用入站默认拒绝防火墙，提前允许必要端口。

如果你使用 [vps-security-bootstrap](https://github.com/elonjack/vps-security-bootstrap)，推荐顺序是：

1. 运行 `vps-security-bootstrap`。
2. 保留当前 SSH 窗口。
3. 新开一个 SSH 窗口，确认密钥登录正常。
4. 再安装 `hy2-safe`。

## Cloudflare DNS 设置

假设：

- VPS IPv4：`203.0.113.10`
- VPS IPv6：`2001:db8::10`
- Hy2 域名：`hy2.example.com`

在 Cloudflare DNS 中可以添加：

| 类型 | 名称 | 内容 | 代理状态 |
| --- | --- | --- | --- |
| `A` | `hy2` | VPS 公网 IPv4 | 仅 DNS，灰色云朵 |
| `AAAA` | `hy2` | VPS 公网 IPv6 | 仅 DNS，灰色云朵 |

同一个名称同时存在 `A` 和 `AAAA` 是正常的，表示这个域名同时支持 IPv4 和 IPv6。VPS 没有真正可用的公网 IPv6 时不要添加 `AAAA`。

> [!WARNING]
> Hy2 使用自定义 UDP/QUIC。Cloudflare 普通小黄云不能代理这种服务，因此 Hy2 域名必须保持灰云。灰云会公开 VPS IP，这是直连代理无法避免的；伪装页面不能隐藏入口 IP。

## 防火墙和安全组

VPS 系统防火墙和云厂商安全组是两层不同的过滤：

| 类型 | 位置 | 示例 |
| --- | --- | --- |
| 系统防火墙 | Debian 内部 | nftables、UFW、firewalld |
| 云防火墙/安全组 | 云厂商网络边界 | 控制台入站规则 |

哪一层设置了“默认拒绝入站”，就必须在哪一层允许：

| 用途 | 协议 | 默认端口 |
| --- | --- | --- |
| SSH | TCP | 你的实际 SSH 端口 |
| ACME 域名验证 | TCP | `80`、`443` |
| Hy2 端口跳跃 | UDP | `50000-50500` |

如果没有任何默认拒绝规则，就不存在“先开放端口才能使用”的步骤；程序监听后公网即可访问。但这也意味着以后其他程序如果意外监听公网，不会被防火墙额外拦截。

`hy2-safe` 不会清空、开启或重写你的系统防火墙，也无法修改云厂商控制台。Hysteria 为端口跳跃创建的临时重定向规则不等于默认拒绝防火墙中的“允许入站”规则。

## 一行命令开始使用

以 `root` 登录 VPS，复制下面一整行：

```bash
curl -fL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/elonjack/hy2-safe/main/hy2-safe.sh -o /root/hy2-safe.sh && chmod 0700 /root/hy2-safe.sh && /root/hy2-safe.sh
```

这条命令会先保存脚本，再执行本地文件，不是直接把网络内容通过管道交给 Shell。

如果想先查看：

```bash
curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/elonjack/hy2-safe/main/hy2-safe.sh \
  -o /root/hy2-safe.sh

less /root/hy2-safe.sh
chmod 0700 /root/hy2-safe.sh
/root/hy2-safe.sh
```

在 `less` 中按 `q` 退出。

第一次运行选择：

```text
1) 安装 Hy2
```

## 安装时怎么填写

| 提示 | 小白建议 |
| --- | --- |
| 证书/SNI 域名 | 填写灰云子域名，例如 `hy2.example.com` |
| ACME 通知邮箱 | 填写可以接收邮件的邮箱 |
| 开启原生端口跳跃 | 直接回车，默认开启 |
| UDP 跳跃端口范围 | 直接回车，默认 `50000-50500` |
| 自定义 HTTPS 伪装站点 | 直接回车，使用本机固定小页面 |
| 每周自动更新 | 直接回车，默认开启 |
| Telegram 提醒 | 需要时输入 `y`，暂时不需要直接回车 |

Hy2 密码由系统密码学随机源自动生成。不要把客户端分享链接、密码或 Telegram Token 发到公开群、截图或 GitHub。

安装结束后会输出客户端配置和分享链接。以后再次查看：

```bash
hy2-safe show-client
```

## 管理菜单

安装后直接运行：

```bash
hy2-safe
```

菜单如下：

```text
hy2-safe v1.0.1 一键管理菜单

  1) 安装 Hy2
  2) 完整卸载 Hy2
  3) 添加 Telegram 通知
  4) 更换 Telegram 机器人
  5) 删除 Telegram 通知
  6) 显示客户端配置
  7) 修改 Hy2 配置
  8) 立即检查更新（默认另有每周自动更新）
  9) 查看版本、服务和自动更新状态
  0) 退出
```

菜单一次执行一个操作。修改配置失败时，脚本会尝试恢复原配置；Hysteria 更新失败时，会尝试恢复上一版本。

## 客户端怎么连接

运行：

```bash
hy2-safe show-client
```

端口跳跃模式会输出：

1. Hysteria 2 官方客户端完整 YAML。
2. Hysteria 2 官方分享链接。
3. v2rayN/v2rayNG 兼容分享链接。

### Windows 11：v2rayN

复制标有“v2rayN / v2rayNG 兼容分享链接”的那一条，在 v2rayN 中从剪贴板导入。建议使用较新的客户端版本和支持 Hy2 的核心。

### Android：v2rayNG

同样导入兼容分享链接。不同版本支持的参数可能不同；如果导入后没有显示端口跳跃范围，请更新客户端。

### 官方客户端 YAML

输出大致如下，实际内容以你的服务器为准：

```yaml
server: "hy2.example.com:50000-50500"
auth: "脚本生成的随机密码"
tls:
  sni: hy2.example.com
congestion:
  type: bbr
  bbrProfile: conservative
transport:
  type: udp
  udp:
    minHopInterval: 15s
    maxHopInterval: 45s
socks5:
  listen: 127.0.0.1:1080
```

脚本没有开启 `fastOpen`，因此保留 SOCKS5 的正常成功/失败语义；也没有关闭证书验证。

## 上传下载速度和 QoS

脚本不会填写固定的：

```yaml
bandwidth:
  up: 100 mbps
  down: 500 mbps
```

原因是手机、公司网络、家庭 Wi-Fi、距离路由器远近、运营商线路和晚高峰都会改变实际带宽。不存在一组适合所有设备的固定数值。

服务端使用：

```yaml
ignoreClientBandwidth: true
congestion:
  type: bbr
  bbrProfile: conservative
```

这里不是不信任你的设备身份，而是不采用客户端手工填写、可能已经不符合当前网络状况的固定 Mbps。BBR 会根据设备到 VPS 的整条实际路径动态调整发送速度。

这可以避免错误的高带宽数值触发 Brutal 丢包补偿，但不能保证运营商永远不做 UDP QoS。持续跑满带宽或短时间传输大量流量，仍可能触发运营商或 VPS 厂商的限制。

Hysteria 官方 URI 规范也说明，带宽属于客户端本地参数，不应写进通用分享链接。

## 端口跳跃

默认范围：

```text
UDP 50000-50500
```

这不代表同时建立 501 个连接，也不代表同时向 501 个端口发送数据。客户端只会随机选择其中一个端口，并在 `15-45` 秒之间随机更换；服务端把范围内端口重定向到实际监听端口。

501 个候选端口对个人节点已经足够，也比开放三万个端口更容易设置防火墙，并减少与其他 UDP 服务发生端口冲突的范围。端口数量本身不会提高速度；端口跳跃只能缓解部分针对单一 UDP 端口的限速或封锁，不能绕过所有网络限制。

修改范围：

```bash
hy2-safe configure \
  --port-hopping 30000-40000 \
  --hop-min 15 \
  --hop-max 45 \
  --non-interactive
```

切换单端口：

```bash
hy2-safe configure --port 443 --non-interactive
```

修改后记得同步调整所有启用默认拒绝的防火墙层。

## 域名、证书和双栈

脚本配置 Hysteria ACME，由 Hysteria 自动申请和续期公开可信证书。证书和 ACME 状态保存在：

```text
/var/lib/hysteria/acme
```

这不是 Cloudflare Origin CA 证书。Cloudflare 在默认方案中只负责 DNS。

服务端监听写法为 `:端口` 或 `:端口范围`，按照 Hysteria 官方定义会监听所有可用 IPv4 和 IPv6 接口。

同一域名可以同时有 `A` 和 `AAAA`，同一张域名证书可用于该域名通过 IPv4 或 IPv6 建立的连接。客户端最终使用哪一个地址取决于客户端核心、DNS 和系统路由策略，不保证一定自动选择速度更快的线路。

如果想手工区分，可以分别创建：

- `hy2-v4.example.com`：只设置 `A`。
- `hy2-v6.example.com`：只设置 `AAAA`。

两个不同域名通常分别申请证书，或者放进同一张包含两个域名的证书。本脚本默认使用一个域名和一张证书。

## 伪装页面

伪装的作用是让未通过 Hy2 认证的普通 HTTP/3 探测看到正常响应。它不能：

- 隐藏 VPS IP。
- 代替 Hy2 密码。
- 保证绕过所有识别或封锁。

默认模式返回本机固定小页面，不请求 Bing、Google 等上游网站，因此陌生人反复探测不会迫使 VPS 下载上游大文件。

如果你确实有自己控制的 HTTPS 网站：

```bash
hy2-safe configure \
  --masquerade-url https://www.example.org/ \
  --non-interactive
```

切回默认本机页面：

```bash
hy2-safe configure --static-masquerade --non-interactive
```

自定义反代目标必须是公开 HTTPS 域名，不能解析到私网、环回或保留地址，也不能与 Hy2 域名相同。反代站点的 DNS 以后发生变化仍可能改变风险，因此不需要真实站点时优先使用默认模式。

## Telegram 连接提醒

Telegram 功能默认关闭。它只监听 Hysteria 的“认证成功连接”日志，不参与 Hy2 密码验证；Telegram 网络故障不会阻止 Hy2 服务运行。

### 添加提醒

1. 在 Telegram 中找到官方 `@BotFather`。
2. 发送 `/newbot` 创建一个专用机器人。
3. 打开新机器人，给它发送任意私人消息。
4. 运行 `hy2-safe`，选择 `3) 添加 Telegram 通知`。
5. 输入 Bot Token。输入时终端不会显示字符。
6. 选择属于自己的私人 Chat ID。
7. 收到测试消息后配置才会生效。

建议创建专门用于 Hy2 的机器人，不要复用正在使用 webhook 或处理其他命令的机器人。

### 消息如何防刷屏

- 新的 IPv4 `/24` 或 IPv6 `/48` 来源：立即提醒。
- 同一网段短时间频繁重连：一小时合并一次。
- 超过 24 小时没有出现后再次连接：重新提醒。
- 每天发送一份汇总。
- IPv4 显示为 `123.45.67.*`。
- IPv6 只显示前 48 bit，例如 `2408:8215:1234:*`。

“隐藏”表示消息中不显示完整 IP，不代表服务器日志中不存在原始连接地址。

### 更换机器人

菜单选择 `4) 更换 Telegram 机器人`，或者：

```bash
hy2-safe telegram-replace
```

新 Token、Chat ID 和测试消息全部验证成功后才会替换；失败时继续保留旧机器人。

### 删除提醒

菜单选择 `5) 删除 Telegram 通知`，或者：

```bash
hy2-safe telegram-disable
```

这会停止提醒服务，删除 Bot Token 和通知状态。通用提醒程序文件会随 Hy2 完整卸载一起删除。

### Telegram 安全边界

- Bot Token 保存在 root-only 的 `0600` 文件中。
- systemd 通过凭据目录把 Token 交给隔离的动态用户。
- Hysteria 流量统计 API 只监听 `127.0.0.1`，并使用随机密钥。
- 提醒只发送给配置时确认的固定私人 Chat ID。
- 机器人不会在后台轮询陌生人的命令。

如果 Token 泄露，请先在 `@BotFather` 撤销，然后使用“更换 Telegram 机器人”。

## 版本和自动更新

查看管理脚本和 Hysteria 核心版本：

```bash
hy2-safe version
```

查看版本、服务、Telegram 和下次自动更新时间：

```bash
hy2-safe status
```

默认启用：

```text
hy2-safe-update.timer
```

它每周检查 Hysteria 官方最新稳定版，并随机延迟最多 12 小时。`Persistent=true` 表示错过计划时间时，会在 VPS 下次运行后补做检查。

自动更新流程：

1. 读取官方 GitHub Latest Release。
2. 拒绝草稿、预发布和异常版本号。
3. 校验官方仓库、下载地址、文件大小和两个 SHA-256 来源。
4. 验证下载的二进制报告版本与 Release 一致。
5. 拒绝自动降级。
6. 原子替换程序并重启服务。
7. 新版本启动失败时恢复上一版本。

菜单 `8) 立即检查更新` 只是马上手动检查一次，不会关闭每周自动更新。

> [!NOTE]
> 自动更新只更新 Hysteria 官方核心，不会远程替换 `hy2-safe` 管理脚本。重新执行 README 的一行下载命令并打开菜单，执行普通管理操作时会同步最新管理脚本、服务账号权限和 systemd 单元；刷新本身不会主动重启正在运行的 Hy2。若恰好同时触发 Hysteria 核心更新，更新流程仍会按设计重启并检查服务。选择“完整卸载”时不会先做刷新。

## hysteria 服务账号是什么

安装时会看到一个名为 `hysteria` 的 Linux 系统账号。它不是 Hy2 客户端账号，也不是你的 VPS 登录账号：

| 名称 | 用途 |
| --- | --- |
| `root` | 你通过 SSH 管理 VPS 使用的管理员账号 |
| Linux 用户 `hysteria` | 只负责以低权限运行 Hysteria 服务端程序 |
| Hy2 随机密码 | v2rayN、v2rayNG 或官方客户端连接节点时使用 |

让服务使用独立低权限账号，是为了即使 Hysteria 程序将来出现漏洞，也尽量缩小它能读写的系统范围。脚本会进行这些限制：

- 登录 Shell 是 `/usr/sbin/nologin`、`/sbin/nologin` 或 `/bin/false`。
- 创建账号后立即锁定密码，密码状态必须是 `L`。
- 家目录 `/var/lib/hysteria` 由 `root` 控制，`hysteria` 用户不能在里面自行创建 `.ssh/authorized_keys`。
- 只有证书目录 `/var/lib/hysteria/acme` 允许 `hysteria` 写入。
- 每次 systemd 启动 Hy2 前，都会重新检查账号、组、密码锁定状态、`.ssh` 入口和目录权限；检查失败就不启动服务。

因此，创建这个账号不会给 Telegram 发送“客户端连接”消息。Telegram 只提醒通过 Hy2 密码认证成功的网络客户端，不会把 Linux 本地账号创建当成节点连接。

> [!IMPORTANT]
> 这些检查不修改你的 SSH 配置，也不影响 `root` 登录。若管理员以后手工给 `hysteria` 设置密码、改成可登录 Shell、加入其他组或创建 `.ssh`，Hy2 会拒绝启动并要求先恢复安全状态。

## 完整卸载与重新安装

运行：

```bash
hy2-safe
```

选择：

```text
2) 完整卸载 Hy2
```

脚本会列出删除范围，并要求输入 `DELETE`。完整卸载会删除：

- Hysteria 当前版本和回滚版本。
- `hy2-safe` 管理脚本及推荐下载位置 `/root/hy2-safe.sh`。
- systemd 服务和自动更新任务。
- Hy2 服务端配置、密码和客户端信息。
- ACME 证书和账户状态。
- Telegram Bot Token 和通知状态。
- 有 root-only 归属记录证明由本脚本创建的 `hysteria` 服务用户和组。

脚本不会自动卸载 `curl`、`python3` 等通用依赖。新安装时，脚本会把自己创建的服务用户 UID 和服务组 GID 记录在：

```text
/etc/hysteria/hy2-safe-account.env
```

该文件只允许 `root` 读取。完整卸载只有在“创建标记、UID/GID 和当前账号”三者一致时才删除 `hysteria` 用户和组；不会删除或修改 `root`。

如果是从没有归属记录的旧版本升级，或者同名账号本来就已存在，脚本不能百分之百证明账号由自己创建，因此会保留账号并在卸载结果中明确说明。这种情况下只删除 Hy2 的 ACME 子目录，家目录仅在已经为空时删除，不递归删除来源不明的其他内容。这样可避免误伤其他程序正在使用的 Linux 身份，不影响以后重新安装。

重新安装时，再次执行 README 的一行命令即可。Hysteria 会重新验证域名并申请新证书。

> [!WARNING]
> 不要在短时间内反复完整卸载重装。删除 ACME 状态后会重新签发证书，可能触发 CA 频率限制。重新安装前先确认域名、灰云和 TCP 80/443 正确，避免连续验证失败。

## 安全设计

### 下载与更新

- 只接受 `apernet/hysteria` 官方稳定 Release。
- 版本号必须匹配 `app/v数字.数字.数字`。
- 下载 URL 必须与官方仓库、版本和架构完全匹配。
- 限制元数据、哈希文件和二进制最大体积。
- 同时验证 GitHub Asset digest 和官方 `hashes.txt`。
- 验证二进制自身报告版本。
- 拒绝低于 `v2.8.0`、不支持当前原生端口范围和 BBR profile 的旧核心。
- 不自动降级。
- 更新失败自动尝试回滚。

### 权限

- Hysteria 使用独立 `hysteria` 无登录账号。
- 脚本明确锁定该账号密码，并在每次服务启动前要求密码状态为 `L`。
- 脚本拒绝复用具有登录 Shell、错误家目录、`.ssh`、额外组权限或共享成员的同名账号/组。
- 账号家目录由 `root` 控制，只有 ACME 证书子目录允许服务写入。
- root-only 归属文件记录脚本创建的用户 UID 和组 GID，卸载时必须匹配才会删除。
- 单端口只授予 `CAP_NET_BIND_SERVICE`。
- 端口跳跃额外授予必需的 `CAP_NET_ADMIN` 和 `AF_NETLINK`。
- systemd 启用文件系统、设备、内核、`/proc` 和可写执行内存限制。

### 密钥和配置

- Hy2 密码约有 256 bit 随机熵。
- 管理设置和 Telegram Token 为 root-only `0600`。
- Hysteria 配置为 `0640 root:hysteria`。
- 客户端保持证书验证。
- Telegram Token 不接受命令行明文参数。

### 不会自动做的事

- 不修改 SSH 设置。
- 不开启或重写系统防火墙。
- 不修改云厂商安全组。
- 不隐藏 VPS IP。
- 不保证绕过所有 QoS 或封锁。
- 不自动更新 `hy2-safe` 自身。

## 隐私与敏感信息

公开仓库中的脚本和 README 不包含你的真实域名、VPS IP、邮箱、Hy2 密码、证书私钥、Telegram Bot Token 或 Chat ID。安装时填写或生成的内容保存在你自己的 VPS 上，不会上传到本项目的 GitHub 仓库。

以下内容本来就需要交给对应服务才能工作：

- 域名和 ACME 邮箱会交给证书机构申请公开可信证书。
- 启用 Telegram 后，Bot Token、固定 Chat ID、已隐藏部分地址的客户端 IP 和提醒时间会通过 Telegram Bot API 处理。
- 下载和自动更新会访问 Hysteria 官方 GitHub Release。

需要自己注意：

- `hy2-safe show-client` 会在当前 SSH 终端显示完整 Hy2 密码和分享链接。脚本会先警告；不要截图、录屏或发送到群聊。
- Hysteria 的 systemd 日志会保留客户端完整来源 IP；Telegram 消息只发送隐藏后的 IPv4 `/24` 或 IPv6 `/48`。
- Telegram Token 通过不回显输入或 root-only 文件读取，不接受命令行明文参数。
- Hy2 自定义密码同样不接受命令行明文，只能使用 root-only `--password-file`；不指定时自动生成。

## 文件位置

| 路径 | 用途 |
| --- | --- |
| `/usr/local/bin/hysteria` | 当前 Hysteria 核心 |
| `/usr/local/bin/hysteria.previous` | 更新回滚版本 |
| `/usr/local/sbin/hy2-safe` | 管理脚本 |
| `/etc/hysteria/config.yaml` | Hysteria 服务端配置 |
| `/etc/hysteria/hy2-safe.env` | root-only 管理设置 |
| `/etc/hysteria/hy2-safe-account.env` | root-only 服务账号创建归属与 UID/GID 记录 |
| `/etc/hysteria/telegram-notifier.json` | root-only Telegram 凭据 |
| `/var/lib/hysteria/acme` | ACME 证书和账户状态 |
| `/usr/local/libexec/hy2-safe-notifier.py` | Telegram 提醒程序 |
| `/var/lib/private/hy2-safe-notifier` | Telegram 防刷屏状态 |
| `/etc/systemd/system/hysteria-server.service` | Hy2 服务 |
| `/etc/systemd/system/hy2-safe-update.timer` | 每周自动更新 |
| `/etc/systemd/system/hy2-safe-notifier.service` | Telegram 提醒服务 |

## 常用命令

```bash
# 打开中文菜单
hy2-safe

# 查看管理脚本和 Hysteria 核心版本
hy2-safe version

# 查看服务和自动更新状态
hy2-safe status

# 显示客户端 YAML 和分享链接
hy2-safe show-client

# 交互修改域名、端口、密码或伪装
hy2-safe configure

# 立即检查 Hysteria 官方稳定版
hy2-safe update

# 查看 Hy2 日志
hy2-safe logs

# 添加或重新设置 Telegram
hy2-safe telegram-setup

# 安全更换 Telegram 机器人
hy2-safe telegram-replace

# 发送 Telegram 测试消息
hy2-safe telegram-test

# 查看 Telegram 提醒日志
hy2-safe telegram-logs

# 删除 Telegram Token 和通知状态
hy2-safe telegram-disable

# 完整卸载
hy2-safe uninstall
```

自动化安装示例：

```bash
/root/hy2-safe.sh install \
  --domain hy2.example.com \
  --email admin@example.com \
  --port-hopping 50000-50500 \
  --static-masquerade \
  --auto-update \
  --non-interactive
```

自动化时如果要指定密码，推荐使用仅 root 可读的文件：

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > /root/hy2-password
chmod 0600 /root/hy2-password

/root/hy2-safe.sh install \
  --domain hy2.example.com \
  --email admin@example.com \
  --password-file /root/hy2-password \
  --non-interactive

rm -f /root/hy2-password
```

## 常见问题

### 安装成功但客户端连不上

依次检查：

1. `hy2-safe status` 中服务是否正在运行。
2. `hy2-safe show-client` 的域名、密码和端口是否与客户端一致。
3. Cloudflare 是否为灰云。
4. DNS `A`/`AAAA` 是否指向这台 VPS。
5. 所有默认拒绝防火墙层是否允许完整 UDP 范围。
6. 本地网络是否封锁 UDP/QUIC。
7. v2rayN/v2rayNG 是否正确识别 `mport`。
8. 使用 `hy2-safe logs` 查看错误。

### 证书申请失败

常见原因：

- 域名没有解析到本机。
- Cloudflare 开启了小黄云。
- TCP 80/443 被系统防火墙或云防火墙阻挡。
- 80/443 被 Nginx、Caddy、Apache 等程序占用。
- 短时间连续失败或重新签发触发 CA 限制。

修正后使用：

```bash
hy2-safe install --reinstall
```

### 端口跳跃无法启动

检查：

```bash
command -v nft
command -v iptables
hy2-safe logs
```

端口范围模式需要 nftables 或 iptables，并需要服务拥有 `CAP_NET_ADMIN`。脚本只在端口范围模式下授予该能力。

### Telegram 没有消息

```bash
hy2-safe telegram-test
hy2-safe telegram-logs
hy2-safe status
```

确认：

- Bot Token 没有被 `@BotFather` 撤销。
- 你没有把机器人改成 webhook 专用机器人。
- VPS 可以访问 `api.telegram.org`。
- 提醒服务正在运行。

### 会不会被别人偷跑流量

攻击者必须先获得 Hy2 密码才能作为客户端使用节点。脚本生成的随机密码无法通过现实可行的公网穷举直接猜出。

更常见的风险是：

- 分享链接被发到群聊或公开仓库。
- 客户端配置截图泄露。
- VPS 的 root 权限被入侵。
- Telegram 或剪贴板同步泄露。

怀疑泄露时应更换密码，并删除所有旧客户端配置：

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > /root/hy2-new-password
chmod 0600 /root/hy2-new-password
hy2-safe configure --password-file /root/hy2-new-password --non-interactive
rm -f /root/hy2-new-password
```

### hysteria 账号能不能 SSH 登录

正常情况下不能。它的密码被锁定、登录 Shell 为 `nologin`，家目录也不允许它创建 `.ssh/authorized_keys`。每次启动 Hy2 前会再次检查，任一条件不符合都会阻止服务启动。

你仍然使用 `root` 管理 VPS。`hysteria` 只是 Hysteria 程序的低权限运行身份，不需要也不应该拿它登录。

### 没开防火墙是否一定不安全

不是“不开就一定被入侵”，但会少一层保护。没有程序监听的端口本来无法连接；正在监听公网的服务则必须依靠自身认证和更新保证安全。

默认拒绝防火墙主要防止以后误装的数据库、管理面板或 Docker 容器意外暴露公网。启用前必须先允许 SSH，避免把自己锁在服务器外。

## 官方资料

- [Hysteria 2 服务端入门](https://v2.hysteria.network/docs/getting-started/Server/)
- [Hysteria 2 完整服务端配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)
- [Hysteria 2 完整客户端配置](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [Hysteria 2 端口跳跃](https://v2.hysteria.network/docs/advanced/Port-Hopping/)
- [Hysteria 2 URI 规范](https://v2.hysteria.network/docs/developers/URI-Scheme/)
- [Hysteria 2 流量统计 API](https://v2.hysteria.network/docs/advanced/Traffic-Stats-API/)
- [Telegram Bot API](https://core.telegram.org/bots/api)
- [Let’s Encrypt 频率限制](https://letsencrypt.org/docs/rate-limits/)

## 版本

当前管理脚本正式版本：`v1.0.0`

Release 页面：[elonjack/hy2-safe/releases](https://github.com/elonjack/hy2-safe/releases)
