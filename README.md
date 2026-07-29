# hy2-safe

一个面向 Debian 12/13 的 Hysteria 2（Hy2）服务端安装与管理脚本。

即使你不熟悉 Linux，也可以按照本文从上到下完成安装。脚本默认使用自己的域名和正规 TLS 证书，支持端口跳跃，并可每周自动更新 Hysteria 2 核心。

## 这个脚本能做什么

- 从 Hysteria 官方 GitHub 仓库安装最新稳定版。
- 使用你自己的域名自动申请证书，客户端不需要关闭证书验证。
- 默认开启 UDP 端口跳跃，范围为 `20000-50000`。
- 自动生成高强度连接密码。
- 默认每周检查更新；更新失败会自动换回旧版本。
- Hysteria 以独立的低权限用户运行。
- 默认显示一个很小的本机伪装页面，不访问第三方网站。
- 提供查看状态、客户端配置、日志、更新和卸载命令。

## 开始前要准备什么

你需要：

1. 一台全新的 Debian 12 或 Debian 13 VPS。
2. 一个由你管理的域名，例如 `example.com`。
3. 一个专门给 Hy2 使用的子域名，例如 `hy2.example.com`。
4. VPS 的 `root` 权限或可以使用 `sudo` 的账号。

如果你平时使用 [vps-security-bootstrap](https://github.com/elonjack/vps-security-bootstrap)，建议先执行它，确认 SSH 密钥登录正常，再安装 Hy2。

## Cloudflare 域名怎么设置

假设 VPS 的公网 IP 是 `203.0.113.10`，你准备用 `hy2.example.com`：

1. 打开 Cloudflare 的 DNS 页面。
2. 新建一条 `A` 记录。
3. 名称填写 `hy2`。
4. IPv4 地址填写你的 VPS 公网 IP。
5. **代理状态选择“仅 DNS”（灰色云朵）**。

如果 VPS 有可用的 IPv6，也可以增加一条 `AAAA` 记录；如果 IPv6 没有配置好，就不要添加。

Hy2 使用 UDP/QUIC，Cloudflare 普通的小黄云不能转发这种自定义 UDP 服务。因此，Hy2 子域名不能开启小黄云，否则客户端通常无法连接。

灰云会让别人通过 DNS 查到 VPS IP，这是直接连接 Hy2 时不可避免的。伪装域名不能隐藏入口 IP，它的作用是让未通过认证的探测请求看到普通网页响应。

## 云厂商安全组要放行什么

默认安装需要在 VPS 控制面板的安全组或防火墙中放行：

| 用途 | 协议 | 端口 |
| --- | --- | --- |
| Hy2 端口跳跃 | UDP | `20000-50000` |
| 自动申请证书 | TCP | `80`、`443` |

这里说的是云厂商控制台中的安全组，例如 AWS、Google Cloud、Azure、Oracle Cloud、腾讯云或阿里云的入站规则。脚本不会替你修改云平台安全组。

如果你以后把 Hy2 改成单端口，就只需要放行那个 UDP 端口。

## 最简单的安装方法

登录 VPS 后依次执行：

```bash
curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/elonjack/hy2-safe/main/hy2-safe.sh \
  -o hy2-safe.sh

less hy2-safe.sh
chmod 0755 hy2-safe.sh
sudo ./hy2-safe.sh install
```

`less hy2-safe.sh` 用来先查看下载到的脚本。按 `q` 可以退出查看。

不建议使用 `curl ... | bash`，因为那样会把刚下载的内容直接交给 `root` 执行，不方便事先检查。

## 安装时每一项怎么选

脚本会依次提问。第一次使用可以这样填写：

| 提示 | 建议填写 |
| --- | --- |
| 证书/SNI 域名 | 你的 Hy2 子域名，例如 `hy2.example.com` |
| ACME 通知邮箱 | 你能正常接收邮件的邮箱 |
| 开启原生端口跳跃 | 直接回车，默认开启 |
| UDP 跳跃端口范围 | 直接回车，使用 `20000-50000` |
| 自定义 HTTPS 伪装站点 | 直接回车，使用本机静态页面 |
| 开启每周自动更新并在失败时回滚 | 直接回车，默认开启 |

密码会由脚本自动生成，不需要你自己编一个。安装成功后，终端会显示客户端 YAML 和分享链接，请把它们保存在安全的位置。

## 安装完成后怎么连接

先查看客户端信息：

```bash
sudo hy2-safe show-client
```

命令会输出两种内容：

- 客户端 YAML：适合复制到支持 Hysteria 2 配置文件的客户端。
- `hysteria2://` 分享链接：适合导入支持 Hy2 分享链接的客户端。

默认端口跳跃的 YAML 大致如下。实际域名和密码以你的服务器输出为准：

```yaml
server: "hy2.example.com:20000-50000"
auth: 这里是脚本生成的密码
tls:
  sni: hy2.example.com
fastOpen: true
transport:
  type: udp
  udp:
    minHopInterval: 15s
    maxHopInterval: 45s
```

不要把真实密码发到公开群聊、截图或 GitHub 仓库里。

## 常用管理命令

```bash
# 查看服务状态和当前版本
sudo hy2-safe status

# 再次显示客户端配置和分享链接
sudo hy2-safe show-client

# 修改域名、端口或伪装设置
sudo hy2-safe configure

# 立即检查并安装官方稳定版
sudo hy2-safe update

# 查看最近的服务日志
sudo hy2-safe logs

# 卸载服务
sudo hy2-safe uninstall
```

## 端口跳跃有什么用

单个 UDP 端口在某些网络中可能被限速、干扰或封锁。端口跳跃会让客户端在一段端口范围内定期更换目标端口，减少只针对单端口的干扰。

它不是万能的，也不能保证绕过所有封锁或 QoS。开启后必须满足两个条件：

1. 云厂商安全组放行完整的 UDP 范围。
2. 客户端使用脚本输出的端口范围和跳跃间隔。

修改为其他范围：

```bash
sudo hy2-safe configure \
  --port-hopping 30000-40000 \
  --hop-min 15 \
  --hop-max 45 \
  --non-interactive
```

关闭端口跳跃，改成单个 UDP 端口：

```bash
sudo hy2-safe configure --port 443 --non-interactive
```

修改后记得同步调整云厂商安全组。

## “伪装域名”到底是什么

这里有两个容易混淆的东西：

- **Hy2 域名**：例如 `hy2.example.com`。它指向 VPS，用于客户端连接、SNI 和申请 TLS 证书，必须由你控制。
- **伪装内容来源**：未通过 Hy2 认证的普通探测请求所看到的网页内容。

脚本默认使用本机生成的小型静态响应，不连接 Bing 或其他网站。这种方式最简单，也不会因为别人反复访问伪装页面而替第三方网站转发大量内容。

如果你确实有自己的正常 HTTPS 网站，也可以把它设置为伪装内容来源：

```bash
sudo hy2-safe configure \
  --masquerade-url https://www.example.org/ \
  --non-interactive
```

这里最好使用你信任并能控制的网站，而且不能与 Hy2 域名相同，否则可能产生代理循环。普通网站可以继续开启 Cloudflare 小黄云；只有直接连接 Hy2 的那个子域名必须使用灰云。

切回默认本机静态页面：

```bash
sudo hy2-safe configure --static-masquerade --non-interactive
```

## 别人会不会偷跑我的 VPS 流量

不知道连接密码的人不能把你的 Hy2 当作代理节点使用。只有认证成功后，Hysteria 才会处理代理请求。

真正需要注意的是“反向代理伪装”：如果你把一个包含大文件的网站设为伪装来源，任何人都可以反复访问伪装入口，让 VPS 去读取并返回这些内容，从而消耗出站流量。

因此，本脚本默认使用很小的本机静态响应，不请求上游网站。这样能避免由反向代理伪装造成的流量滥用，但任何公网服务仍然可能遭遇扫描、UDP 洪泛或 DDoS，这类风险需要依靠云厂商的防护和限流能力。

## 自动更新怎么工作

默认会启用 `hy2-safe-update.timer`，每周检查一次 Hysteria 官方最新稳定版。

更新时会检查下载地址、文件大小和官方 SHA-256；不会自动降级。新版本替换完成后会重启并检查服务，如果启动失败，就恢复上一个可用版本。

自动更新只更新 Hysteria 官方核心，不会远程替换 `hy2-safe` 管理脚本。

查看自动更新计划和日志：

```bash
systemctl list-timers hy2-safe-update.timer
journalctl -u hy2-safe-update.service
```

如果你不想自动更新，可以在安装时选择关闭，或使用：

```bash
sudo hy2-safe configure --no-auto-update --non-interactive
```

## 与 vps-security-bootstrap 一起使用

推荐顺序：

1. 运行 `vps-security-bootstrap`。
2. 新开一个 SSH 窗口，确认密钥登录正常，避免把自己锁在服务器外。
3. 运行 `hy2-safe`。
4. 在云厂商安全组放行 Hy2 的完整 UDP 范围和证书所需的 TCP 端口。

两者可以共同使用。`hy2-safe` 不会清空现有防火墙规则。如果你后来自己添加了“默认拒绝所有入站流量”的 nftables、UFW 或其他防火墙规则，仍需手动允许 Hy2 的 UDP 端口范围。

## 常见问题

### 证书申请失败

依次检查：

- Hy2 域名是否正确解析到这台 VPS。
- Cloudflare 是否为灰云“仅 DNS”。
- TCP `80` 和 `443` 是否已在云安全组和系统防火墙中放行。
- 这两个端口是否被其他程序占用。

### 安装成功但客户端连不上

依次检查：

- 云安全组是否放行完整的 UDP `20000-50000`。
- 客户端是否使用 `hy2-safe show-client` 输出的域名、密码和端口范围。
- 本地网络是否限制 UDP/QUIC。
- 服务是否正常：

```bash
sudo hy2-safe status
sudo hy2-safe logs
```

### 修改配置后服务启动失败

先查看：

```bash
sudo hy2-safe logs
```

常见原因是域名解析错误、端口被占用、证书验证需要的端口未放行，或端口跳跃所需的 nftables 不可用。

### 怎么确认正在使用哪个版本

```bash
sudo hy2-safe status
```

需要立即检查官方更新时执行：

```bash
sudo hy2-safe update
```

## 卸载

```bash
sudo hy2-safe uninstall
```

为防止误删，卸载会保留配置和 ACME 证书。以后想按原设置恢复，可以重新下载同一脚本并执行：

```bash
sudo ./hy2-safe.sh install --reinstall --non-interactive
```

## 进一步了解

- [Hysteria 2 官方安装文档](https://v2.hysteria.network/docs/getting-started/Installation/)
- [Hysteria 2 官方服务端配置](https://v2.hysteria.network/docs/getting-started/Server/)
- [Hysteria 2 完整服务端配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)
- [Hysteria 2 官方端口跳跃说明](https://v2.hysteria.network/docs/advanced/Port-Hopping/)
- [Hysteria 2 关于普通 CDN 的说明](https://v2.hysteria.network/docs/misc/CDN/)
- [Hysteria 官方 Releases](https://github.com/apernet/hysteria/releases)
