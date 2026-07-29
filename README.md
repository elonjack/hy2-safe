# hy2-safe

一个面向 Debian 12/13 的 Hysteria 2（Hy2）服务端安装与管理脚本。

脚本默认使用你自己的域名和正规 TLS 证书，开启 UDP 端口跳跃，并每周检查 Hysteria 2 官方稳定版更新。本文按 `root` 用户编写，命令不需要加 `sudo`。

> [!IMPORTANT]
> **防火墙最容易弄混：VPS 系统防火墙和云厂商防火墙是两层独立的防火墙。哪一层设置了“默认拒绝入站”，就必须在哪一层放行 SSH、TCP 80/443 和 Hy2 使用的 UDP 端口。两层都拒绝时，两层都要放行。**

## 这个脚本能做什么

- 从 Hysteria 官方 GitHub 仓库安装最新稳定版，并校验官方 SHA-256。
- 使用你自己的域名，由 Hysteria 自动申请和续期公开可信的 TLS 证书。
- 默认开启原生 UDP 端口跳跃，范围为 `20000-50000`。
- 不硬编码上传/下载 Mbps；服务端拒绝客户端提交的固定带宽值，默认使用较稳健的自适应 BBR，避免错误带宽触发 Brutal 丢包补偿。
- 使用系统密码学随机源生成约 256 bit 熵的连接密码。
- 默认每周检查 Hysteria 官方稳定版；更新失败会自动恢复旧版本。
- Hysteria 以独立低权限用户运行。
- 默认返回很小的本机伪装内容，不反向代理 Bing 等第三方网站。
- 输出官方客户端完整 YAML、官方分享链接和 v2rayN/v2rayNG 兼容链接。
- 可选开启 Telegram 成功连接提醒，并自动合并网络抖动产生的重复消息。

## 开始前要准备什么

你需要：

1. 一台全新的 Debian 12 或 Debian 13 VPS。
2. 一个由你管理的域名。
3. 一个专门给 Hy2 使用的子域名，例如 `hy2.example.com`。
4. VPS 的 `root` 权限。

如果你使用 [vps-security-bootstrap](https://github.com/elonjack/vps-security-bootstrap)，建议先运行它，再新开一个 SSH 窗口确认密钥登录正常，最后安装 Hy2。

## Cloudflare 域名怎么设置

假设 VPS 的公网 IPv4 是 `203.0.113.10`，你准备用 `hy2.example.com`：

1. 在 Cloudflare DNS 中新建一条 `A` 记录。
2. 名称填写 `hy2`，地址填写 VPS 公网 IPv4。
3. **代理状态选择“仅 DNS”（灰色云朵）**。
4. VPS 确实有可用公网 IPv6 时，可以给同一名称增加 `AAAA` 记录；没有配置好就不要加。

Hy2 使用 UDP/QUIC。Cloudflare 普通小黄云不能转发这种自定义 UDP 服务，所以 Hy2 子域名不能开启小黄云。

灰云会让 DNS 查询者看到 VPS IP，这是直连 Hy2 无法避免的。伪装不能隐藏入口 IP，它只能让未通过认证的普通探测看到一个正常 HTTPS 响应。

## 防火墙先看懂：系统防火墙和云防火墙

它们不是同一个东西：

| 防火墙 | 在哪里 | 谁负责设置 |
| --- | --- | --- |
| VPS 系统防火墙 | Debian 内部，例如 nftables、UFW、firewalld | 你在 VPS 中设置 |
| 云防火墙/安全组 | 云厂商网络边界、VPS 外部 | 你在云厂商控制台设置 |

网络流量必须依次通过存在的每一层。脚本无法替你修改云厂商控制台。

| 实际情况 | 你要做什么 |
| --- | --- |
| 两层都没有默认拒绝规则 | 不需要执行“开放端口”；服务监听后就能接收流量 |
| 只有系统防火墙默认拒绝 | 在系统防火墙放行 |
| 只有云防火墙默认拒绝 | 在云厂商控制台放行 |
| 两层都默认拒绝 | 两层都要放行相同的必要端口 |

“不需要开放端口”只代表功能上不会被防火墙挡住，**不代表整台 VPS 更安全**。没有默认拒绝防火墙时，其他正在监听公网地址的服务也可能暴露。

很多普通 VPS 没有默认拒绝防火墙也能长期正常使用，是因为没有程序监听的端口本来就无法建立连接，加上 SSH 密钥、Fail2ban、及时更新和服务自身认证，扫描者通常无法进入。默认拒绝防火墙仍然是一层额外保险：以后某个程序如果意外监听公网，它可以先把流量挡住。当前不启用默认拒绝防火墙并不等于 Hy2 密码会失效，但必须继续保护 SSH、及时更新系统并妥善保管节点密码。

**所以，防火墙不是“不开就一定会被入侵”，也不是安装 Hy2 的强制条件。** 对一台全新、只运行 SSH 和 Hy2、已经使用密钥登录并及时更新的 VPS，不开启全局默认拒绝通常也能合理使用，只是少了一层保护。默认拒绝防火墙更适合防止将来误装的数据库、管理面板、Docker 容器等程序意外监听公网。脚本不会自动强开默认拒绝，因为错误规则可能直接把你的 SSH 锁在服务器外。

默认配置需要允许：

| 用途 | 协议 | 端口 |
| --- | --- | --- |
| 你实际使用的 SSH 端口 | TCP | 例如 `22`，以你的设置为准 |
| Hysteria 自动申请和续期证书 | TCP | `80`、`443` |
| Hy2 默认端口跳跃 | UDP | `20000-50000` |

如果改成单端口，只需允许那个 UDP 端口；如果改了跳跃范围，就允许新的完整范围。

你当前使用的 `vps-security-bootstrap` 会安装 nftables，并让 Fail2ban 动态封禁攻击者，但没有建立一个全局 `input policy drop` 的默认拒绝防火墙。`hy2-safe` 也不会擅自添加入站放行规则。Hysteria 为端口跳跃建立的 nftables 重定向属于端口转发，不等于在默认拒绝防火墙中放行了这些端口。

如果 CloudCone 控制台没有云防火墙或安全组功能，通常就没有那一层规则需要设置；仍应以你购买的具体产品控制台和文档为准。

## 最简单的安装方法

你平时使用 `root` 登录，可以复制下面一整行：

```bash
curl -fL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/elonjack/hy2-safe/main/hy2-safe.sh -o /root/hy2-safe.sh && chmod 0700 /root/hy2-safe.sh && /root/hy2-safe.sh install
```

这个写法会先把脚本保存到磁盘，再执行，不是 `curl | bash`。如果想先查看内容，使用：

```bash
curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/elonjack/hy2-safe/main/hy2-safe.sh \
  -o /root/hy2-safe.sh

less /root/hy2-safe.sh
chmod 0700 /root/hy2-safe.sh
/root/hy2-safe.sh install
```

在 `less` 中按 `q` 退出。

## 安装时怎么选择

第一次安装可以这样填写：

| 提示 | 建议填写 |
| --- | --- |
| 证书/SNI 域名 | `hy2.example.com` |
| ACME 通知邮箱 | 你能正常接收邮件的邮箱 |
| 开启原生端口跳跃 | 直接回车，默认开启 |
| UDP 跳跃端口范围 | 直接回车，默认 `20000-50000` |
| 自定义 HTTPS 伪装站点 | 直接回车，使用本机小型静态响应 |
| 开启每周自动更新并在失败时回滚 | 直接回车，默认开启 |
| 安装完成后开启 Telegram 连接提醒 | 需要就输入 `y`；暂时不需要直接回车 |

密码由脚本自动生成。不要把真实密码发到公开群聊、截图或 GitHub 仓库。

## 证书是谁申请、多久续期

服务端配置中的 `acme` 会让 **Hysteria 自己使用 ACME 自动申请和续期证书**。当前配置使用公开可信 CA 的生产环境（默认是 Let’s Encrypt），不是 Cloudflare Origin CA 证书，也不需要你从 Cloudflare 下载证书。

Cloudflare 在这里仅负责 DNS。Hy2 子域名保持灰云，域名正确指向 VPS，并让 TCP 80/443 能到达 Hysteria，才可以完成验证。

证书有效期由 CA 的当期政策决定，不应在脚本中写死。Let’s Encrypt 证书属于短周期证书，Hysteria 会在需要时自动续期；证书和 ACME 状态保存在 `/var/lib/hysteria/acme`。因此正常情况下不需要手动重新申请。

## 安装完成后怎么连接

查看客户端信息：

```bash
hy2-safe show-client
```

端口跳跃模式会输出三部分：

1. **Hysteria 2 官方客户端完整 YAML**：包含本机 SOCKS5 监听 `127.0.0.1:1080`，可直接作为官方客户端配置使用。
2. **Hysteria 2 官方分享链接**：端口范围直接写在地址中。
3. **v2rayN/v2rayNG 兼容分享链接**：URI 主端口保持为数字，跳跃范围通过 `mport=20000-50000` 传递。

v2rayN 和 v2rayNG 使用第三种兼容链接。建议使用较新的客户端版本；v2rayN 可优先选择支持 Hy2 的 sing-box 核心。

官方客户端 YAML 大致如下，实际域名和密码以服务器输出为准：

```yaml
server: "hy2.example.com:20000-50000"
auth: 这里是脚本生成的密码
tls:
  sni: hy2.example.com
congestion:
  type: bbr
  bbrProfile: conservative
fastOpen: true
transport:
  type: udp
  udp:
    minHopInterval: 15s
    maxHopInterval: 45s
socks5:
  listen: 127.0.0.1:1080
```

### 为什么没有上传、下载 Mbps

脚本有意不在服务端、官方客户端 YAML 或分享链接里填写固定的上传/下载速度。公司宽带、家庭 Wi-Fi 和手机网络的可用带宽会不断变化，不存在一个适合所有设备的固定数值。

Hysteria 2 一旦填写 `bandwidth.up` 或 `bandwidth.down`，相应方向可能改用固定目标速率的 Brutal。Brutal 在丢包时还可能为了达到目标速度而增加发送量；数值高于真实线路能力时，反而更容易造成拥塞、抖动和流量浪费。

本脚本生成的服务端配置使用：

```yaml
ignoreClientBandwidth: true
congestion:
  type: bbr
  bbrProfile: conservative
```

这表示服务端不会采信客户端随意填写的 Mbps，而是使用会根据网络状况自行调整的非 Brutal 拥塞控制。官方客户端 YAML 同样明确选择 `bbrProfile: conservative`。分享链接不包含带宽值，这也符合 Hysteria 2 官方 URI 规范；该规范明确说明带宽属于每个客户端自己的本地参数，不应写进分享链接。

这项设置可以降低错误带宽参数导致的激进发包风险，但无法保证运营商一定不做 UDP QoS，也无法保证 IP 永不受限。Hy2 本身仍然是 UDP/QUIC 协议；实际传输大量数据时仍会产生相应 UDP 流量。

分享链接会明确带上 `insecure=0`，不会关闭证书验证。

## Telegram 连接提醒

这是可选功能，默认不启用。正常执行一键安装时，Hy2 启动成功并输出客户端配置后，脚本会直接询问：

```text
是否现在开启 Telegram 成功连接提醒？[y/N]:
```

输入 `y` 会在同一次一键脚本中继续配置；直接回车则跳过。保留独立的 `hy2-safe telegram-setup` 命令，是为了以后补开提醒、更换机器人或重新设置时不需要重装 Hy2。建议专门创建一个只用于 Hy2 提醒的新机器人，不要复用正在处理其他命令或 webhook 的机器人。

### 第一次设置

如果 VPS 以前安装过旧版 `hy2-safe`，运行 `hy2-safe telegram-setup` 提示未知命令，先安全更新管理脚本：

```bash
curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/elonjack/hy2-safe/main/hy2-safe.sh \
  -o /root/hy2-safe.sh
chmod 0700 /root/hy2-safe.sh
/root/hy2-safe.sh install --reinstall --non-interactive
```

1. 在 Telegram 中找到官方的 `@BotFather`。
2. 发送 `/newbot`，按照提示创建机器人并得到 Bot Token。
3. 打开刚创建的机器人，给它发送任意一条私人消息。
4. 如果当前仍处于一键安装的 Telegram 提示中，直接输入 `y` 并跟随提示。如果安装时已经跳过，之后执行：

```bash
hy2-safe telegram-setup
```

5. 粘贴 Bot Token。输入时终端不会显示字符，这是正常的。
6. 脚本会通过 Telegram 官方接口列出最近给机器人发过消息的私人 Chat ID。
7. 只选择属于你自己的 Chat ID。
8. 收到测试消息并且服务检查通过后，提醒才算启用。

运行期间，机器人不会读取命令、不会设置 webhook，也不会回复其他用户；它只会向设置时确认的那个私人 Chat ID 主动发送消息。设置阶段会读取一次最近私人消息，用来帮助你找到自己的 Chat ID。

### IP 怎么显示

机器人不会发送完整客户端 IP：

- IPv4 `123.45.67.89` 显示为 `123.45.67.*`。
- IPv6 `2408:8215:1234:5678:...` 显示为 `2408:8215:1234:*`。

IPv4 只隐藏最后一段，比隐藏最后两段更适合安全提醒：既不显示完整地址，又能区分大多数不同网络。提醒程序自己的状态文件只保存上述已隐藏网段，不额外保存完整 IP；但 Hysteria 原始服务日志本身仍可能按照 systemd journal 的保留策略包含完整连接地址。

### 怎么防止晚高峰刷屏

- 第一次出现的新 IP 网段会立即提醒。
- 同一个 IPv4 `/24` 网段或 IPv6 `/48` 网段反复重连时，一小时内不逐条发送。
- 一小时后只发送一条合并汇总，告诉你重复连接次数、第一次和最近一次连接时间。
- 同一网段超过 24 小时没有出现，后来再次连接时会重新立即提醒。
- 每天发送一份连接来源汇总。
- 当前在线客户端数量来自只监听 `127.0.0.1`、带随机密钥保护的 Hysteria Traffic Stats API，不向公网开放。
- Telegram 暂时不可用时，消息会留在受限状态文件中稍后重试；提醒故障不会参与或阻断 Hy2 认证和转发。

示例：

```text
Hy2 重连汇总

IP（已隐藏最后一部分）：123.45.67.*
首次发现：2026-07-29 20:06:12
最近连接：2026-07-29 20:48:35
本次合并的重复连接：12 次
当前在线客户端：1
```

常用命令：

```bash
# 发送一条测试消息
hy2-safe telegram-test

# 查看提醒服务日志
hy2-safe telegram-logs

# 查看 Hy2 和提醒服务状态
hy2-safe status

# 关闭提醒并从配置中删除 Bot Token
hy2-safe telegram-disable
```

Bot Token 保存在 root-only 的 `0600` 配置文件中，并通过 systemd 凭据功能只交给受限的提醒进程。不要把 Token 发到聊天群、截图或 GitHub；如果 Token 泄露，应立即在 `@BotFather` 撤销并重新生成。

## IPv4、IPv6、域名和证书

一个客户端节点的“服务器地址”不一定只能写一个 IP，也可以写域名：

- `hy2.example.com` 同时有 `A` 和 `AAAA` 记录时，一个节点可以解析出 IPv4 和 IPv6。最终使用哪个地址由客户端核心、系统 DNS 和路由策略决定，**不保证先测速再自动选择最优线路**。
- 如果节点地址直接填写 IPv4，那么它只会走 IPv4。
- 如果节点地址直接填写 IPv6，那么它只会走 IPv6。

因此，你说的“建两个节点，一个写 IPv4、一个写 IPv6，自己手动选择”是对的。关键是两个节点都把 TLS 的 SNI/服务器名称设为同一个 `hy2.example.com`：

| 节点 | 连接地址 | TLS SNI |
| --- | --- | --- |
| Hy2-IPv4 | VPS 的 IPv4 | `hy2.example.com` |
| Hy2-IPv6 | VPS 的 IPv6 | `hy2.example.com` |

这样仍然只需要 **一张 `hy2.example.com` 的证书**。证书验证的是 TLS SNI 域名，不要求连接地址也必须是域名。

不要为了区分线路直接改用 `hy2-v4.example.com` 和 `hy2-v6.example.com`，除非证书也同时包含这两个名称。当前脚本一次配置一个证书域名，最简单可靠的做法是两个节点共用同一个 SNI。

服务端的 `listen: ":端口"` 按 Hysteria 官方定义会监听所有可用 IPv4 和 IPv6 接口，但 VPS 本身必须真正拥有可用公网 IPv6，云厂商和系统防火墙也必须允许相应流量。

## 端口跳跃有什么用

单个 UDP 端口在某些网络中可能被限速、干扰或封锁。端口跳跃让客户端定期更换目标端口，可以减少只针对单端口的干扰，但不能保证绕过所有封锁或 QoS。

修改范围：

```bash
hy2-safe configure \
  --port-hopping 30000-40000 \
  --hop-min 15 \
  --hop-max 45 \
  --non-interactive
```

关闭跳跃并改成单个 UDP 端口：

```bash
hy2-safe configure --port 443 --non-interactive
```

修改后要同步检查系统防火墙和云防火墙。

## “伪装域名”到底是什么

这里有两个容易混淆的概念：

- **Hy2 域名**：例如 `hy2.example.com`，用于连接、TLS SNI 和申请证书，必须由你控制。
- **伪装内容来源**：未通过 Hy2 认证的普通 HTTPS 请求所看到的内容。

脚本默认返回固定的小型本机响应，不连接 Bing 或其他上游网站。这比反向代理一个大型第三方网站更可控，也避免别人反复请求伪装入口，迫使 VPS 从上游下载大文件。

如果你确实有自己控制的正常 HTTPS 网站，可以设置为伪装来源：

```bash
hy2-safe configure \
  --masquerade-url https://www.example.org/ \
  --non-interactive
```

伪装来源不能与 Hy2 域名相同，否则可能形成代理循环。切回默认本机响应：

```bash
hy2-safe configure --static-masquerade --non-interactive
```

## 会不会被偷跑流量

脚本生成 32 个密码学随机字节，再编码为 43 个 Base64URL 字符，搜索空间约为 `2^256`。

严谨地说，任何有限密码都不能宣称“数学上绝对不可能猜中”。但在随机源正常、密码没有泄露的前提下，通过公网逐个尝试穷举 256 bit 随机值在现实计算能力和时间尺度上不可行。

更现实的风险是：

- 把分享链接或客户端配置发到了公开位置。
- 客户端设备、中转剪贴板、网盘或聊天账号被入侵。
- 使用反向代理大型网站作为伪装来源，造成公开可触发的流量消耗。
- 公网 UDP 服务遭遇扫描、洪泛或 DDoS；强密码不能阻止这种攻击。

如果怀疑泄露，可以用下面的方法安全生成并换成新密码，然后删除所有旧客户端配置：

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > /root/hy2-new-password
chmod 0600 /root/hy2-new-password
hy2-safe configure --password-file /root/hy2-new-password --non-interactive
rm -f /root/hy2-new-password
```

## 自动更新怎么工作

默认启用 `hy2-safe-update.timer`，每周检查 Hysteria 官方最新稳定版。

更新会核对下载地址、文件大小、GitHub Release 元数据和官方 SHA-256，不会自动降级。替换后会重启并检查服务，启动失败则恢复上一版本。自动更新只更新 Hysteria 官方核心，不会远程替换 `hy2-safe` 管理脚本。

```bash
systemctl list-timers hy2-safe-update.timer
journalctl -u hy2-safe-update.service
```

关闭自动更新：

```bash
hy2-safe configure --no-auto-update --non-interactive
```

## 常用管理命令

```bash
# 查看服务状态和当前版本
hy2-safe status

# 显示客户端配置和分享链接
hy2-safe show-client

# 修改域名、端口、密码或伪装设置
hy2-safe configure

# 立即检查并安装官方稳定版
hy2-safe update

# 查看最近日志
hy2-safe logs

# 卸载服务
hy2-safe uninstall
```

## 常见问题

### 证书申请失败

依次检查：

- Hy2 域名是否正确指向本 VPS。
- Cloudflare 是否为灰云“仅 DNS”。
- 云防火墙和系统防火墙中，TCP 80/443 是否都能到达 VPS。
- TCP 80/443 是否被其他程序占用。

### 安装成功但客户端连不上

依次检查：

- 所有启用入站过滤的防火墙层是否允许完整 UDP 范围。
- 客户端是否使用 `hy2-safe show-client` 输出的域名、密码和端口范围。
- v2rayN/v2rayNG 是否导入了带 `mport` 的兼容链接。
- 本地网络是否限制 UDP/QUIC。
- `hy2-safe status` 和 `hy2-safe logs` 是否有错误。

### 和 vps-security-bootstrap 一起怎么用

推荐顺序：

1. 运行 `vps-security-bootstrap`。
2. 新开 SSH 窗口确认密钥登录正常。
3. 运行 `hy2-safe`。
4. 如果将来增加默认拒绝防火墙，先允许实际 SSH TCP 端口、TCP 80/443、Hy2 的完整 UDP 范围，再启用默认拒绝。
5. 云厂商控制台另有防火墙时，也要在那里设置一次。

## 卸载

```bash
hy2-safe uninstall
```

为避免误删，卸载会保留配置和 ACME 证书。以后恢复：

```bash
/root/hy2-safe.sh install --reinstall --non-interactive
```

## 官方资料

- [Hysteria 2 服务端配置](https://v2.hysteria.network/docs/getting-started/Server/)
- [Hysteria 2 客户端配置](https://v2.hysteria.network/docs/getting-started/Client/)
- [Hysteria 2 完整客户端配置](https://v2.hysteria.network/docs/advanced/Full-Client-Config/)
- [Hysteria 2 端口跳跃](https://v2.hysteria.network/docs/advanced/Port-Hopping/)
- [Hysteria 2 URI 格式](https://v2.hysteria.network/docs/developers/URI-Scheme/)
- [Hysteria 官方 Releases](https://github.com/apernet/hysteria/releases)
