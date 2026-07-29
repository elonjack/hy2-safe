# hy2-safe

这是一个尽量小、可审计的 Hysteria 2 服务端安装与维护脚本。它不复用来源不明的二进制或长期不更新的安装副本，只从 Hysteria 官方仓库下载最新稳定版。

## 为什么重新做

对 `Misaka-blog/hysteria-install` 的 `hy2/hysteria.sh` 和它附带的 `install_server.sh` 做过逐行检查后，主要问题如下：

| 问题 | 影响 | hy2-safe 的处理 |
| --- | --- | --- |
| `chmod -R 777 /root`，证书和私钥也设为 `777` | 本机任意用户都可能读取或篡改私钥；`/root` 权限被整体破坏 | 配置 `0640`，管理信息 `0600`，服务以独立用户运行 |
| 默认伪造 `www.bing.com` 自签证书，客户端固定 `insecure: true` | 客户端不验证服务端身份，失去 TLS 身份认证 | 只使用你控制的域名和 ACME 真证书，客户端不关闭校验 |
| `wget` 下载另一个脚本后立即以 root 执行 | 上游文件变化时难以审计；下载内容没有完整性验证 | 只下载官方发布二进制，强制校验 GitHub API 的 Asset SHA-256 并再次核对官方 `hashes.txt` |
| 更新依赖手动选择菜单，且没有校验和、失败回滚 | 不是自动更新；更新损坏或不兼容时可能直接停服 | systemd timer 每周检查稳定版；原子替换，重启失败自动回滚 |
| 安装/卸载会清空整个 iptables `PREROUTING` 链 | 可能破坏 Docker、转发、NAT 或其他服务规则 | 不清空现有链；端口跳跃仅使用 Hysteria 原生临时规则 |
| 服务权限宽，脚本到处写 `/root` | 扩大被利用后的影响范围 | 独立 `hysteria` 用户、最小 capability、systemd 沙箱 |
| 修改密码和伪装站点的 `sed` 目标/行号存在明显错误 | 菜单显示修改成功，实际配置可能没有变化 | 原子重写完整配置，并通过服务重启结果判断是否成功 |
| 仓库最后提交为 2024-04-18 | 无法及时跟进 Hysteria 的配置变化和安全更新 | 核心版本与管理脚本解耦，只跟踪官方稳定发布 |

旧脚本的“核心更新”确实会查询官方仓库的最新版本，所以手动执行时有机会升级核心；但它既不是自动更新，也不校验下载文件，更没有失败回滚。

## 安全设计

- 只接受 `https://github.com/apernet/hysteria` 的稳定 Release。
- 结构化解析 GitHub Release JSON，拒绝草稿、预发布、重复 Asset 和异常下载地址。
- 下载二进制与官方 `hashes.txt`；同时核对 Asset 大小和 GitHub Asset SHA-256，再用 `hashes.txt` 交叉校验。任何字段缺失或不一致都拒绝安装。
- 新二进制先落到临时文件，再原子替换；保留上一版用于回滚。
- 自动更新会比较严格的三段稳定版本号，发现官方 `latest` 低于已安装版本时拒绝降级。
- 自动更新只更新 Hysteria 核心，不会远程替换本管理脚本。
- 使用 ACME 真证书，客户端配置中没有 `insecure: true` 或 `skip-cert-verify`。
- Hysteria 以 `hysteria` 用户运行；单端口只保留 `CAP_NET_BIND_SERVICE`，开启端口跳跃时才额外授予 `CAP_NET_ADMIN`。
- 不开放安全组、不清空现有链。端口跳跃由 Hysteria 原生管理自己的 nftables/iptables 临时转发规则，服务停止时自动清理。
- 检测到旧脚本或其他工具管理的 Hysteria 文件时拒绝覆盖，避免误伤现有节点。
- 默认使用官方 `string` 模式返回很小的固定页面，不访问上游站点，也不暴露可写目录。也可以明确指定自己的 HTTPS 伪装站点。
- 卸载时保留配置和 ACME 证书，防止误删；需要彻底清理时由管理员确认目录后手动处理。

## 安装前准备

1. 一台使用 systemd 的 Debian 12 或 Debian 13 VPS。为缩小未测试分支和包管理差异，本版本会拒绝在其他发行版上安装。
2. 一个你控制的域名，例如 `hy2.example.com`，A/AAAA 记录直接解析到 VPS，并在 Cloudflare 中设为“仅 DNS”（灰云）。
3. 云厂商安全组和系统防火墙允许：
   - Hysteria 数据端口：默认跳跃范围 `UDP 20000-50000`；
   - ACME 验证：通常需要 `TCP 80/443`。
4. 如果使用反向代理伪装，准备一个可正常通过 HTTPS 访问的站点。不要把伪装 URL 指回同一个 Hysteria 域名，否则会形成代理循环。

这里有两个容易混淆的概念：

- `--domain` 是你自己的证书/SNI 域名，客户端用它验证服务器身份。
- `--masquerade-url` 是普通访客通过 HTTP/3 探测时看到的伪装内容来源。它可以是你自己的另一个站点；留空则使用本机静态页。

反代伪装只允许 `https://` 公网站点，并会拒绝当前解析到私网、环回或保留地址的目标，避免把 VPS 内部 Web 服务意外暴露出去。DNS 以后仍可能变化，因此只应填写你信任和控制的站点。

## Cloudflare 与伪装域名

普通 Cloudflare“小黄云”只代理它支持的 HTTP/HTTPS 等流量，不能作为 Hysteria 2 的 UDP/QUIC 入口。Hysteria 官方也明确说明其认证后会切换到 CDN 不理解的自定义协议，因此不能套普通 CDN。

推荐结构：

- `hy2.example.com`：灰云，仅 DNS，直接指向 VPS，用于 Hysteria 地址、SNI 和 ACME 证书。
- `www.example.net`：可以继续开 Cloudflare 小黄云，作为另一个正常网站或 `--masquerade-url` 的内容来源。
- 更省依赖的选择是保留默认本机静态伪装页。

灰云确实会让 `hy2.example.com` 的 DNS 暴露 VPS IP，但直连 Hysteria 本来就必须让客户端知道可达地址。想真正隐藏源站只能使用额外的四层代理；Cloudflare 对自定义 UDP 的 Spectrum 是单独的企业级付费能力，不是普通小黄云，而且不属于本脚本支持范围。

## “伪装域名会被偷流量”是什么意思

不知道认证密码的人不能把你的 Hysteria 当作 TCP/UDP 代理。官方协议要求只有认证成功后才开始处理代理请求；认证失败或普通 HTTP/3 请求只会走伪装响应。

但“反代伪装”仍有一种真实的流量风险：任何人都能请求伪装入口，服务器会替他访问你配置的上游页面并把内容返回。如果上游存在大文件或动态接口，别人反复请求会消耗 VPS 出站流量。这不是偷走 Hy2 节点权限，而是滥用公开 Web 响应。

因此脚本默认采用固定的小型 `string` 响应，不发起任何上游请求；只有你显式填写 `--masquerade-url` 才开启反代，并会显示风险警告。固定响应仍无法抵御纯粹的 UDP 洪泛或 DDoS——任何公网服务都存在这类带宽风险，需要云厂商清洗或限流能力处理。

## 与 vps-security-bootstrap 配合

已按 `elonjack/vps-security-bootstrap` 当前脚本核对过。它安装 nftables，并让 Fail2ban 使用自己的 nftables 表/链，但没有建立全局“默认拒绝”入站策略；hy2-safe 的原生端口范围由 Hysteria 创建独立的临时重定向规则，正常情况下两者可以共存。Fail2ban 的 recidive 封禁某个来源后，该来源无法访问 Hy2 也是预期行为。

推荐顺序就是：

1. 先运行 `vps-security-bootstrap`，确认新的 SSH 公钥登录正常。
2. 再运行 hy2-safe。
3. 在云厂商安全组放行完整的 Hy2 UDP 范围，并为 ACME 放行 TCP 80/443。

注意：原生端口跳跃规则负责“把范围内 UDP 重定向到首端口”，不负责绕过你以后另行添加的默认拒绝防火墙。如果你自己再配置 nftables 输入策略，仍要显式放行该 UDP 范围。

不要把“伪装 URL”与“证书/SNI 域名”混在一起。用 Bing 当反向代理内容来源可以工作，但把 `www.bing.com` 写进自签证书并让客户端跳过验证并不安全，因为你并不拥有 Bing 的证书。证书/SNI 应始终使用自己的域名；伪装内容优先选自己可控的另一个正常站点或本机静态页。

## 使用

先把脚本下载到 VPS，阅读内容后再执行。不要使用 `curl | bash`。

```bash
curl -fL --proto '=https' --tlsv1.2 \
  https://raw.githubusercontent.com/elonjack/hy2-safe/main/hy2-safe.sh \
  -o hy2-safe.sh
less hy2-safe.sh
chmod 0755 hy2-safe.sh
sudo ./hy2-safe.sh install
```

非交互式安装：

```bash
sudo ./hy2-safe.sh install \
  --domain hy2.example.com \
  --email admin@example.com \
  --port-hopping 20000-50000 \
  --hop-min 15 \
  --hop-max 45 \
  --masquerade-url https://www.example.org/ \
  --auto-update \
  --non-interactive
```

不填写密码时会生成 256 位随机密码。需要自定义时，只接受 16-128 位的字母、数字、`_` 和 `-`，避免 YAML 与分享链接转义歧义。命令行参数可能被 shell 历史和进程列表记录，因此自动化场景优先使用由 root 拥有、权限不宽于 `0600`、且不是符号链接的文件：

```bash
sudo ./hy2-safe.sh install \
  --domain hy2.example.com \
  --email admin@example.com \
  --password-file /root/hy2-password \
  --non-interactive
```

安装完成后，管理命令位于 `/usr/local/sbin/hy2-safe`：

```bash
sudo hy2-safe status
sudo hy2-safe show-client
sudo hy2-safe configure
sudo hy2-safe update
sudo hy2-safe logs
sudo hy2-safe uninstall
```

卸载会保留配置与证书。以后要按原参数恢复，可把本项目脚本重新复制到服务器后运行：

```bash
sudo ./hy2-safe.sh install --reinstall --non-interactive
```

切换到自己的伪装站点：

```bash
sudo hy2-safe configure \
  --masquerade-url https://www.example.org/ \
  --non-interactive
```

切回本机静态页：

```bash
sudo hy2-safe configure --static-masquerade --non-interactive
```

## 端口跳跃

默认启用 Hysteria 2 原生端口范围监听：

```yaml
listen: ":20000-50000"
```

服务端实际监听范围首端口，并通过自己创建的 nftables/iptables 临时规则接收整个范围。客户端配置使用随机 15-45 秒间隔；分享链接也包含端口范围，不支持随机间隔字段的客户端会使用其默认间隔。

修改范围：

```bash
sudo hy2-safe configure \
  --port-hopping 30000-40000 \
  --hop-min 15 \
  --hop-max 45 \
  --non-interactive
```

关闭端口跳跃、改回单端口：

```bash
sudo hy2-safe configure --port 443 --non-interactive
```

除了 VPS 本机防火墙，还必须在云厂商安全组中放行完整 UDP 范围。脚本不会自动修改安全组、UFW 或 firewalld。

## 自动更新

默认安装 `hy2-safe-update.timer`，每周在随机延迟窗口内检查一次官方最新稳定版：

```bash
systemctl list-timers hy2-safe-update.timer
journalctl -u hy2-safe-update.service
```

更新流程为：

1. 查询 `apernet/hysteria` 最新稳定 Release；
2. 从 Release JSON 确认唯一的二进制和 `hashes.txt` Asset，并限制下载地址必须属于该官方 Release；
3. 强制校验 GitHub Asset 大小与 SHA-256，再按当前 CPU 架构核对 `hashes.txt` 中的 SHA-256；
4. 备份旧二进制并原子替换；
5. 重启服务并连续检查状态；
6. 若新版本无法正常运行，恢复旧二进制并再次启动。

自动升级仍然意味着信任 Hysteria 官方 GitHub 账号及其发布链路。更保守的做法是安装时加 `--no-auto-update`，收到官方安全公告后手动运行 `sudo hy2-safe update`。

## 文件位置

| 路径 | 用途 |
| --- | --- |
| `/usr/local/bin/hysteria` | Hysteria 官方二进制 |
| `/usr/local/bin/hysteria.previous` | 自动更新回滚用的上一版 |
| `/usr/local/sbin/hy2-safe` | 本地管理器副本 |
| `/etc/hysteria/config.yaml` | 服务端配置，`0640 root:hysteria` |
| `/etc/hysteria/hy2-safe.env` | 生成客户端配置所需的信息，`0600 root:root` |
| `/var/lib/hysteria/acme` | ACME 账户和证书状态 |

## 当前取舍

- 端口跳跃默认开启，并使用 Hysteria 原生端口范围。它需要 `CAP_NET_ADMIN`，因此服务受攻击后的潜在网络权限高于单端口模式；不需要时应通过 `--port 443` 关闭。
- 不提供默认自签证书。自签证书配合证书指纹也可以安全使用，但客户端兼容和迁移更复杂；公网 VPS 使用 ACME 更简单。
- 不自动修改 UFW、firewalld 或云安全组。Hysteria 原生端口跳跃会创建并清理自己的底层 nftables/iptables 临时规则，但不会清空现有规则链。

## 参考

- [Hysteria 2 官方安装文档](https://v2.hysteria.network/docs/getting-started/Installation/)
- [Hysteria 2 官方服务端配置](https://v2.hysteria.network/docs/getting-started/Server/)
- [Hysteria 2 完整服务端配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/)
- [Hysteria 2 端口跳跃](https://v2.hysteria.network/docs/advanced/Port-Hopping/)
- [Hysteria 2 为什么不能套普通 CDN](https://v2.hysteria.network/docs/misc/CDN/)
- [Cloudflare Spectrum](https://developers.cloudflare.com/spectrum/)
- [Hysteria 官方 Releases](https://github.com/apernet/hysteria/releases)
- [被审查的原脚本](https://github.com/Misaka-blog/hysteria-install/blob/main/hy2/hysteria.sh)
