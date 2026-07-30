from pathlib import Path
import os
import re


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "hy2-safe.sh").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def require(pattern: str, message: str) -> None:
    if re.search(pattern, SCRIPT, re.MULTILINE) is None:
        raise AssertionError(message)


def forbid(pattern: str, message: str) -> None:
    if re.search(pattern, SCRIPT, re.MULTILINE) is not None:
        raise AssertionError(message)


require(r"^set -Eeuo pipefail$", "strict Bash mode is required")
require(r'PROGRAM_VERSION="1\.0\.2"', "the release must expose its manager version")
require(r"require_supported_os", "installations must be limited to Debian 12/13")
require(r"sha256sum", "release binaries must be checksum-verified")
require(r"release_asset_field", "release metadata must be parsed structurally")
require(r"asset_api_digest", "GitHub release asset digests must be checked")
require(r"compare_versions", "automatic updates must refuse downgrades")
require(r'最低版本 v2\.8\.0', "the installer must reject cores that predate native ranges and BBR profiles")
require(r"--max-filesize 134217728", "downloads must have a hard size ceiling")
if len(re.findall(r"--max-filesize 1048576", SCRIPT)) < 2:
    raise AssertionError("release metadata and hashes.txt must each have a 1 MiB ceiling")
require(r"stat -c '%s'", "download sizes must match release metadata")
require(r"reported_version=", "the verified binary must report its version")
require(r'"\$reported_version" == "\$version"', "the binary version must match release metadata")
require(r'sub\(/\^\.\*\\//, "", candidate\)', "hashes.txt build/ paths must be normalized")
require(r"REPOSITORY=\"apernet/hysteria\"", "downloads must use the official repository")
require(r"User=hysteria$", "the service must run as the dedicated user")
require(r"现有 hysteria 用户具有可登录 Shell", "pre-existing service users must be validated")
require(r"hysteria 组包含额外成员", "the config-reading group must reject extra members")
require(r'ACCOUNT_OWNERSHIP_PATH="\$\{CONFIG_DIR\}/hy2-safe-account\.env"', "account ownership must be recorded separately")
require(r"FORMAT_VERSION=1", "account ownership records must be versioned")
require(r"服务账号归属记录权限必须严格为 0600", "account ownership records must be root-only")
require(r'passwd --lock hysteria', "the service account password must be explicitly locked")
require(r'密码未锁定（状态必须为 L）', "service starts must reject an unlocked password")
require(r'存在 \.ssh/authorized_keys 入口', "service starts must reject SSH key entry points")
require(r'ExecStartPre=\+\$\{MANAGER_PATH\} verify-service-account', "every service start must verify the account as root")
require(r'install -d -m 0750 -o root -g hysteria "\$STATE_DIR"', "the service account home must not be writable by the account")
require(r'install -d -m 0750 -o hysteria -g hysteria "\$\{STATE_DIR\}/acme"', "only ACME state should be service-writable")
require(r'hysteria 家目录必须是 root:hysteria 0750', "service starts must verify the non-writable home permissions")
require(r'ACME 状态目录必须是 hysteria:hysteria 0750', "service starts must verify the writable ACME permissions")
require(r'"\$\(id -u hysteria\)" == "\$SERVICE_USER_UID"', "account deletion must be bound to the recorded UID")
require(r'"\$\(getent group hysteria \| awk -F: \'\{print \$3\}\'\)" == "\$SERVICE_GROUP_GID"', "group deletion must be bound to the recorded GID")
require(r'validate_root_secret_file "\$SETTINGS_PATH"', "managed settings must be ownership-checked")
require(r'service_capabilities="CAP_NET_BIND_SERVICE"', "low-port capability is required")
require(r'service_capabilities\+=" CAP_NET_ADMIN"', "port hopping must add NET_ADMIN only conditionally")
require(r'service_address_families\+=" AF_NETLINK"', "port hopping must allow nftables netlink only conditionally")
require(r'listen: ":%s-%s"', "native server-side port ranges must be supported")
require(r'HOP_START="50000"', "the default hopping range must use the audited narrow start port")
require(r'HOP_END="50500"', "the default hopping range must contain 501 candidate ports")
forbid(r'20000-50000', "the obsolete broad default hopping range must not return")
require(r"ignoreClientBandwidth: true", "the server must reject client bandwidth hints")
require(r"bbrProfile: conservative", "server and official client output must use conservative BBR")
if len(re.findall(r"bbrProfile: conservative", SCRIPT)) < 2:
    raise AssertionError("both server and official client output must use conservative BBR")
forbid(r"printf 'bandwidth:", "generated configs must not force a fixed bandwidth")
require(r"minHopInterval:", "client output must include randomized port hopping")
require(r"^socks5:$", "official client YAML must include a runnable client mode")
require(r'auth: "\$\{PASSWORD\}"', "official client YAML must preserve numeric-looking passwords as strings")
require(r"listen: 127\.0\.0\.1:1080", "official client YAML must bind its SOCKS5 proxy locally")
require(r"&insecure=0", "share links must keep certificate verification enabled explicitly")
require(r"&mport=\$\{HOP_START\}-\$\{HOP_END\}", "v2rayN/v2rayNG links must encode port hopping with mport")
require(r"compatible_share=.*\$\{DOMAIN\}:\$\{HOP_START\}/", "compatible links must keep a numeric URI port")
require(r'listen: "127\.0\.0\.1:%s"', "traffic stats must bind to loopback only")
require(r"LoadCredential=telegram-config:", "the notifier token must use systemd credentials")
require(r"DynamicUser=yes", "the notifier must use an isolated dynamic user")
require(r"SupplementaryGroups=systemd-journal", "the notifier needs read-only journal access")
require(r"PartOf=hysteria-server\.service", "the notifier must restart with Hysteria")
require(r"protect_content.*true", "Telegram messages must request content protection")
require(r"HOURLY_SECONDS = 3600", "reconnect alerts must be rate-limited")
require(r'f"v4:\{network\.network_address\}/24"', "IPv4 alerts must group by /24")
require(r'f"v6:\{network\.network_address\}/48"', "IPv6 alerts must group by /48")
require(r"--token-file FILE --chat-id ID", "Telegram setup must support a secret token file")
require(r"如果知道自己的私人 Chat ID，请输入", "interactive Telegram setup must accept a known private Chat ID")
require(r'pairing_code="HY2-\$\(openssl rand -hex 8\)"', "unknown Chat IDs must use a random one-time pairing code")
require(r'message\.get\("text"\) != pairing_code', "Telegram discovery must only accept the exact pairing code")
require(r"一次性配对码对应多个私人聊天，拒绝自动绑定", "ambiguous pairing codes must fail closed")
require(r"确认请输入 YES", "interactive setup must confirm that the test message reached the owner")
require(r"是否现在开启 Telegram 成功连接提醒", "interactive installs must offer Telegram setup")
require(r"flock -u 9\s+command_telegram_setup", "the install lock must be released before Telegram setup")
require(r"hy2-safe.*一键管理菜单", "running without a command must offer a management menu")
require(r'\[\[ "\$#" -eq 0 \]\][\s\S]*?command_menu', "no-argument interactive runs must open the menu")
require(r"完整卸载 Hy2", "the menu must expose a clearly labeled full uninstall")
require(r"更换 Telegram 机器人", "the menu must expose Telegram bot replacement")
require(r"删除 Telegram 通知", "the menu must expose Telegram notification removal")
require(r"3\)[\s\S]*?command_telegram_add", "the add menu entry must not silently replace an existing bot")
require(r"telegram-replace\) command_telegram_replace", "Telegram replacement needs a direct command")
require(r"立即检查更新（默认另有每周自动更新）", "manual update must be distinguished from automatic updates")
require(r"查看版本、服务和自动更新状态", "the status menu must clearly advertise version output")
require(r"refresh_managed_runtime", "downloaded manager updates must refresh hardened runtime files")
require(r"管理脚本、服务账号权限和 systemd 单元已同步", "runtime refreshes must be visible to the user")
require(r"当前 Hysteria 2 版本", "status output must show the installed Hysteria version first")
require(r"OnCalendar=weekly", "automatic updates must run weekly")
require(r"Persistent=true", "missed automatic update runs must be caught up")
require(r"确认完整卸载请输入 DELETE", "full uninstall must require destructive confirmation")
require(r"反复完整卸载重装.*频率限制", "full uninstall must warn about ACME reissuance limits")
require(r'"\$DEFAULT_DOWNLOAD_PATH"', "full uninstall must remove the recommended downloaded script")
require(r'remove_managed_tree "\$CONFIG_DIR"', "full uninstall must remove the managed config")
require(r'remove_managed_tree "\$STATE_DIR"', "full uninstall must remove ACME state")
require(r'remove_managed_tree "\$\{STATE_DIR\}/acme"', "untracked service accounts must only lose managed ACME state")
require(r'rmdir -- "\$STATE_DIR"', "untracked service-account homes may only be removed when empty")
require(r'remove_managed_tree "\$NOTIFIER_PRIVATE_STATE_DIR"', "DynamicUser private notifier state must be removed")
require(r'service_user_has_processes "\$service_uid"', "uninstall must reject deletion while the service UID still has processes")
require(r'Hysteria 服务仍在运行，拒绝继续卸载', "uninstall must verify that the service really stopped")
require(r'if \[\[ "\$SERVICE_USER_CREATED" -eq 1 \]\].*getent passwd hysteria', "only script-created users may be deleted")
require(r'userdel hysteria', "full uninstall must delete a script-created service user")
require(r'if \[\[ "\$SERVICE_GROUP_CREATED" -eq 1 \]\].*getent group hysteria', "only script-created groups may be deleted")
require(r'groupdel hysteria', "full uninstall must delete a script-created service group")
require(r"拒绝删除不在 hy2-safe 白名单中的目录", "recursive deletion must use an exact allowlist")
require(r"ProtectSystem=strict$", "the service unit must protect the filesystem")
require(r"ProcSubset=pid", "services must receive a restricted /proc view")
notifier_unit = re.search(
    r"write_notifier_unit\(\) \{.*?cat >\"\$NOTIFIER_SERVICE_PATH\" <<EOF\n(.*?)\nEOF",
    SCRIPT,
    re.DOTALL,
)
if notifier_unit is None:
    raise AssertionError("the notifier systemd unit must be extractable")
if re.search(r"(?m)^ProcSubset=pid$", notifier_unit.group(1)):
    raise AssertionError("the notifier must expose boot_id to its journalctl child")
if "ProtectProc=invisible" not in notifier_unit.group(1):
    raise AssertionError("the notifier must retain process visibility hardening")
require(r"MemoryDenyWriteExecute=true", "services must deny writable executable memory")
require(r"ReadWritePaths=/usr/local/bin /run/lock", "the updater must have a narrow writable filesystem")
require(r"正在自动回滚", "updates must implement rollback")
require(r"正在恢复上一份配置", "configuration changes must implement rollback")
require(r"masquerade_host", "masquerade proxy loops must be checked")
require(r"validate_public_masquerade_target", "masquerade proxies must reject private targets")
require(r"validate_password_file", "password files must be permission-checked")
require(r"下面会显示完整 Hy2 密码和分享链接", "client output must warn before revealing credentials")
require(r"printf '  type: string", "the safe default must use a fixed string response")

forbid(r"chmod\s+(?:-R\s+)?777", "world-writable permissions are forbidden")
forbid(r"iptables\s+-t\s+nat\s+-F", "the installer must not flush firewall chains")
forbid(r"insecure:\s+true", "TLS verification must not be disabled")
forbid(r"skip-cert-verify", "TLS verification must not be disabled")
forbid(r"fastOpen:\s+true", "client output must preserve correct proxy failure semantics")
forbid(r"(?m)^\s*bandwidth:", "generated client YAML must not force a fixed bandwidth")
forbid(r"www\.bing\.com", "third-party self-signed identities are forbidden")
forbid(r"curl[^\n]*\|\s*(?:ba)?sh", "download-and-execute pipelines are forbidden")
forbid(r"MASQUERADE_DIR", "the fixed default masquerade must not expose a writable directory")
forbid(r"--telegram-token(?:\s|=)", "Bot tokens must never be accepted on the command line")
forbid(r"--password(?:\s+PASSWORD|\))", "Hy2 passwords must never be accepted in command-line arguments")
forbid(r"userdel\s+(?:-[a-zA-Z]*r[a-zA-Z]*|--remove)\s+hysteria", "userdel must not recursively follow the home path")

python_blocks = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", SCRIPT, re.DOTALL)
if len(python_blocks) < 10:
    raise AssertionError("all embedded Python helpers must use quoted heredocs")
for index, source in enumerate(python_blocks, start=1):
    compile(source, f"embedded-python-{index}.py", "exec")


match = re.search(
    r"write_notifier_script\(\) \{.*?cat >\"\$tmp\" <<'PY'\n(.*?)\nPY\n  chmod 0755",
    SCRIPT,
    re.DOTALL,
)
if match is None:
    raise AssertionError("embedded notifier source must be extractable")

previous_credentials = os.environ.get("CREDENTIALS_DIRECTORY")
previous_state = os.environ.get("STATE_DIRECTORY")
os.environ["CREDENTIALS_DIRECTORY"] = str(ROOT / "tests")
os.environ["STATE_DIRECTORY"] = str(ROOT / "tests")
namespace = {"__name__": "hy2_notifier_test"}
try:
    exec(compile(match.group(1), "hy2-safe-notifier.py", "exec"), namespace)
finally:
    if previous_credentials is None:
        os.environ.pop("CREDENTIALS_DIRECTORY", None)
    else:
        os.environ["CREDENTIALS_DIRECTORY"] = previous_credentials
    if previous_state is None:
        os.environ.pop("STATE_DIRECTORY", None)
    else:
        os.environ["STATE_DIRECTORY"] = previous_state

parse_remote_ip = namespace["parse_remote_ip"]
hidden_ip_group = namespace["hidden_ip_group"]
extract_connection = namespace["extract_connection"]
process_connection = namespace["process_connection"]
queue_hourly_summaries = namespace["queue_hourly_summaries"]
default_state = namespace["default_state"]
namespace["online_line"] = lambda _config: "当前在线客户端：1"

v4_key, v4_label = hidden_ip_group(parse_remote_ip("123.45.67.89:443"))
if (v4_key, v4_label) != ("v4:123.45.67.0/24", "123.45.67.*"):
    raise AssertionError("IPv4 hiding/grouping is incorrect")

v6_key, v6_label = hidden_ip_group(parse_remote_ip("[2408:8215:1234::99]:443"))
if (v6_key, v6_label) != ("v6:2408:8215:1234::/48", "2408:8215:1234:*"):
    raise AssertionError("IPv6 hiding/grouping is incorrect")

event = extract_connection(
    {
        "MESSAGE": (
            '2026-07-29T12:00:00+08:00 INFO client connected '
            '{"addr":"123.45.67.89:4567","id":"user","tx":0}'
        ),
        "__REALTIME_TIMESTAMP": "1785297600000000",
    }
)
if event is None or event[0] != "123.45.67.89:4567":
    raise AssertionError("successful Hysteria connection logs must be recognized")

state = default_state()
config = {}
process_connection(state, config, "123.45.67.89:4567", 1000.0)
process_connection(state, config, "123.45.67.90:5678", 1010.0)
group = state["groups"]["v4:123.45.67.0/24"]
if group["pending_reconnects"] != 1 or len(state["groups"]) != 1:
    raise AssertionError("same-/24 reconnects must be grouped")
queue_hourly_summaries(state, config, 4611.0)
if group["pending_reconnects"] != 0:
    raise AssertionError("hourly summaries must consume grouped reconnect counts")
if "hourly:v4:123.45.67.0/24" not in state["outbox"]:
    raise AssertionError("an hourly reconnect summary must be queued")
process_connection(state, config, "123.45.67.91:6789", 100000.0)
if "returned:v4:123.45.67.0/24" not in state["outbox"]:
    raise AssertionError("a /24 returning after 24 hours must alert again")

if not README.startswith("# hy2-safe\n"):
    raise AssertionError("README must start with one H1 project title")
if README.count("```") % 2:
    raise AssertionError("README fenced code blocks must be balanced")
if "[!IMPORTANT]" not in README or "[!WARNING]" not in README:
    raise AssertionError("README must make the main safety warnings prominent")
if "hy2-safe v1.0.2 一键管理菜单" not in README:
    raise AssertionError("README menu version must match the release")
if "/etc/hysteria/hy2-safe-account.env" not in README:
    raise AssertionError("README must explain the account ownership record")
if "密码状态必须是 `L`" not in README:
    raise AssertionError("README must explain the locked service-account password")
if "## 隐私与敏感信息" not in README:
    raise AssertionError("README must explain what sensitive data leaves the VPS")
combined_public_text = SCRIPT + "\n" + README
for email in re.findall(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b",
    combined_public_text,
):
    if not email.lower().endswith("@example.com"):
        raise AssertionError(f"unexpected public email literal: {email}")
for secret_pattern, description in (
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private key"),
    (r"\bgh[opusr]_[A-Za-z0-9_]{20,}\b", "GitHub token"),
    (r"\b[0-9]{6,12}:[A-Za-z0-9_-]{25,}\b", "Telegram Bot token"),
):
    if re.search(secret_pattern, combined_public_text):
        raise AssertionError(f"unexpected {description} literal in public files")
if "raw.githubusercontent.com/elonjack/hy2-safe/main/hy2-safe.sh" not in README:
    raise AssertionError("README must contain the public one-line installer URL")
if "apt-get install -y --no-install-recommends ca-certificates curl" not in README:
    raise AssertionError("the one-line installer must support minimal Debian without curl")
if "sudo " in README:
    raise AssertionError("README commands are written for the root-user workflow")
for label, target in re.findall(r"\[([^\]\n]+)\]\(([^)\n]+)\)", README):
    if not label.strip() or not target.strip():
        raise AssertionError("README contains an empty Markdown link")

print("static checks passed")
