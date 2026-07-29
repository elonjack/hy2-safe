from pathlib import Path
import os
import re


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "hy2-safe.sh").read_text(encoding="utf-8")


def require(pattern: str, message: str) -> None:
    if re.search(pattern, SCRIPT, re.MULTILINE) is None:
        raise AssertionError(message)


def forbid(pattern: str, message: str) -> None:
    if re.search(pattern, SCRIPT, re.MULTILINE) is not None:
        raise AssertionError(message)


require(r"^set -Eeuo pipefail$", "strict Bash mode is required")
require(r"require_supported_os", "installations must be limited to Debian 12/13")
require(r"sha256sum", "release binaries must be checksum-verified")
require(r"release_asset_field", "release metadata must be parsed structurally")
require(r"asset_api_digest", "GitHub release asset digests must be checked")
require(r"compare_versions", "automatic updates must refuse downgrades")
require(r"--max-filesize 134217728", "downloads must have a hard size ceiling")
require(r"stat -c '%s'", "download sizes must match release metadata")
require(r'sub\(/\^\.\*\\//, "", candidate\)', "hashes.txt build/ paths must be normalized")
require(r"REPOSITORY=\"apernet/hysteria\"", "downloads must use the official repository")
require(r"User=hysteria$", "the service must run as the dedicated user")
require(r'service_capabilities="CAP_NET_BIND_SERVICE"', "low-port capability is required")
require(r'service_capabilities\+=" CAP_NET_ADMIN"', "port hopping must add NET_ADMIN only conditionally")
require(r'service_address_families\+=" AF_NETLINK"', "port hopping must allow nftables netlink only conditionally")
require(r'listen: ":%s-%s"', "native server-side port ranges must be supported")
require(r"ignoreClientBandwidth: true", "the server must reject client bandwidth hints")
require(r"bbrProfile: conservative", "server and official client output must use conservative BBR")
if len(re.findall(r"bbrProfile: conservative", SCRIPT)) < 2:
    raise AssertionError("both server and official client output must use conservative BBR")
forbid(r"printf 'bandwidth:", "generated configs must not force a fixed bandwidth")
require(r"minHopInterval:", "client output must include randomized port hopping")
require(r"^socks5:$", "official client YAML must include a runnable client mode")
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
require(r"是否现在开启 Telegram 成功连接提醒", "interactive installs must offer Telegram setup")
require(r"flock -u 9\s+command_telegram_setup", "the install lock must be released before Telegram setup")
require(r"hy2-safe 一键管理菜单", "running without a command must offer a management menu")
require(r'\[\[ "\$#" -eq 0 \]\][\s\S]*?command_menu', "no-argument interactive runs must open the menu")
require(r"完整卸载 Hy2", "the menu must expose a clearly labeled full uninstall")
require(r"更换 Telegram 机器人", "the menu must expose Telegram bot replacement")
require(r"删除 Telegram 通知", "the menu must expose Telegram notification removal")
require(r"3\) command_telegram_add", "the add menu entry must not silently replace an existing bot")
require(r"telegram-replace\) command_telegram_replace", "Telegram replacement needs a direct command")
require(r"立即检查更新（默认另有每周自动更新）", "manual update must be distinguished from automatic updates")
require(r"查看版本、服务和自动更新状态", "the status menu must clearly advertise version output")
require(r"当前 Hysteria 2 版本", "status output must show the installed Hysteria version first")
require(r"OnCalendar=weekly", "automatic updates must run weekly")
require(r"Persistent=true", "missed automatic update runs must be caught up")
require(r"确认完整卸载请输入 DELETE", "full uninstall must require destructive confirmation")
require(r"反复完整卸载重装.*频率限制", "full uninstall must warn about ACME reissuance limits")
require(r'"\$DEFAULT_DOWNLOAD_PATH"', "full uninstall must remove the recommended downloaded script")
require(r'remove_managed_tree "\$CONFIG_DIR"', "full uninstall must remove the managed config")
require(r'remove_managed_tree "\$STATE_DIR"', "full uninstall must remove ACME state")
require(r'remove_managed_tree "\$NOTIFIER_PRIVATE_STATE_DIR"', "DynamicUser private notifier state must be removed")
require(r"拒绝删除不在 hy2-safe 白名单中的目录", "recursive deletion must use an exact allowlist")
require(r"ProtectSystem=strict$", "the service unit must protect the filesystem")
require(r"ReadWritePaths=/usr/local/bin /run/lock", "the updater must have a narrow writable filesystem")
require(r"正在自动回滚", "updates must implement rollback")
require(r"正在恢复上一份配置", "configuration changes must implement rollback")
require(r"masquerade_host", "masquerade proxy loops must be checked")
require(r"validate_public_masquerade_target", "masquerade proxies must reject private targets")
require(r"validate_password_file", "password files must be permission-checked")
require(r"printf '  type: string", "the safe default must use a fixed string response")

forbid(r"chmod\s+(?:-R\s+)?777", "world-writable permissions are forbidden")
forbid(r"iptables\s+-t\s+nat\s+-F", "the installer must not flush firewall chains")
forbid(r"insecure:\s+true", "TLS verification must not be disabled")
forbid(r"skip-cert-verify", "TLS verification must not be disabled")
forbid(r"www\.bing\.com", "third-party self-signed identities are forbidden")
forbid(r"curl[^\n]*\|\s*(?:ba)?sh", "download-and-execute pipelines are forbidden")
forbid(r"MASQUERADE_DIR", "the fixed default masquerade must not expose a writable directory")
forbid(r"--telegram-token(?:\s|=)", "Bot tokens must never be accepted on the command line")

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

print("static checks passed")
