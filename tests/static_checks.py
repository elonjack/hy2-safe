from pathlib import Path
import datetime as dt
import json
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
require(r'PROGRAM_VERSION="1\.0\.7"', "the release must expose its manager version")
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
require(r'"parse_mode": "HTML"', "Telegram notices must use structured HTML formatting")
require(r'"disable_notification": "true" if silent else "false"', "scheduled reports must support silent delivery")
require(r"HOURLY_SECONDS = 3600", "reconnect alerts must be rate-limited")
require(r"TRAFFIC_SAMPLE_SECONDS = 60", "traffic sampling must remain lightweight")
require(r'stats_json\(config, "/traffic"\)', "reports must use Hysteria's official local traffic API")
forbid(r"/traffic\?clear=1", "traffic reporting must not clear official counters")
require(r'Path\("/sys/class/net"\)', "VPS totals must use kernel interface counters")
require(r'Path\("/proc/net/route"\)', "VPS totals must prefer default-route interfaces")
forbid(r"\btcpdump\b", "traffic reporting must never capture packets")
require(r'"version": 2', "notifier traffic state must be versioned")
require(r"if version == 1:", "v1 notifier state must migrate forward")
require(r"REPORT_HOUR = 8", "daily reports must use the documented Beijing schedule")
require(r"MONTHLY_REPORT_MINUTE = 5", "monthly reports must follow the daily report")
require(r"telegram-report\) command_telegram_report", "manual traffic reports need a direct command")
require(r"telegram-name\) command_telegram_name", "Telegram instance names need a direct command")
require(r'"display_name": display_name', "the notifier credential must store the instance name")
require(r"instance_line\(config\)", "every report family must expose the instance name")
require(r"设置 Telegram 消息名称", "the menu must expose instance-name management")
require(r"--signal=SIGUSR1", "manual reports must signal only the running notifier")
require(r'f"v4:\{network\.network_address\}/24"', "IPv4 alerts must group by /24")
require(r'f"v6:\{network\.network_address\}/48"', "IPv6 alerts must group by /48")
require(r"--token-file FILE --chat-id ID", "Telegram setup must support a secret token file")
require(r"私人 Chat ID \[知道请直接输入；不知道请直接回车使用一次性配对码\]", "interactive Telegram setup must accept a known private Chat ID")
require(r'pairing_code="HY2-\$\(openssl rand -hex 8\)"', "unknown Chat IDs must use a random one-time pairing code")
require(r'message\.get\("text"\) != pairing_code', "Telegram discovery must only accept the exact pairing code")
require(r"一次性配对码对应多个私人聊天，拒绝自动绑定", "ambiguous pairing codes must fail closed")
require(r"确认请输入 YES", "interactive setup must confirm that the test message reached the owner")
require(r"是否现在开启 Telegram 成功连接提醒", "interactive installs must offer Telegram setup")
require(r"flock -u 9\s+command_telegram_setup", "the install lock must be released before Telegram setup")
require(r"Hysteria 2 管理菜单", "running without a command must offer a management menu")
require(r'\[\[ "\$#" -eq 0 \]\][\s\S]*?command_menu', "no-argument interactive runs must open the menu")
require(r"完整卸载 Hy2", "the menu must expose a clearly labeled full uninstall")
require(r"更换 Telegram 机器人", "the menu must expose Telegram bot replacement")
require(r"删除 Telegram 通知", "the menu must expose Telegram notification removal")
require(r"3\)[\s\S]*?command_telegram_add", "the add menu entry must not silently replace an existing bot")
require(r"telegram-replace\) command_telegram_replace", "Telegram replacement needs a direct command")
require(r"立即检查更新（默认另有每周自动更新）", "manual update must be distinguished from automatic updates")
require(r"查看版本、服务和自动更新状态", "the status menu must clearly advertise version output")
require(r"initialize_colors", "interactive output must initialize colors centrally")
require(r'-z "\$\{NO_COLOR\+x\}"', "NO_COLOR must disable ANSI styling")
require(r'"\$\{TERM:-dumb\}" != "dumb"', "dumb terminals must not receive ANSI styling")
require(r"\[\[ -t 1", "redirected output must not receive ANSI styling")
require(r"menu_item", "menu options must use one consistent formatter")
require(r"COLOR_YELLOW=\$'\\033\[33m'", "prompts and menu choices must use ANSI yellow")
require(r"COLOR_CYAN=\$'\\033\[36m'", "menu headings must use ANSI cyan")
require(r"COLOR_GREEN=\$'\\033\[32m'", "informational output must use ANSI green")
require(r"COLOR_RED=\$'\\033\[31m'", "errors must use ANSI red")
require(r"\[Y/n，直接回车默认：是\]", "yes-default prompts must explain Enter behavior")
require(r"\[y/N，直接回车默认：否\]", "no-default prompts must explain Enter behavior")
require(r"prompt_yes_no", "yes/no decisions must use one validated prompt helper")
require(r"请输入 y（是）或 n（否）", "invalid yes/no input must be rejected visibly")
forbid(r"read -r (?:-s )?-p", "interactive reads must use the centralized safe prompt helpers")
require(r"refresh_managed_runtime", "downloaded manager updates must refresh hardened runtime files")
require(r"管理脚本、服务账号权限和 systemd 单元已同步", "runtime refreshes must be visible to the user")
require(r"当前 Hysteria 2 版本", "status output must show the installed Hysteria version first")
require(r"OnCalendar=weekly", "automatic updates must run weekly")
require(r"Persistent=true", "missed automatic update runs must be caught up")
require(r'printf \'  type: "%s"\\n\\n\' "\$ACME_TYPE"', "ACME challenge type must be explicit")
require(r'ACME_TYPE="http"', "fresh installs must default to HTTP-01 on TCP 80 only")
require(r"preflight_domain", "install and configure must preflight public DNS")
require(r"preflight_ports", "install and configure must preflight TCP/UDP conflicts")
require(r"ss -H -lnt", "ACME TCP conflicts must be detected before changes")
require(r"ss -H -lun", "Hy2 UDP conflicts must be detected before changes")
require(r"OnCalendar=\*-\*-\* 09:00", "certificate health must be checked daily")
require(r"certificate-warning", "certificate expiry failures must support Telegram alerts")
require(r"update-failed", "failed Hysteria updates must support Telegram alerts")
require(r"update-success", "successful version changes must support Telegram alerts")
require(r"一键重置 Hy2 密码", "the menu must expose safe password rotation")
require(r"command_rotate_password", "password rotation must have a dedicated command")
require(r"正在恢复旧配置", "password rotation failures must roll back")
require(r"HY2_SAFE_SOURCE_ONLY", "Debian smoke tests must be able to source helpers safely")
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
normalize_state = namespace["normalize_state"]
counter_delta = namespace["counter_delta"]
sample_traffic = namespace["sample_traffic"]
queue_scheduled_reports = namespace["queue_scheduled_reports"]
monthly_report_text = namespace["monthly_report_text"]
manual_report_text = namespace["manual_report_text"]
aggregate_days = namespace["aggregate_days"]
records_for_month = namespace["records_for_month"]
format_bytes = namespace["format_bytes"]
send_message = namespace["send_message"]
drain_journal = namespace["drain_journal"]
hy2_traffic_totals = namespace["hy2_traffic_totals"]
network_counters = namespace["network_counters"]
namespace["online_line"] = lambda _config: "当前在线客户端：1"


class PipeProcess:
    def __init__(self, stream):
        self.stdout = stream


read_fd, write_fd = os.pipe()
os.set_blocking(read_fd, False)
burst = b"".join(
    json.dumps({"MESSAGE": f"client connected {index}"}).encode("utf-8") + b"\n"
    for index in range(25)
)
os.write(write_fd, burst)
os.close(write_fd)
with os.fdopen(read_fd, "rb", buffering=0) as stream:
    journal_buffer, journal_entries, journal_eof = drain_journal(
        PipeProcess(stream), b""
    )
if journal_buffer or len(journal_entries) != 25 or not journal_eof:
    raise AssertionError("burst journal records must be drained without buffering delays")

class LegacyConfigPath:
    def read_text(self, encoding: str) -> str:
        if encoding != "utf-8":
            raise AssertionError("Telegram credentials must be decoded as UTF-8")
        return json.dumps(
            {
                "token": "123456:" + "A" * 32,
                "chat_id": "123456789",
                "stats_port": 19090,
                "stats_secret": "B" * 32,
            }
        )


namespace["config_path"] = LegacyConfigPath()
legacy_config = namespace["load_config"]()
if legacy_config["display_name"] != "Hy2 节点":
    raise AssertionError("v1.0.5 Telegram credentials must receive a safe default name")

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

colored_message = (
    "2026-07-30T15:35:10+08:00\t\x1b[34mINFO\x1b[0m\t"
    'client connected\t{"addr":"198.51.100.77:2776","id":"user","tx":0}'
)
binary_event = extract_connection(
    {
        "MESSAGE": list(colored_message.encode("utf-8")),
        "__REALTIME_TIMESTAMP": "1785396910639499",
    }
)
if binary_event is None or binary_event[0] != "198.51.100.77:2776":
    raise AssertionError(
        "ANSI-colored journal MESSAGE byte arrays must be recognized"
    )

trailing_ansi_event = extract_connection(
    {
        "MESSAGE": (
            'INFO client connected {"addr":"123.45.67.89:4567",'
            '"id":"user","tx":0}\x1b[0m'
        ),
    }
)
if trailing_ansi_event is None or trailing_ansi_event[0] != "123.45.67.89:4567":
    raise AssertionError("trailing ANSI data must not hide successful connections")

state = default_state()
config = {"display_name": "洛杉矶 01"}
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

escaped_state = default_state()
escaped_config = {"display_name": "东京 <主机&01>"}
process_connection(
    escaped_state, escaped_config, "198.51.100.77:4567", 1000.0
)
escaped_text = escaped_state["outbox"]["new:v4:198.51.100.0/24"]["text"]
if "东京 &lt;主机&amp;01&gt;" not in escaped_text or "东京 <主机&01>" in escaped_text:
    raise AssertionError("Telegram instance names must be HTML-escaped")

beijing = dt.timezone(dt.timedelta(hours=8))
sample_time = dt.datetime(2026, 7, 30, 12, 0, tzinfo=beijing).timestamp()
migrated = normalize_state(
    {
        "version": 1,
        "last_daily_date": "2026-07-30",
        "groups": state["groups"],
        "outbox": {
            "old": {
                "text": "old alert",
                "created": sample_time,
            }
        },
    },
    sample_time,
)
if migrated["version"] != 2 or not migrated["groups"]:
    raise AssertionError("v1 notifier state must migrate without losing groups")
if migrated["outbox"]["old"]["silent"]:
    raise AssertionError("migrated connection alerts must remain audible")
if migrated["reporting_started_date"] != "2026-07-30":
    raise AssertionError("traffic accounting must start on the migration date")

if counter_delta(None, 100) != 0:
    raise AssertionError("the first traffic counter sample must be a baseline")
if counter_delta(100, 175) != 75:
    raise AssertionError("monotonic traffic counters must add only their delta")
if counter_delta(100, 25) != 25:
    raise AssertionError("reset traffic counters must restart from their current value")
if format_bytes(1024**3) != "1.00 GiB":
    raise AssertionError("traffic sizes must use unambiguous IEC units")

telegram_fields = {}
namespace["telegram_call"] = lambda _config, _method, fields: telegram_fields.update(
    fields
)
send_message({"chat_id": "1"}, "<b>report</b>", silent=True)
if (
    telegram_fields.get("parse_mode") != "HTML"
    or telegram_fields.get("disable_notification") != "true"
    or telegram_fields.get("protect_content") != "true"
):
    raise AssertionError("formatted silent Telegram reports must stay protected")

namespace["stats_json"] = lambda _config, path: (
    {
        "user": {"tx": 1200, "rx": 3400},
        "other": {"tx": 50, "rx": 60},
    }
    if path == "/traffic"
    else {}
)
if hy2_traffic_totals({}) != {"upload": 1250, "download": 3460}:
    raise AssertionError("official per-client traffic values must be summed correctly")

if os.name == "posix" and Path("/proc/net/route").exists():
    detected_counters = network_counters()
    if not detected_counters:
        raise AssertionError("the Linux default-route interface must be measurable")
    for interface, counters in detected_counters.items():
        if (
            not interface
            or counters["receive"] < 0
            or counters["send"] < 0
        ):
            raise AssertionError("Linux interface counters must be non-negative")

traffic_state = default_state(sample_time)
hy2_sample = {"upload": 1000, "download": 2000}
nic_sample = {"eth0": {"receive": 4000, "send": 5000}}
namespace["hy2_traffic_totals"] = lambda _config: dict(hy2_sample)
namespace["network_counters"] = lambda: {
    key: dict(value) for key, value in nic_sample.items()
}
namespace["online_count"] = lambda _config: 1
sample_traffic(traffic_state, {}, sample_time)
first_day = traffic_state["traffic"]["days"]["2026-07-30"]
if first_day["hy2_upload"] or first_day["vps_receive"]:
    raise AssertionError("initial samples must not count pre-install traffic")

hy2_sample.update(upload=1600, download=2900)
nic_sample["eth0"].update(receive=4700, send=6200)
namespace["online_count"] = lambda _config: 3
sample_traffic(traffic_state, {}, sample_time + 60)
if (
    first_day["hy2_upload"],
    first_day["hy2_download"],
    first_day["vps_receive"],
    first_day["vps_send"],
) != (600, 900, 700, 1200):
    raise AssertionError("Hy2 and VPS traffic deltas must be accumulated separately")
if first_day["peak_online"] != 3:
    raise AssertionError("daily peak online devices must be retained")

hy2_sample.update(upload=100, download=200)
nic_sample["eth0"].update(receive=50, send=80)
sample_traffic(traffic_state, {}, sample_time + 120)
if (
    first_day["hy2_upload"],
    first_day["hy2_download"],
    first_day["vps_receive"],
    first_day["vps_send"],
) != (700, 1100, 750, 1280):
    raise AssertionError("counter resets must not create negatives or giant spikes")

july_snapshot = dict(first_day)
august_time = dt.datetime(2026, 8, 1, 0, 1, tzinfo=beijing).timestamp()
hy2_sample.update(upload=180, download=320)
nic_sample["eth0"].update(receive=150, send=200)
sample_traffic(traffic_state, {}, august_time)
august_day = traffic_state["traffic"]["days"]["2026-08-01"]
if (
    august_day["hy2_upload"],
    august_day["hy2_download"],
    august_day["vps_receive"],
    august_day["vps_send"],
) != (80, 120, 100, 120):
    raise AssertionError("a new calendar month must start its own traffic totals")
if first_day != july_snapshot:
    raise AssertionError("new-month samples must not change prior-month records")
july_total = aggregate_days(
    [item[1] for item in records_for_month(traffic_state, "2026-07")]
)
august_total = aggregate_days(
    [item[1] for item in records_for_month(traffic_state, "2026-08")]
)
if july_total["hy2_upload"] != 700 or august_total["hy2_upload"] != 80:
    raise AssertionError("monthly totals must include only their own calendar month")

before_report = dt.datetime(2026, 7, 31, 7, 59, tzinfo=beijing).timestamp()
queue_scheduled_reports(traffic_state, config, before_report)
if any(key.startswith("daily:") for key in traffic_state["outbox"]):
    raise AssertionError("daily reports must not be sent before 08:00 Beijing time")
daily_time = dt.datetime(2026, 7, 31, 8, 0, tzinfo=beijing).timestamp()
queue_scheduled_reports(traffic_state, config, daily_time)
daily_item = traffic_state["outbox"].get("daily:2026-07-30")
if daily_item is None or not daily_item["silent"]:
    raise AssertionError("the previous-day report must be queued silently at 08:00")
queue_scheduled_reports(traffic_state, config, daily_time + 60)
if len([key for key in traffic_state["outbox"] if key.startswith("daily:")]) != 1:
    raise AssertionError("daily reports must be idempotent")

monthly_before = dt.datetime(2026, 8, 1, 8, 4, tzinfo=beijing).timestamp()
queue_scheduled_reports(traffic_state, config, monthly_before)
if "monthly:2026-07" in traffic_state["outbox"]:
    raise AssertionError("monthly reports must not be sent before 08:05")
monthly_time = dt.datetime(2026, 8, 1, 8, 5, tzinfo=beijing).timestamp()
queue_scheduled_reports(traffic_state, config, monthly_time)
monthly_item = traffic_state["outbox"].get("monthly:2026-07")
if monthly_item is None or not monthly_item["silent"]:
    raise AssertionError("the previous-month report must be queued silently at 08:05")
if "Hy2 月度报告" not in monthly_report_text(
    traffic_state, config, "2026-07"
):
    raise AssertionError("monthly report formatting is missing")
if "洛杉矶 01" not in monthly_item["text"]:
    raise AssertionError("scheduled reports must identify their VPS instance")
if "VPS 网卡与 Hy2 统计口径不同" not in manual_report_text(
    traffic_state, config, monthly_time
):
    raise AssertionError("manual reports must explain the incompatible traffic scopes")

if not README.startswith("# hy2-safe\n"):
    raise AssertionError("README must start with one H1 project title")
if README.count("```") % 2:
    raise AssertionError("README fenced code blocks must be balanced")
if "[!IMPORTANT]" not in README or "[!WARNING]" not in README:
    raise AssertionError("README must make the main safety warnings prominent")
if "hy2-safe v1.0.7 · Hysteria 2 管理菜单" not in README:
    raise AssertionError("README menu version must match the release")
if "/etc/hysteria/hy2-safe-account.env" not in README:
    raise AssertionError("README must explain the account ownership record")
if "密码状态必须是 `L`" not in README:
    raise AssertionError("README must explain the locked service-account password")
if "## 隐私与敏感信息" not in README:
    raise AssertionError("README must explain what sensitive data leaves the VPS")
if "NO_COLOR=1 hy2-safe" not in README:
    raise AssertionError("README must explain how to disable interactive colors")
if "直接回车默认：是" not in README or "直接回车默认：否" not in README:
    raise AssertionError("README must explain yes/no defaults in plain language")
if "进入下个月后新月份从 `0` 开始" not in README:
    raise AssertionError("README must explain natural-month traffic resets")
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
