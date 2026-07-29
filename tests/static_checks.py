from pathlib import Path
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
require(r"minHopInterval:", "client output must include randomized port hopping")
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

print("static checks passed")
