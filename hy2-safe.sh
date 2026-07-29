#!/usr/bin/env bash
#
# hy2-safe - a small, auditable Hysteria 2 server installer/manager.
#
# Security properties:
#   - downloads only official apernet/hysteria stable releases;
#   - verifies the selected binary against GitHub's asset digest and hashes.txt;
#   - installs atomically and rolls back a failed update;
#   - runs Hysteria as an unprivileged user with a hardened systemd unit;
#   - uses a real ACME certificate and never sets insecure=true for clients;
#   - never flushes or rewrites the host firewall.

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly PROGRAM="hy2-safe"
readonly REPOSITORY="apernet/hysteria"
readonly API_URL="https://api.github.com/repos/${REPOSITORY}/releases/latest"
readonly RELEASE_URL="https://github.com/${REPOSITORY}/releases/download"
readonly BIN_PATH="/usr/local/bin/hysteria"
readonly PREVIOUS_BIN_PATH="/usr/local/bin/hysteria.previous"
readonly MANAGER_PATH="/usr/local/sbin/hy2-safe"
readonly CONFIG_DIR="/etc/hysteria"
readonly CONFIG_PATH="${CONFIG_DIR}/config.yaml"
readonly SETTINGS_PATH="${CONFIG_DIR}/hy2-safe.env"
readonly STATE_DIR="/var/lib/hysteria"
readonly SERVICE_PATH="/etc/systemd/system/hysteria-server.service"
readonly UPDATE_SERVICE_PATH="/etc/systemd/system/hy2-safe-update.service"
readonly UPDATE_TIMER_PATH="/etc/systemd/system/hy2-safe-update.timer"
readonly NOTIFIER_PATH="/usr/local/libexec/hy2-safe-notifier.py"
readonly NOTIFIER_CONFIG_PATH="${CONFIG_DIR}/telegram-notifier.json"
readonly NOTIFIER_SERVICE_PATH="/etc/systemd/system/hy2-safe-notifier.service"
readonly NOTIFIER_STATE_DIR="/var/lib/hy2-safe-notifier"
readonly SERVICE_NAME="hysteria-server.service"
readonly TIMER_NAME="hy2-safe-update.timer"
readonly NOTIFIER_NAME="hy2-safe-notifier.service"
readonly LOCK_PATH="/run/lock/hy2-safe.lock"

QUIET=0
TMP_ROOT=""

info() {
  if [[ "$QUIET" -eq 0 ]]; then
    printf '[信息] %s\n' "$*"
  fi
}

warn() {
  printf '[警告] %s\n' "$*" >&2
}

die() {
  printf '[错误] %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$TMP_ROOT" && "$TMP_ROOT" == /tmp/hy2-safe.* && -d "$TMP_ROOT" ]]; then
    rm -rf -- "$TMP_ROOT"
  fi
}
trap cleanup EXIT

usage() {
  cat <<'EOF'
hy2-safe - 安全、精简的 Hysteria 2 服务端管理器

用法：
  ./hy2-safe.sh install [选项]
  hy2-safe configure [选项]
  hy2-safe update [--quiet]
  hy2-safe show-client
  hy2-safe status
  hy2-safe logs
  hy2-safe telegram-setup [--token-file FILE --chat-id ID]
  hy2-safe telegram-test
  hy2-safe telegram-logs
  hy2-safe telegram-disable
  hy2-safe uninstall

install/configure 选项：
  --domain DOMAIN            证书/SNI 域名，必须解析到本机
  --email EMAIL              ACME 证书通知邮箱
  --port PORT                使用单 UDP 端口（关闭端口跳跃）
  --port-hopping START-END   使用原生端口跳跃范围，默认 20000-50000
  --hop-min SECONDS          随机跳跃最短间隔，默认 15 秒
  --hop-max SECONDS          随机跳跃最长间隔，默认 45 秒
  --password PASSWORD        16-128 位 base64url 字符；默认安全随机生成
  --password-file FILE       从仅管理员可读的文件读取密码（自动化时推荐）
  --masquerade-url URL       自定义 HTTPS 伪装站点
  --static-masquerade        使用本机静态伪装页（默认）
  --auto-update              开启每周自动更新（默认）
  --no-auto-update           不开启自动更新
  --non-interactive          缺少必需参数时直接失败
  --reinstall                使用已保留的 hy2-safe 配置修复/重装

示例：
  ./hy2-safe.sh install \
    --domain hy2.example.com \
    --email admin@example.com \
    --masquerade-url https://www.example.org/

说明：
  - 当前版本只支持 Debian 12/13。
  - 不会清空现有防火墙链，也不会修改 UFW、firewalld 或云安全组。
  - 端口跳跃会让 Hysteria 原生创建并在停止时清理自己的 nftables/iptables 临时规则。
  - ACME 通常还需要放行 TCP 80/443；Hysteria 数据端口需要放行 UDP。
  - Telegram 提醒默认关闭；启用后只向设置时确认的私人 Chat ID 发消息。
EOF
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请以 root 身份运行（非 root 用户可使用 sudo）。"
}

require_systemd() {
  command -v systemctl >/dev/null 2>&1 || die "未找到 systemctl；本脚本只支持 systemd Linux。"
  [[ -d /run/systemd/system ]] || die "当前环境未运行 systemd。"
}

require_supported_os() {
  local ID=""
  local VERSION_ID=""
  [[ -r /etc/os-release ]] || die "无法读取 /etc/os-release。"
  # shellcheck disable=SC1091
  source /etc/os-release
  [[ "$ID" == "debian" ]] || die "本版本只支持 Debian 12/13。"
  case "$VERSION_ID" in
    12 | 13) ;;
    *) die "检测到 Debian ${VERSION_ID:-未知版本}；本版本只支持 Debian 12/13。" ;;
  esac
}

install_dependencies() {
  local missing=()
  local command_name
  for command_name in curl openssl sha256sum install flock getent python3 stat; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  [[ "${#missing[@]}" -eq 0 ]] && return

  info "安装必要依赖：curl、CA 证书、OpenSSL、coreutils、util-linux、Python 3。"
  command -v apt-get >/dev/null 2>&1 || die "Debian 系统中未找到 apt-get。"
  apt-get -o DPkg::Lock::Timeout=60 update
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y \
    --no-install-recommends ca-certificates curl openssl coreutils util-linux python3

  for command_name in curl openssl sha256sum install flock getent python3 stat; do
    command -v "$command_name" >/dev/null 2>&1 || die "依赖安装后仍未找到：$command_name"
  done
}

ensure_port_hopping_backend() {
  [[ "$PORT_MODE" == "range" ]] || return
  if command -v nft >/dev/null 2>&1 ||
    command -v iptables >/dev/null 2>&1; then
    return
  fi

  info "端口跳跃需要 nftables 或 iptables；正在安装 nftables 命令。"
  command -v apt-get >/dev/null 2>&1 || die "Debian 系统中未找到 apt-get。"
  apt-get -o DPkg::Lock::Timeout=60 update
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y \
    --no-install-recommends nftables

  command -v nft >/dev/null 2>&1 ||
    command -v iptables >/dev/null 2>&1 ||
    die "安装后仍未找到 nftables 或 iptables。"
}

detect_architecture() {
  case "$(uname -m)" in
    x86_64 | amd64) printf 'amd64\n' ;;
    i386 | i486 | i586 | i686) printf '386\n' ;;
    aarch64 | arm64) printf 'arm64\n' ;;
    armv7 | armv7l) printf 'arm\n' ;;
    mipsle | mips64le) printf 'mipsle\n' ;;
    s390x) printf 's390x\n' ;;
    riscv64) printf 'riscv64\n' ;;
    *) die "不支持的 CPU 架构：$(uname -m)" ;;
  esac
}

curl_secure() {
  curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --proto '=https' \
    --proto-redir '=https' \
    --tlsv1.2 \
    --retry 3 \
    --retry-delay 2 \
    --connect-timeout 10 \
    --max-time 180 \
    --max-filesize 134217728 \
    "$@"
}

latest_version() {
  local metadata="$1"
  local version
  curl_secure \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "$API_URL" \
    --output "$metadata"
  version="$(
    python3 - "$metadata" <<'PY'
import json
import re
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    release = json.load(handle)

tag = release.get("tag_name", "")
if release.get("draft") or release.get("prerelease"):
    raise SystemExit("latest release is not stable")
if not re.fullmatch(r"app/v[0-9]+\.[0-9]+\.[0-9]+", tag):
    raise SystemExit("invalid release tag")
print(tag.removeprefix("app/"))
PY
  )" || die "无法从 GitHub 官方 API 解析最新稳定版版本号。"
  printf '%s\n' "$version"
}

release_asset_field() {
  local metadata="$1"
  local asset_name="$2"
  local field="$3"
  python3 - "$metadata" "$asset_name" "$field" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    release = json.load(handle)

matches = [
    asset for asset in release.get("assets", [])
    if asset.get("name") == sys.argv[2] and asset.get("state") == "uploaded"
]
if len(matches) != 1:
    raise SystemExit("release asset is missing or duplicated")
value = matches[0].get(sys.argv[3])
if value is None:
    print("")
elif isinstance(value, (str, int)) and not isinstance(value, bool):
    print(value)
else:
    raise SystemExit("release asset field has an unexpected type")
PY
}

fetch_verified_release() {
  local architecture asset version metadata
  local asset_url hashes_url asset_api_digest hashes_api_digest
  local asset_size hashes_size expected actual hashes_actual
  architecture="$(detect_architecture)"
  asset="hysteria-linux-${architecture}"
  TMP_ROOT="$(mktemp -d /tmp/hy2-safe.XXXXXXXX)"
  metadata="${TMP_ROOT}/release.json"
  version="$(latest_version "$metadata")"
  asset_url="$(release_asset_field "$metadata" "$asset" browser_download_url)" ||
    die "官方 Release 中未找到唯一的 ${asset}。"
  hashes_url="$(release_asset_field "$metadata" hashes.txt browser_download_url)" ||
    die "官方 Release 中未找到唯一的 hashes.txt。"
  asset_api_digest="$(release_asset_field "$metadata" "$asset" digest)" ||
    die "无法读取 ${asset} 的 GitHub Asset 摘要。"
  hashes_api_digest="$(release_asset_field "$metadata" hashes.txt digest)" ||
    die "无法读取 hashes.txt 的 GitHub Asset 摘要。"
  asset_size="$(release_asset_field "$metadata" "$asset" size)" ||
    die "无法读取 ${asset} 的 GitHub Asset 大小。"
  hashes_size="$(release_asset_field "$metadata" hashes.txt size)" ||
    die "无法读取 hashes.txt 的 GitHub Asset 大小。"

  [[ "$asset_url" == "${RELEASE_URL}/app/${version}/${asset}" ]] ||
    die "官方 API 返回了异常的二进制下载地址，拒绝继续。"
  [[ "$hashes_url" == "${RELEASE_URL}/app/${version}/hashes.txt" ]] ||
    die "官方 API 返回了异常的校验文件下载地址，拒绝继续。"
  [[ "$asset_size" =~ ^[1-9][0-9]{0,8}$ && "$asset_size" -le 134217728 ]] ||
    die "官方 API 返回了异常的二进制大小，拒绝继续。"
  [[ "$hashes_size" =~ ^[1-9][0-9]{0,6}$ && "$hashes_size" -le 1048576 ]] ||
    die "官方 API 返回了异常的 hashes.txt 大小，拒绝继续。"

  info "下载 Hysteria ${version}（${architecture}）官方发布文件。"
  curl_secure --max-filesize 1048576 "$hashes_url" --output "${TMP_ROOT}/hashes.txt"
  curl_secure "$asset_url" --output "${TMP_ROOT}/${asset}"

  [[ "$(stat -c '%s' -- "${TMP_ROOT}/${asset}")" == "$asset_size" ]] ||
    die "二进制文件大小与 GitHub Asset 元数据不一致，拒绝安装。"
  [[ "$(stat -c '%s' -- "${TMP_ROOT}/hashes.txt")" == "$hashes_size" ]] ||
    die "hashes.txt 大小与 GitHub Asset 元数据不一致，拒绝安装。"
  actual="$(sha256sum "${TMP_ROOT}/${asset}" | awk '{print $1}')"
  hashes_actual="$(sha256sum "${TMP_ROOT}/hashes.txt" | awk '{print $1}')"
  [[ "$asset_api_digest" =~ ^sha256:([0-9a-fA-F]{64})$ ]] ||
    die "GitHub API 未提供有效的二进制 Asset 摘要，拒绝安装。"
  [[ "${actual,,}" == "${BASH_REMATCH[1],,}" ]] ||
    die "GitHub Asset SHA-256 校验失败，拒绝安装。"
  [[ "$hashes_api_digest" =~ ^sha256:([0-9a-fA-F]{64})$ ]] ||
    die "GitHub API 未提供有效的 hashes.txt Asset 摘要，拒绝安装。"
  [[ "${hashes_actual,,}" == "${BASH_REMATCH[1],,}" ]] ||
    die "GitHub Asset hashes.txt 摘要校验失败，拒绝安装。"

  expected="$(
    awk -v filename="$asset" '
      {
        candidate = $2
        sub(/^\*/, "", candidate)
        sub(/^.*\//, "", candidate)
        if (candidate == filename) {
          print $1
          exit
        }
      }
    ' "${TMP_ROOT}/hashes.txt"
  )"
  [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] ||
    die "官方 hashes.txt 中未找到 ${asset} 的有效 SHA-256。"

  [[ "${actual,,}" == "${expected,,}" ]] ||
    die "SHA-256 校验失败，拒绝安装。期望 ${expected}，实际 ${actual}。"

  chmod 0755 "${TMP_ROOT}/${asset}"

  FETCHED_VERSION="$version"
  FETCHED_BINARY="${TMP_ROOT}/${asset}"
}

installed_version() {
  if [[ -x "$BIN_PATH" ]]; then
    "$BIN_PATH" version 2>/dev/null |
      sed -n 's/.*Version:[[:space:]]*\(v[^[:space:]]*\).*/\1/p' |
      head -n 1
  else
    return 1
  fi
}

compare_versions() {
  python3 - "$1" "$2" <<'PY'
import re
import sys

def parse(value):
    match = re.fullmatch(r"v([0-9]+)\.([0-9]+)\.([0-9]+)", value)
    if not match:
        raise SystemExit("invalid semantic version")
    return tuple(int(part) for part in match.groups())

left = parse(sys.argv[1])
right = parse(sys.argv[2])
print((left > right) - (left < right))
PY
}

wait_for_service() {
  local _
  for _ in 1 2 3 4 5; do
    sleep 1
    systemctl is-active --quiet "$SERVICE_NAME" || return 1
  done
  return 0
}

wait_for_unit() {
  local unit="$1"
  local _
  for _ in 1 2 3 4 5; do
    sleep 1
    systemctl is-active --quiet "$unit" || return 1
  done
  return 0
}

install_fetched_binary() {
  local restart_service="${1:-0}"
  local had_previous=0
  local current relation
  current="$(installed_version || true)"

  if [[ -n "$current" ]]; then
    relation="$(compare_versions "$current" "$FETCHED_VERSION")" ||
      die "无法安全比较已安装版本 ${current} 与目标版本 ${FETCHED_VERSION}。"
    if [[ "$relation" -eq 0 ]]; then
      info "当前已是最新版 ${current}。"
      return
    fi
    if [[ "$relation" -gt 0 ]]; then
      warn "已安装版本 ${current} 高于官方 latest ${FETCHED_VERSION}，拒绝自动降级。"
      return
    fi
  fi

  if [[ -e "$BIN_PATH" ]]; then
    cp --preserve=mode,ownership,timestamps -- "$BIN_PATH" "$PREVIOUS_BIN_PATH"
    had_previous=1
  fi

  install -m 0755 -o root -g root "$FETCHED_BINARY" "${BIN_PATH}.new"
  mv -f -- "${BIN_PATH}.new" "$BIN_PATH"

  if [[ "$restart_service" -eq 1 ]] && systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    if systemctl restart "$SERVICE_NAME" && wait_for_service; then
      info "已更新至 ${FETCHED_VERSION}，服务运行正常。"
      return
    fi

    if [[ "$had_previous" -eq 1 ]]; then
      warn "新版本启动失败，正在自动回滚。"
      install -m 0755 -o root -g root "$PREVIOUS_BIN_PATH" "$BIN_PATH"
      systemctl restart "$SERVICE_NAME" || true
      wait_for_service || warn "回滚后服务仍未恢复，请检查日志。"
    fi
    journalctl --no-pager -n 30 -u "$SERVICE_NAME" >&2 || true
    die "更新失败，已尝试回滚。"
  fi

  info "已安装 Hysteria ${FETCHED_VERSION}。"
}

validate_domain() {
  local domain="$1"
  local label
  local labels=()
  [[ "${#domain}" -le 253 ]] || return 1
  [[ "$domain" == *.* ]] || return 1
  [[ "$domain" =~ ^[a-z0-9.-]+$ ]] || return 1
  [[ "$domain" != .* && "$domain" != *. && "$domain" != *..* ]] || return 1
  IFS='.' read -r -a labels <<<"$domain"
  for label in "${labels[@]}"; do
    [[ -n "$label" && "${#label}" -le 63 ]] || return 1
    [[ "$label" != -* && "$label" != *- ]] || return 1
  done
}

validate_email() {
  local email="$1"
  [[ "${#email}" -le 254 ]] || return 1
  [[ "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]]
}

validate_port() {
  local port="$1"
  [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || return 1
  ((port >= 1 && port <= 65535))
}

validate_hop_interval() {
  local seconds="$1"
  [[ "$seconds" =~ ^[1-9][0-9]{0,3}$ ]] || return 1
  ((seconds >= 5 && seconds <= 3600))
}

validate_password() {
  local password="$1"
  (("${#password}" >= 16 && "${#password}" <= 128)) || return 1
  [[ "$password" =~ ^[A-Za-z0-9_-]+$ ]]
}

validate_root_secret_file() {
  local file="$1"
  local description="$2"
  local owner permissions
  [[ -f "$file" && ! -L "$file" && -r "$file" ]] ||
    die "${description}必须是可读的普通文件且不能是符号链接：$file"
  owner="$(stat -c '%u' -- "$file")"
  permissions="$(stat -c '%a' -- "$file")"
  [[ "$owner" == "0" ]] || die "${description}必须由 root 拥有：$file"
  [[ "$permissions" =~ ^[0-7]{3,4}$ ]] ||
    die "无法判断${description}权限：$file"
  (( (8#$permissions & 0077) == 0 )) ||
    die "${description}不能向组或其他用户开放；请执行 chmod 600：$file"
}

validate_password_file() {
  validate_root_secret_file "$1" "密码文件"
}

validate_telegram_token() {
  local token="$1"
  (("${#token}" >= 20 && "${#token}" <= 200)) || return 1
  [[ "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]]
}

validate_telegram_chat_id() {
  local chat_id="$1"
  [[ "$chat_id" =~ ^[1-9][0-9]{4,19}$ ]]
}

find_free_stats_port() {
  python3 - <<'PY'
import socket

for port in range(19090, 19200):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        sock.close()
        continue
    sock.close()
    print(port)
    raise SystemExit(0)
raise SystemExit(1)
PY
}

validate_masquerade_url() {
  local url="$1"
  local authority host port
  [[ "${#url}" -le 2048 ]] || return 1
  [[ "$url" == https://* ]] || return 1
  case "$url" in
    *" "* | *$'\t'* | *$'\r'* | *$'\n'* | *"'"* | *'"'* | *\\*) return 1 ;;
  esac
  [[ "$url" =~ ^https://[A-Za-z0-9] ]] || return 1
  authority="${url#https://}"
  authority="${authority%%/*}"
  [[ "$authority" != *"@"* ]] || return 1
  host="${authority%%:*}"
  validate_domain "${host,,}" || return 1
  if [[ "$authority" == *:* ]]; then
    port="${authority##*:}"
    validate_port "$port" || return 1
  fi
}

masquerade_host() {
  local value="${1#https://}"
  value="${value%%/*}"
  value="${value%%:*}"
  printf '%s\n' "${value,,}"
}

validate_public_masquerade_target() {
  local host="$1"
  local address
  local addresses=()
  while read -r address _; do
    [[ -n "$address" ]] && addresses+=("$address")
  done < <(getent ahosts "$host" | awk '!seen[$1]++ { print $1 }')
  (("${#addresses[@]}"…9737 tokens truncated…TIFIER_NAME" >/dev/null 2>&1 || true
  fi
}

parse_config_options() {
  NON_INTERACTIVE=0
  PORT_MODE_WAS_SET=0
  PORT_VALUE_WAS_SET=0
  MASQUERADE_WAS_SET=0
  AUTO_UPDATE_WAS_SET=0

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --domain)
        [[ "$#" -ge 2 ]] || die "--domain 缺少参数。"
        DOMAIN="$2"
        shift 2
        ;;
      --email)
        [[ "$#" -ge 2 ]] || die "--email 缺少参数。"
        EMAIL="$2"
        shift 2
        ;;
      --port)
        [[ "$#" -ge 2 ]] || die "--port 缺少参数。"
        PORT_MODE="single"
        PORT="$2"
        PORT_MODE_WAS_SET=1
        PORT_VALUE_WAS_SET=1
        shift 2
        ;;
      --port-hopping)
        [[ "$#" -ge 2 ]] || die "--port-hopping 缺少参数。"
        PORT_MODE="range"
        HOP_START="${2%-*}"
        HOP_END="${2#*-}"
        PORT_MODE_WAS_SET=1
        PORT_VALUE_WAS_SET=1
        shift 2
        ;;
      --hop-min)
        [[ "$#" -ge 2 ]] || die "--hop-min 缺少参数。"
        HOP_MIN_INTERVAL="$2"
        shift 2
        ;;
      --hop-max)
        [[ "$#" -ge 2 ]] || die "--hop-max 缺少参数。"
        HOP_MAX_INTERVAL="$2"
        shift 2
        ;;
      --password)
        [[ "$#" -ge 2 ]] || die "--password 缺少参数。"
        warn "--password 可能出现在 shell 历史和进程列表中；自动化请优先使用 --password-file。"
        PASSWORD="$2"
        shift 2
        ;;
      --password-file)
        [[ "$#" -ge 2 ]] || die "--password-file 缺少参数。"
        validate_password_file "$2"
        PASSWORD="$(head -n 1 -- "$2")"
        shift 2
        ;;
      --masquerade-url)
        [[ "$#" -ge 2 ]] || die "--masquerade-url 缺少参数。"
        MASQUERADE_MODE="proxy"
        MASQUERADE_URL="$2"
        MASQUERADE_WAS_SET=1
        shift 2
        ;;
      --static-masquerade)
        MASQUERADE_MODE="static"
        MASQUERADE_URL=""
        MASQUERADE_WAS_SET=1
        shift
        ;;
      --auto-update)
        AUTO_UPDATE=1
        AUTO_UPDATE_WAS_SET=1
        shift
        ;;
      --no-auto-update)
        AUTO_UPDATE=0
        AUTO_UPDATE_WAS_SET=1
        shift
        ;;
      --non-interactive)
        NON_INTERACTIVE=1
        shift
        ;;
      --reinstall)
        REINSTALL=1
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "未知选项：$1" ;;
    esac
  done
}

show_client() {
  local server_address official_share compatible_share share_output transport_config firewall_ports
  require_root
  load_existing_settings || die "未找到由 hy2-safe 管理的配置。"
  if [[ "$PORT_MODE" == "range" ]]; then
    server_address="${DOMAIN}:${HOP_START}-${HOP_END}"
    official_share="hysteria2://${PASSWORD}@${DOMAIN}:${HOP_START}-${HOP_END}/?sni=${DOMAIN}&insecure=0#hy2-${DOMAIN}"
    compatible_share="hysteria2://${PASSWORD}@${DOMAIN}:${HOP_START}/?sni=${DOMAIN}&insecure=0&mport=${HOP_START}-${HOP_END}#hy2-${DOMAIN}"
    share_output="$(cat <<EOF
Hysteria 2 官方分享链接：
${official_share}

v2rayN / v2rayNG 兼容分享链接：
${compatible_share}
EOF
)"
    firewall_ports="${HOP_START}-${HOP_END}"
    transport_config="$(cat <<EOF
transport:
  type: udp
  udp:
    minHopInterval: ${HOP_MIN_INTERVAL}s
    maxHopInterval: ${HOP_MAX_INTERVAL}s
EOF
)"
  else
    server_address="${DOMAIN}:${PORT}"
    official_share="hysteria2://${PASSWORD}@${DOMAIN}:${PORT}/?sni=${DOMAIN}&insecure=0#hy2-${DOMAIN}"
    share_output="$(cat <<EOF
通用分享链接（官方客户端、v2rayN、v2rayNG）：
${official_share}
EOF
)"
    firewall_ports="$PORT"
    transport_config=""
  fi
  cat <<EOF
Hysteria 2 官方客户端完整 YAML（本机 SOCKS5：127.0.0.1:1080）：

server: "${server_address}"
auth: ${PASSWORD}
tls:
  sni: ${DOMAIN}
fastOpen: true
${transport_config}
socks5:
  listen: 127.0.0.1:1080

${share_output}

需要放行的 UDP 端口：${firewall_ports}
EOF
}

command_install() {
  local install_arg
  require_root
  require_systemd
  require_supported_os
  REINSTALL=0
  for install_arg in "$@"; do
    [[ "$install_arg" == "--reinstall" ]] && REINSTALL=1
  done
  if [[ -f "$SETTINGS_PATH" ]]; then
    [[ "$REINSTALL" -eq 1 ]] ||
      die "检测到已有或已卸载但保留配置的 hy2-safe 实例。请使用 configure、update 或 install --reinstall。"
  elif [[ -e "$BIN_PATH" || -e "$CONFIG_PATH" || -e "$SERVICE_PATH" ]]; then
    die "检测到非 hy2-safe 管理的 Hysteria 文件，拒绝覆盖。请先备份并迁移或卸载旧实例。"
  elif [[ "$REINSTALL" -eq 1 ]]; then
    die "没有找到可供重装的 hy2-safe 配置。"
  fi
  install_dependencies

  if [[ "$REINSTALL" -eq 1 ]]; then
    load_existing_settings || die "无法读取保留的 hy2-safe 配置。"
  else
    DOMAIN=""
    EMAIL=""
    PORT="443"
    PORT_MODE="range"
    HOP_START="20000"
    HOP_END="50000"
    HOP_MIN_INTERVAL="15"
    HOP_MAX_INTERVAL="45"
    PASSWORD=""
    MASQUERADE_MODE="static"
    MASQUERADE_URL=""
    AUTO_UPDATE=1
    TELEGRAM_ENABLED=0
    TELEGRAM_CHAT_ID=""
    TELEGRAM_STATS_PORT=""
    TELEGRAM_STATS_SECRET=""
  fi
  parse_config_options "$@"
  prompt_install_values "$NON_INTERACTIVE"
  validate_install_values
  ensure_port_hopping_backend
  if ! getent ahosts "$DOMAIN" >/dev/null 2>&1; then
    warn "当前未能解析 ${DOMAIN}。ACME 只有在域名正确解析到本 VPS 后才能签发证书。"
  fi

  exec 9>"$LOCK_PATH"
  flock -n 9 || die "另一个 hy2-safe 任务正在运行。"

  ensure_service_user_and_directories
  install_manager_copy
  fetch_verified_release
  install_fetched_binary 0
  write_config
  save_settings
  write_systemd_units
  configure_update_timer

  systemctl enable "$SERVICE_NAME"
  if ! systemctl restart "$SERVICE_NAME" || ! wait_for_service; then
    journalctl --no-pager -n 40 -u "$SERVICE_NAME" >&2 || true
    die "Hysteria 服务启动失败。最常见原因是域名未正确解析、TCP 80/443 未放行或端口冲突。"
  fi
  if [[ "$TELEGRAM_ENABLED" -eq 1 ]]; then
    configure_notifier_service ||
      warn "Hysteria 正常运行，但 Telegram 提醒服务启动失败；请运行 hy2-safe telegram-logs。"
  fi

  info "安装完成，服务已作为非特权用户 hysteria 运行。"
  printf '\n'
  show_client
  if [[ "$PORT_MODE" == "range" ]]; then
    printf '\n请确认防火墙/安全组已放行：UDP %s-%s，以及 ACME 所需的 TCP 80/443。\n' \
      "$HOP_START" "$HOP_END"
  else
    printf '\n请确认防火墙/安全组已放行：UDP %s，以及 ACME 所需的 TCP 80/443。\n' "$PORT"
  fi
}

command_configure() {
  local old_auto_update
  require_root
  require_systemd
  load_existing_settings || die "请先执行 install。"
  old_auto_update="$AUTO_UPDATE"
  parse_config_options "$@"
  prompt_install_values "$NON_INTERACTIVE"
  validate_install_values
  ensure_port_hopping_backend

  exec 9>"$LOCK_PATH"
  flock -n 9 || die "另一个 hy2-safe 任务正在运行。"

  TMP_ROOT="$(mktemp -d /tmp/hy2-safe.XXXXXXXX)"
  cp --preserve=mode,ownership,timestamps -- "$CONFIG_PATH" "${TMP_ROOT}/config.yaml"
  cp --preserve=mode,ownership,timestamps -- "$SETTINGS_PATH" "${TMP_ROOT}/hy2-safe.env"
  cp --preserve=mode,ownership,timestamps -- "$SERVICE_PATH" "${TMP_ROOT}/hysteria-server.service"
  install_manager_copy
  write_config
  save_settings
  write_systemd_units
  configure_update_timer
  if ! systemctl restart "$SERVICE_NAME" || ! wait_for_service; then
    warn "新配置启动失败，正在恢复上一份配置。"
    cp --preserve=mode,ownership,timestamps -- "${TMP_ROOT}/config.yaml" "$CONFIG_PATH"
    cp --preserve=mode,ownership,timestamps -- "${TMP_ROOT}/hy2-safe.env" "$SETTINGS_PATH"
    cp --preserve=mode,ownership,timestamps -- \
      "${TMP_ROOT}/hysteria-server.service" "$SERVICE_PATH"
    systemctl daemon-reload
    AUTO_UPDATE="$old_auto_update"
    configure_update_timer
    systemctl restart "$SERVICE_NAME" || true
    wait_for_service || warn "恢复配置后服务仍未启动，请检查日志。"
    journalctl --no-pager -n 40 -u "$SERVICE_NAME" >&2 || true
    die "新配置启动失败，已恢复上一份配置。"
  fi
  configure_notifier_service ||
    warn "Hysteria 配置成功，但 Telegram 提醒服务未能启动；请运行 hy2-safe telegram-logs。"
  info "配置已更新。"
  show_client
}

restore_telegram_change() {
  local backup_dir="$1"
  local old_enabled="$2"
  cp --preserve=mode,ownership,timestamps -- "${backup_dir}/config.yaml" "$CONFIG_PATH"
  cp --preserve=mode,ownership,timestamps -- "${backup_dir}/hy2-safe.env" "$SETTINGS_PATH"
  if [[ -f "${backup_dir}/telegram-notifier.json" ]]; then
    cp --preserve=mode,ownership,timestamps -- \
      "${backup_dir}/telegram-notifier.json" "$NOTIFIER_CONFIG_PATH"
  else
    rm -f -- "$NOTIFIER_CONFIG_PATH"
  fi
  systemctl daemon-reload
  systemctl restart "$SERVICE_NAME" || true
  wait_for_service || warn "恢复 Telegram 变更后 Hysteria 仍未启动，请检查日志。"
  TELEGRAM_ENABLED="$old_enabled"
  configure_notifier_service >/dev/null 2>&1 || true
}

command_telegram_setup() {
  local token_input_file=""
  local requested_chat_id=""
  local token_file candidates_file old_enabled
  require_root
  require_systemd
  install_dependencies
  load_existing_settings || die "请先安装 Hy2，再运行 telegram-setup。"

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --token-file)
        [[ "$#" -ge 2 ]] || die "--token-file 缺少参数。"
        token_input_file="$2"
        shift 2
        ;;
      --chat-id)
        [[ "$#" -ge 2 ]] || die "--chat-id 缺少参数。"
        requested_chat_id="$2"
        shift 2
        ;;
      -h | --help)
        printf '用法：hy2-safe telegram-setup [--token-file FILE --chat-id ID]\n'
        return
        ;;
      *) die "telegram-setup 的未知选项：$1" ;;
    esac
  done

  [[ -z "$requested_chat_id" ]] ||
    validate_telegram_chat_id "$requested_chat_id" ||
    die "Chat ID 必须是私人聊天的正整数。"
  if [[ -n "$token_input_file" ]]; then
    validate_root_secret_file "$token_input_file" "Bot Token 文件"
  fi

  exec 9>"$LOCK_PATH"
  flock -n 9 || die "另一个 hy2-safe 任务正在运行。"
  TMP_ROOT="$(mktemp -d /tmp/hy2-safe.XXXXXXXX)"
  token_file="${TMP_ROOT}/telegram-token"
  candidates_file="${TMP_ROOT}/telegram-candidates.json"

  if [[ -n "$token_input_file" ]]; then
    head -n 1 -- "$token_input_file" | tr -d '\r\n' >"$token_file"
  else
    printf '请先通过 Telegram 的 @BotFather 创建机器人，并给机器人发送一条消息。\n'
    read -r -s -p "请输入 Bot Token（输入时不会显示）: " TELEGRAM_BOT_TOKEN
    printf '\n'
    printf '%s' "$TELEGRAM_BOT_TOKEN" >"$token_file"
    unset TELEGRAM_BOT_TOKEN
  fi
  chmod 0600 "$token_file"
  validate_telegram_token "$(cat "$token_file")" ||
    die "Bot Token 格式无效。"

  if [[ -z "$requested_chat_id" ]]; then
    read -r -p "确认已经给机器人发送消息后，按回车继续。"
    discover_telegram_chats "$token_file" "$candidates_file"
    read -r -p "请输入上面属于你自己的私人 Chat ID: " requested_chat_id
    validate_telegram_chat_id "$requested_chat_id" ||
      die "Chat ID 必须是私人聊天的正整数。"
    validate_discovered_chat "$candidates_file" "$requested_chat_id" ||
      die "该 Chat ID 不在刚才发现的私人聊天中，拒绝设置。"
  fi

  info "发送 Telegram 测试消息。"
  telegram_send_test "$token_file" "$requested_chat_id"

  old_enabled="$TELEGRAM_ENABLED"
  cp --preserve=mode,ownership,timestamps -- "$CONFIG_PATH" "${TMP_ROOT}/config.yaml"
  cp --preserve=mode,ownership,timestamps -- "$SETTINGS_PATH" "${TMP_ROOT}/hy2-safe.env"
  if [[ -f "$NOTIFIER_CONFIG_PATH" ]]; then
    cp --preserve=mode,ownership,timestamps -- \
      "$NOTIFIER_CONFIG_PATH" "${TMP_ROOT}/telegram-notifier.json"
  fi

  TELEGRAM_ENABLED=1
  TELEGRAM_CHAT_ID="$requested_chat_id"
  if [[ -z "$TELEGRAM_STATS_PORT" ]]; then
    TELEGRAM_STATS_PORT="$(find_free_stats_port)" ||
      die "无法找到可用的本机统计端口。"
  fi
  [[ -n "$TELEGRAM_STATS_SECRET" ]] ||
    TELEGRAM_STATS_SECRET="$(random_password)"
  validate_install_values

  if ! write_config ||
    ! save_settings ||
    ! write_telegram_config "$token_file" ||
    ! write_systemd_units; then
    warn "写入 Telegram 提醒配置失败，正在回滚。"
    restore_telegram_change "$TMP_ROOT" "$old_enabled"
    die "Telegram 提醒启用失败，已恢复原配置。"
  fi
  if ! systemctl restart "$SERVICE_NAME" || ! wait_for_service; then
    warn "启用 Telegram 统计接口后 Hysteria 启动失败，正在回滚。"
    restore_telegram_change "$TMP_ROOT" "$old_enabled"
    journalctl --no-pager -n 40 -u "$SERVICE_NAME" >&2 || true
    die "Telegram 提醒启用失败，已恢复原配置。"
  fi
  if ! configure_notifier_service; then
    warn "Telegram 提醒服务启动失败，正在回滚。"
    journalctl --no-pager -n 40 -u "$NOTIFIER_NAME" >&2 || true
    restore_telegram_change "$TMP_ROOT" "$old_enabled"
    die "Telegram 提醒启用失败，已恢复原配置。"
  fi

  info "Telegram 连接提醒已启用，只会向 Chat ID ${TELEGRAM_CHAT_ID} 主动发送消息。"
  printf '规则：新 IP 网段立即提醒；相同网段一小时内合并；每天发送一份汇总。\n'
}

command_telegram_test() {
  require_root
  load_existing_settings || die "请先安装 Hy2。"
  [[ "$TELEGRAM_ENABLED" -eq 1 && -f "$NOTIFIER_CONFIG_PATH" ]] ||
    die "Telegram 提醒尚未启用。"
  stored_telegram_send_test
  info "Telegram 测试消息发送成功。"
}

command_telegram_logs() {
  require_root
  journalctl --no-pager -e -u "$NOTIFIER_NAME"
}

command_telegram_disable() {
  local old_enabled
  require_root
  require_systemd
  load_existing_settings || die "请先安装 Hy2。"
  if [[ "$TELEGRAM_ENABLED" -eq 0 ]]; then
    info "Telegram 提醒已经处于关闭状态。"
    return
  fi

  exec 9>"$LOCK_PATH"
  flock -n 9 || die "另一个 hy2-safe 任务正在运行。"
  TMP_ROOT="$(mktemp -d /tmp/hy2-safe.XXXXXXXX)"
  old_enabled="$TELEGRAM_ENABLED"
  cp --preserve=mode,ownership,timestamps -- "$CONFIG_PATH" "${TMP_ROOT}/config.yaml"
  cp --preserve=mode,ownership,timestamps -- "$SETTINGS_PATH" "${TMP_ROOT}/hy2-safe.env"
  if [[ -f "$NOTIFIER_CONFIG_PATH" ]]; then
    cp --preserve=mode,ownership,timestamps -- \
      "$NOTIFIER_CONFIG_PATH" "${TMP_ROOT}/telegram-notifier.json"
  fi

  TELEGRAM_ENABLED=0
  TELEGRAM_CHAT_ID=""
  TELEGRAM_STATS_PORT=""
  TELEGRAM_STATS_SECRET=""
  if ! write_config || ! save_settings; then
    warn "写入关闭配置失败，正在回滚。"
    restore_telegram_change "$TMP_ROOT" "$old_enabled"
    die "Telegram 提醒关闭失败，已恢复原配置。"
  fi
  if ! systemctl restart "$SERVICE_NAME" || ! wait_for_service; then
    warn "关闭 Telegram 统计接口后 Hysteria 启动失败，正在回滚。"
    restore_telegram_change "$TMP_ROOT" "$old_enabled"
    die "Telegram 提醒关闭失败，已恢复原配置。"
  fi
  configure_notifier_service
  rm -f -- "$NOTIFIER_CONFIG_PATH"
  info "Telegram 提醒已关闭，Bot Token 已从服务器配置中删除。"
}

command_update() {
  require_root
  require_systemd
  [[ -f "$SETTINGS_PATH" ]] || die "未检测到 hy2-safe 管理的安装，拒绝更新未知实例。"
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --quiet)
        QUIET=1
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "update 的未知选项：$1" ;;
    esac
  done

  exec 9>"$LOCK_PATH"
  flock -n 9 || die "另一个 hy2-safe 任务正在运行。"
  fetch_verified_release
  install_fetched_binary 1
}

command_status() {
  require_root
  load_existing_settings || true
  systemctl --no-pager --full status "$SERVICE_NAME" || true
  printf '\n已安装版本：%s\n' "$(installed_version || printf '未安装')"
  if systemctl is-enabled --quiet "$TIMER_NAME" 2>/dev/null; then
    printf '自动更新：已开启\n'
    systemctl list-timers --no-pager "$TIMER_NAME" || true
  else
    printf '自动更新：未开启\n'
  fi
  if [[ "${TELEGRAM_ENABLED:-0}" -eq 1 ]]; then
    if systemctl is-active --quiet "$NOTIFIER_NAME" 2>/dev/null; then
      printf 'Telegram 提醒：已开启并正在运行\n'
    else
      printf 'Telegram 提醒：已配置但服务异常\n'
    fi
  else
    printf 'Telegram 提醒：未开启\n'
  fi
}

command_logs() {
  require_root
  journalctl --no-pager -e -u "$SERVICE_NAME"
}

command_uninstall() {
  require_root
  require_systemd
  [[ -f "$SETTINGS_PATH" ]] || die "未检测到 hy2-safe 管理的安装，拒绝删除未知实例。"
  exec 9>"$LOCK_PATH"
  flock -n 9 || die "另一个 hy2-safe 任务正在运行。"

  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
  systemctl disable --now "$NOTIFIER_NAME" >/dev/null 2>&1 || true
  rm -f -- \
    "$SERVICE_PATH" \
    "$UPDATE_SERVICE_PATH" \
    "$UPDATE_TIMER_PATH" \
    "$NOTIFIER_SERVICE_PATH" \
    "$BIN_PATH" \
    "$PREVIOUS_BIN_PATH" \
    "$NOTIFIER_PATH" \
    "$MANAGER_PATH"
  systemctl daemon-reload
  systemctl reset-failed \
    "$SERVICE_NAME" \
    hy2-safe-update.service \
    "$NOTIFIER_NAME" >/dev/null 2>&1 || true

  info "程序和 systemd 单元已卸载。"
  printf '出于防误删考虑，配置、证书和 Telegram 提醒状态仍保留在：\n  %s\n  %s\n  %s\n' \
    "$CONFIG_DIR" "$STATE_DIR" "$NOTIFIER_STATE_DIR"
}

main() {
  local command="${1:-help}"
  if [[ "$#" -gt 0 ]]; then
    shift
  fi
  case "$command" in
    install) command_install "$@" ;;
    configure) command_configure "$@" ;;
    update) command_update "$@" ;;
    show-client) show_client "$@" ;;
    status) command_status "$@" ;;
    logs) command_logs "$@" ;;
    telegram-setup) command_telegram_setup "$@" ;;
    telegram-test) command_telegram_test "$@" ;;
    telegram-logs) command_telegram_logs "$@" ;;
    telegram-disable) command_telegram_disable "$@" ;;
    uninstall) command_uninstall "$@" ;;
    help | -h | --help) usage ;;
    *) die "未知命令：$command。请运行 $PROGRAM help。" ;;
  esac
}

main "$@"
