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
readonly SERVICE_NAME="hysteria-server.service"
readonly TIMER_NAME="hy2-safe-update.timer"
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
  sudo ./hy2-safe.sh install [选项]
  sudo hy2-safe configure [选项]
  sudo hy2-safe update [--quiet]
  sudo hy2-safe show-client
  sudo hy2-safe status
  sudo hy2-safe logs
  sudo hy2-safe uninstall

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
  sudo ./hy2-safe.sh install \
    --domain hy2.example.com \
    --email admin@example.com \
    --masquerade-url https://www.example.org/

说明：
  - 当前版本只支持 Debian 12/13。
  - 不会清空现有防火墙链，也不会修改 UFW、firewalld 或云安全组。
  - 端口跳跃会让 Hysteria 原生创建并在停止时清理自己的 nftables/iptables 临时规则。
  - ACME 通常还需要放行 TCP 80/443；Hysteria 数据端口需要放行 UDP。
EOF
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请使用 root 或 sudo 运行。"
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

validate_password_file() {
  local file="$1"
  local owner permissions
  [[ -f "$file" && ! -L "$file" && -r "$file" ]] ||
    die "密码文件必须是可读的普通文件且不能是符号链接：$file"
  owner="$(stat -c '%u' -- "$file")"
  permissions="$(stat -c '%a' -- "$file")"
  [[ "$owner" == "0" ]] || die "密码文件必须由 root 拥有：$file"
  [[ "$permissions" =~ ^[0-7]{3,4}$ ]] ||
    die "无法判断密码文件权限：$file"
  (( (8#$permissions & 0077) == 0 )) ||
    die "密码文件不能向组或其他用户开放；请执行 chmod 600：$file"
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
  (("${#addresses[@]}" > 0)) ||
    die "伪装站点当前无法解析：$host"
  if ! python3 - "${addresses[@]}" <<'PY'
import ipaddress
import sys

for value in sys.argv[1:]:
    address = ipaddress.ip_address(value.split("%", 1)[0])
    if not address.is_global:
        raise SystemExit(1)
PY
  then
    die "伪装站点解析到了私网、环回或保留地址，拒绝配置反代：$host"
  fi
}

random_password() {
  openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n'
}

prompt_install_values() {
  local non_interactive="$1"
  local answer=""

  if [[ -z "$DOMAIN" && "$non_interactive" -eq 0 ]]; then
    read -r -p "证书/SNI 域名（需解析到本 VPS）: " DOMAIN
  fi
  DOMAIN="${DOMAIN,,}"

  if [[ -z "$EMAIL" && "$non_interactive" -eq 0 ]]; then
    read -r -p "ACME 通知邮箱: " EMAIL
  fi

  if [[ "$PORT_MODE_WAS_SET" -eq 0 && "$non_interactive" -eq 0 ]]; then
    if [[ "$PORT_MODE" == "range" ]]; then
      read -r -p "开启原生端口跳跃？[Y/n]: " answer
    else
      read -r -p "开启原生端口跳跃？[y/N]: " answer
    fi
    case "${answer,,}" in
      y | yes) PORT_MODE="range" ;;
      n | no) PORT_MODE="single" ;;
      *) : ;;
    esac
  fi

  if [[ "$PORT_VALUE_WAS_SET" -eq 0 && "$non_interactive" -eq 0 ]]; then
    if [[ "$PORT_MODE" == "range" ]]; then
      read -r -p "UDP 跳跃端口…96 tokens truncated…0 ]]; then
    read -r -p "自定义 HTTPS 伪装站点（留空保留当前模式）: " answer
    if [[ -n "$answer" ]]; then
      MASQUERADE_MODE="proxy"
      MASQUERADE_URL="$answer"
    fi
  fi

  if [[ "$AUTO_UPDATE_WAS_SET" -eq 0 && "$non_interactive" -eq 0 ]]; then
    if [[ "$AUTO_UPDATE" -eq 1 ]]; then
      read -r -p "开启每周自动更新并在失败时回滚？[Y/n]: " answer
    else
      read -r -p "开启每周自动更新并在失败时回滚？[y/N]: " answer
    fi
    case "${answer,,}" in
      y | yes) AUTO_UPDATE=1 ;;
      n | no) AUTO_UPDATE=0 ;;
      *) : ;;
    esac
  fi

  [[ -n "$PASSWORD" ]] || PASSWORD="$(random_password)"
}

validate_install_values() {
  [[ -n "$DOMAIN" ]] || die "缺少 --domain。"
  validate_domain "$DOMAIN" || die "域名格式无效：$DOMAIN"
  [[ -n "$EMAIL" ]] || die "缺少 --email。"
  validate_email "$EMAIL" || die "邮箱格式无效：$EMAIL"
  case "$PORT_MODE" in
    single)
      validate_port "$PORT" || die "端口必须在 1-65535 之间。"
      ;;
    range)
      validate_port "$HOP_START" || die "跳跃起始端口必须在 1-65535 之间。"
      validate_port "$HOP_END" || die "跳跃结束端口必须在 1-65535 之间。"
      ((HOP_START < HOP_END)) || die "跳跃起始端口必须小于结束端口。"
      validate_hop_interval "$HOP_MIN_INTERVAL" ||
        die "最短跳跃间隔必须为 5-3600 秒。"
      validate_hop_interval "$HOP_MAX_INTERVAL" ||
        die "最长跳跃间隔必须为 5-3600 秒。"
      ((HOP_MIN_INTERVAL <= HOP_MAX_INTERVAL)) ||
        die "最短跳跃间隔不能大于最长跳跃间隔。"
      ;;
    *) die "未知端口模式：$PORT_MODE" ;;
  esac
  validate_password "$PASSWORD" ||
    die "密码必须是 16-128 位，且只能包含字母、数字、下划线和连字符。"

  if [[ "$MASQUERADE_MODE" == "proxy" ]]; then
    validate_masquerade_url "$MASQUERADE_URL" ||
      die "伪装站点必须是无空格、无引号的有效 https:// URL。"
    [[ "$(masquerade_host "$MASQUERADE_URL")" != "$DOMAIN" ]] ||
      die "伪装站点不能与 Hysteria 域名相同，否则可能形成反向代理循环。"
    validate_public_masquerade_target "$(masquerade_host "$MASQUERADE_URL")"
    warn "反代伪装允许未认证访客触发上游 HTTPS 请求，可能消耗 VPS 流量；不需要真实站点时优先使用默认静态响应。"
  fi
}

load_existing_settings() {
  [[ -f "$SETTINGS_PATH" ]] || return 1
  # This file is generated by this script and is writable only by root.
  # shellcheck disable=SC1090
  source "$SETTINGS_PATH"
  PORT_MODE="${PORT_MODE:-single}"
  HOP_START="${HOP_START:-20000}"
  HOP_END="${HOP_END:-50000}"
  HOP_MIN_INTERVAL="${HOP_MIN_INTERVAL:-15}"
  HOP_MAX_INTERVAL="${HOP_MAX_INTERVAL:-45}"
}

save_settings() {
  local tmp
  tmp="$(mktemp "${CONFIG_DIR}/.hy2-safe.env.XXXXXX")"
  {
    printf 'DOMAIN=%q\n' "$DOMAIN"
    printf 'EMAIL=%q\n' "$EMAIL"
    printf 'PORT=%q\n' "$PORT"
    printf 'PORT_MODE=%q\n' "$PORT_MODE"
    printf 'HOP_START=%q\n' "$HOP_START"
    printf 'HOP_END=%q\n' "$HOP_END"
    printf 'HOP_MIN_INTERVAL=%q\n' "$HOP_MIN_INTERVAL"
    printf 'HOP_MAX_INTERVAL=%q\n' "$HOP_MAX_INTERVAL"
    printf 'PASSWORD=%q\n' "$PASSWORD"
    printf 'MASQUERADE_MODE=%q\n' "$MASQUERADE_MODE"
    printf 'MASQUERADE_URL=%q\n' "$MASQUERADE_URL"
    printf 'AUTO_UPDATE=%q\n' "$AUTO_UPDATE"
  } >"$tmp"
  chown root:root "$tmp"
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$SETTINGS_PATH"
}

ensure_service_user_and_directories() {
  local nologin_shell
  if ! getent group hysteria >/dev/null 2>&1; then
    groupadd --system hysteria
  fi
  if ! getent passwd hysteria >/dev/null 2>&1; then
    nologin_shell="$(command -v nologin || true)"
    [[ -n "$nologin_shell" ]] || nologin_shell="/bin/false"
    useradd \
      --system \
      --gid hysteria \
      --home-dir "$STATE_DIR" \
      --shell "$nologin_shell" \
      hysteria
  fi

  install -d -m 0750 -o root -g hysteria "$CONFIG_DIR"
  install -d -m 0750 -o hysteria -g hysteria "$STATE_DIR"
  install -d -m 0750 -o hysteria -g hysteria "${STATE_DIR}/acme"
  install -d -m 0755 -o root -g root /usr/local/bin /usr/local/sbin
}

write_config() {
  local tmp
  tmp="$(mktemp "${CONFIG_DIR}/.config.yaml.XXXXXX")"
  {
    if [[ "$PORT_MODE" == "range" ]]; then
      printf 'listen: ":%s-%s"\n\n' "$HOP_START" "$HOP_END"
    else
      printf 'listen: ":%s"\n\n' "$PORT"
    fi
    printf 'acme:\n'
    printf '  domains:\n'
    printf '    - "%s"\n' "$DOMAIN"
    printf '  email: "%s"\n' "$EMAIL"
    printf '  dir: "%s/acme"\n\n' "$STATE_DIR"
    printf 'auth:\n'
    printf '  type: password\n'
    printf '  password: "%s"\n\n' "$PASSWORD"
    printf 'masquerade:\n'
    if [[ "$MASQUERADE_MODE" == "proxy" ]]; then
      printf '  type: proxy\n'
      printf '  proxy:\n'
      printf '    url: "%s"\n' "$MASQUERADE_URL"
      printf '    rewriteHost: true\n'
      printf '    insecure: false\n'
      printf '    xForwarded: false\n'
    else
      printf '  type: string\n'
      printf '  string:\n'
      printf '    content: |\n'
      printf '      <!doctype html>\n'
      printf '      <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome</title></head><body><main><h1>Welcome</h1><p>This service is online.</p></main></body></html>\n'
      printf '    headers:\n'
      printf '      content-type: "text/html; charset=utf-8"\n'
      printf '      cache-control: "no-store"\n'
      printf '      x-content-type-options: "nosniff"\n'
      printf '    statusCode: 200\n'
    fi
  } >"$tmp"
  chown root:hysteria "$tmp"
  chmod 0640 "$tmp"
  mv -f -- "$tmp" "$CONFIG_PATH"
}

install_manager_copy() {
  local source_path
  source_path="$(readlink -f "$0")"
  if [[ "$source_path" != "$MANAGER_PATH" ]]; then
    install -m 0755 -o root -g root "$source_path" "$MANAGER_PATH"
  fi
}

write_systemd_units() {
  local service_capabilities="CAP_NET_BIND_SERVICE"
  local service_address_families="AF_INET AF_INET6 AF_UNIX"
  if [[ "$PORT_MODE" == "range" ]]; then
    service_capabilities+=" CAP_NET_ADMIN"
    service_address_families+=" AF_NETLINK"
  fi
  cat >"$SERVICE_PATH" <<EOF
[Unit]
Description=Hysteria 2 Server
Documentation=https://v2.hysteria.network/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=hysteria
Group=hysteria
WorkingDirectory=${STATE_DIR}
ExecStart=${BIN_PATH} server --config ${CONFIG_PATH}
Restart=on-failure
RestartSec=5s
UMask=0077

Environment=HYSTERIA_DISABLE_UPDATE_CHECK=1
Environment=HYSTERIA_LOG_LEVEL=info
AmbientCapabilities=${service_capabilities}
CapabilityBoundingSet=${service_capabilities}
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ReadOnlyPaths=${CONFIG_DIR}
ReadWritePaths=${STATE_DIR}
LockPersonality=true
RestrictAddressFamilies=${service_address_families}
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

  cat >"$UPDATE_SERVICE_PATH" <<EOF
[Unit]
Description=Safely update the Hysteria 2 binary
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=${MANAGER_PATH} update --quiet
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
ReadWritePaths=/usr/local/bin /run/lock
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
EOF

  cat >"$UPDATE_TIMER_PATH" <<'EOF'
[Unit]
Description=Weekly Hysteria 2 stable update

[Timer]
OnCalendar=weekly
RandomizedDelaySec=12h
Persistent=true

[Install]
WantedBy=timers.target
EOF

  chmod 0644 "$SERVICE_PATH" "$UPDATE_SERVICE_PATH" "$UPDATE_TIMER_PATH"
  systemctl daemon-reload
}

configure_update_timer() {
  if [[ "$AUTO_UPDATE" -eq 1 ]]; then
    systemctl enable --now "$TIMER_NAME"
  else
    systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
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
  local server_address share_address transport_config firewall_ports
  require_root
  load_existing_settings || die "未找到由 hy2-safe 管理的配置。"
  if [[ "$PORT_MODE" == "range" ]]; then
    server_address="${DOMAIN}:${HOP_START}-${HOP_END}"
    share_address="${DOMAIN}:${HOP_START}-${HOP_END}"
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
    share_address="${DOMAIN}:${PORT}"
    firewall_ports="$PORT"
    transport_config=""
  fi
  cat <<EOF
客户端 YAML：

server: "${server_address}"
auth: ${PASSWORD}
tls:
  sni: ${DOMAIN}
fastOpen: true
${transport_config}

分享链接：
hysteria2://${PASSWORD}@${share_address}/?sni=${DOMAIN}#hy2-${DOMAIN}

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
  info "配置已更新。"
  show_client
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
  systemctl --no-pager --full status "$SERVICE_NAME" || true
  printf '\n已安装版本：%s\n' "$(installed_version || printf '未安装')"
  if systemctl is-enabled --quiet "$TIMER_NAME" 2>/dev/null; then
    printf '自动更新：已开启\n'
    systemctl list-timers --no-pager "$TIMER_NAME" || true
  else
    printf '自动更新：未开启\n'
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
  rm -f -- \
    "$SERVICE_PATH" \
    "$UPDATE_SERVICE_PATH" \
    "$UPDATE_TIMER_PATH" \
    "$BIN_PATH" \
    "$PREVIOUS_BIN_PATH" \
    "$MANAGER_PATH"
  systemctl daemon-reload
  systemctl reset-failed "$SERVICE_NAME" hy2-safe-update.service >/dev/null 2>&1 || true

  info "程序和 systemd 单元已卸载。"
  printf '出于防误删考虑，配置和证书仍保留在：\n  %s\n  %s\n' "$CONFIG_DIR" "$STATE_DIR"
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
    uninstall) command_uninstall "$@" ;;
    help | -h | --help) usage ;;
    *) die "未知命令：$command。请运行 $PROGRAM help。" ;;
  esac
}

main "$@"
