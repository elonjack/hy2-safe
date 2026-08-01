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
readonly PROGRAM_VERSION="1.0.9"
readonly REPOSITORY="apernet/hysteria"
readonly API_URL="https://api.github.com/repos/${REPOSITORY}/releases/latest"
readonly RELEASE_URL="https://github.com/${REPOSITORY}/releases/download"
readonly BIN_PATH="/usr/local/bin/hysteria"
readonly PREVIOUS_BIN_PATH="/usr/local/bin/hysteria.previous"
readonly MANAGER_PATH="/usr/local/sbin/hy2-safe"
readonly DEFAULT_DOWNLOAD_PATH="/root/hy2-safe.sh"
readonly CONFIG_DIR="/etc/hysteria"
readonly CONFIG_PATH="${CONFIG_DIR}/config.yaml"
readonly SETTINGS_PATH="${CONFIG_DIR}/hy2-safe.env"
readonly ACCOUNT_OWNERSHIP_PATH="${CONFIG_DIR}/hy2-safe-account.env"
readonly STATE_DIR="/var/lib/hysteria"
readonly SERVICE_PATH="/etc/systemd/system/hysteria-server.service"
readonly UPDATE_SERVICE_PATH="/etc/systemd/system/hy2-safe-update.service"
readonly UPDATE_TIMER_PATH="/etc/systemd/system/hy2-safe-update.timer"
readonly HEALTH_SERVICE_PATH="/etc/systemd/system/hy2-safe-health.service"
readonly HEALTH_ALERT_SERVICE_PATH="/etc/systemd/system/hy2-safe-health-alert.service"
readonly HEALTH_TIMER_PATH="/etc/systemd/system/hy2-safe-health.timer"
readonly NOTIFIER_PATH="/usr/local/libexec/hy2-safe-notifier.py"
readonly NOTIFIER_CONFIG_PATH="${CONFIG_DIR}/telegram-notifier.json"
readonly NOTIFIER_SERVICE_PATH="/etc/systemd/system/hy2-safe-notifier.service"
readonly NOTIFIER_STATE_DIR="/var/lib/hy2-safe-notifier"
readonly NOTIFIER_PRIVATE_STATE_DIR="/var/lib/private/hy2-safe-notifier"
readonly SERVICE_NAME="hysteria-server.service"
readonly TIMER_NAME="hy2-safe-update.timer"
readonly HEALTH_TIMER_NAME="hy2-safe-health.timer"
readonly NOTIFIER_NAME="hy2-safe-notifier.service"
readonly LOCK_PATH="/run/lock/hy2-safe.lock"

QUIET=0
TMP_ROOT=""
SERVICE_USER_CREATED=0
SERVICE_GROUP_CREATED=0
SERVICE_USER_UID=""
SERVICE_GROUP_GID=""
FAILURE_EVENT=""
TELEGRAM_EVENT_IN_PROGRESS=0

COLOR_RESET=""
COLOR_BOLD=""
COLOR_CYAN=""
COLOR_GREEN=""
COLOR_YELLOW=""
COLOR_RED=""

initialize_colors() {
  if [[ -t 1 && -z "${NO_COLOR+x}" && "${TERM:-dumb}" != "dumb" ]]; then
    COLOR_RESET=$'\033[0m'
    COLOR_BOLD=$'\033[1m'
    COLOR_CYAN=$'\033[36m'
    COLOR_GREEN=$'\033[32m'
    COLOR_YELLOW=$'\033[33m'
    COLOR_RED=$'\033[31m'
  fi
}

initialize_colors

info() {
  if [[ "$QUIET" -eq 0 ]]; then
    printf '%b[信息]%b %s\n' "$COLOR_GREEN" "$COLOR_RESET" "$*"
  fi
}

warn() {
  printf '%b[警告]%b %s\n' "$COLOR_YELLOW" "$COLOR_RESET" "$*" >&2
}

die() {
  if [[ -n "${FAILURE_EVENT:-}" && "${TELEGRAM_EVENT_IN_PROGRESS:-0}" -eq 0 ]] &&
    declare -F send_telegram_system_event >/dev/null 2>&1; then
    TELEGRAM_EVENT_IN_PROGRESS=1
    send_telegram_system_event "$FAILURE_EVENT" "$*" >/dev/null 2>&1 || true
    TELEGRAM_EVENT_IN_PROGRESS=0
  fi
  printf '%b[错误]%b %s\n' "$COLOR_RED" "$COLOR_RESET" "$*" >&2
  exit 1
}

prompt_input() {
  local message="$1"
  local variable_name="$2"
  local input_value=""
  printf '%b%s%b' "$COLOR_YELLOW" "$message" "$COLOR_RESET" >&2
  IFS= read -r input_value
  printf -v "$variable_name" '%s' "$input_value"
}

prompt_secret() {
  local message="$1"
  local variable_name="$2"
  local input_value=""
  printf '%b%s%b' "$COLOR_YELLOW" "$message" "$COLOR_RESET" >&2
  IFS= read -r -s input_value
  printf '\n' >&2
  printf -v "$variable_name" '%s' "$input_value"
}

prompt_yes_no() {
  local message="$1"
  local default_answer="$2"
  local answer=""
  local suffix=""
  case "$default_answer" in
    yes) suffix="[Y/n，直接回车默认：是]: " ;;
    no) suffix="[y/N，直接回车默认：否]: " ;;
    *) die "内部错误：无效的是/否默认值。"
  esac
  while true; do
    prompt_input "${message}${suffix}" answer
    case "${answer,,}" in
      y | yes) return 0 ;;
      n | no) return 1 ;;
      "")
        if [[ "$default_answer" == "yes" ]]; then
          return 0
        fi
        return 1
        ;;
      *) warn "请输入 y（是）或 n（否）；也可以直接回车使用提示中的默认值。" ;;
    esac
  done
}

menu_item() {
  local number="$1"
  local label="$2"
  printf '  %b%b%s)%b %b%s%b\n' \
    "$COLOR_BOLD" "$COLOR_YELLOW" "$number" "$COLOR_RESET" \
    "$COLOR_YELLOW" "$label" "$COLOR_RESET"
}

cleanup() {
  if [[ -n "$TMP_ROOT" && "$TMP_ROOT" == /tmp/hy2-safe.* && -d "$TMP_ROOT" ]]; then
    rm -rf -- "$TMP_ROOT"
  fi
}
trap cleanup EXIT

usage() {
  printf 'hy2-safe v%s - 安全、精简的 Hysteria 2 服务端管理器\n\n' "$PROGRAM_VERSION"
  cat <<'EOF'
用法：
  ./hy2-safe.sh                 打开中文管理菜单
  ./hy2-safe.sh install [选项]
  hy2-safe configure [选项]
  hy2-safe update [--quiet]
  hy2-safe rotate-password
  hy2-safe certificate-check [--quiet]
  hy2-safe show-client
  hy2-safe status
  hy2-safe version
  hy2-safe logs
  hy2-safe telegram-setup [--token-file FILE --chat-id ID --name NAME]
  hy2-safe telegram-test
  hy2-safe telegram-report
  hy2-safe telegram-name [NAME]
  hy2-safe telegram-logs
  hy2-safe telegram-disable
  hy2-safe telegram-replace [--token-file FILE --chat-id ID --name NAME]
  hy2-safe uninstall [--yes]

install/configure 选项：
  --domain DOMAIN            证书/SNI 域名，必须解析到本机
  --email EMAIL              ACME 证书通知邮箱
  --acme-type http|tls|dns   ACME 验证方式；默认 http，dns 使用 Cloudflare
  --cloudflare-token-file FILE
                             从 root-only 文件读取 Cloudflare API Token
  --port PORT                使用单 UDP 端口（关闭端口跳跃）
  --port-hopping START-END   使用原生端口跳跃范围，默认 50000-50500
  --hop-min SECONDS          随机跳跃最短间隔，默认 15 秒
  --hop-max SECONDS          随机跳跃最长间隔，默认 45 秒
  --password-file FILE       从仅管理员可读的文件读取密码；默认安全随机生成
  --masquerade-url URL       自定义 HTTPS 伪装站点
  --static-masquerade        使用本机静态伪装页（默认）
  --telegram-name NAME       Telegram 消息中的 VPS/节点名称
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
  - 默认 ACME HTTP-01 只需要 TCP 80；tls 只需要 TCP 443；dns 不需要入站 TCP 端口。
  - Cloudflare Token 不接受命令行明文，只能隐藏输入或从 root-only 文件读取。
  - Telegram 提醒默认关闭；启用后只向设置时确认的私人 Chat ID 发消息。
  - 完整卸载会删除 Hy2 配置、证书和 Telegram Token，无法撤销。
  - 交互终端默认启用颜色；设置 NO_COLOR=1 可关闭彩色输出。
EOF
}

remove_managed_tree() {
  local target="$1"
  case "$target" in
    /etc/hysteria | /var/lib/hysteria | /var/lib/hysteria/acme | /var/lib/hy2-safe-notifier | /var/lib/private/hy2-safe-notifier) ;;
    *) die "拒绝删除不在 hy2-safe 白名单中的目录：$target" ;;
  esac
  if [[ -L "$target" ]]; then
    rm -f -- "$target"
  elif [[ -d "$target" ]]; then
    rm -rf -- "$target"
  elif [[ -e "$target" ]]; then
    rm -f -- "$target"
  fi
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
  for command_name in \
    awk curl find flock getent groupadd groupdel head id install openssl passwd python3 readlink sed \
    sha256sum ss stat timeout tr uname useradd userdel; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  [[ "${#missing[@]}" -eq 0 ]] && return

  info "安装必要依赖：curl、CA 证书、OpenSSL、coreutils、iproute2、findutils、Python 3 和账号管理工具。"
  command -v apt-get >/dev/null 2>&1 || die "Debian 系统中未找到 apt-get。"
  apt-get -o DPkg::Lock::Timeout=60 update
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y \
    --no-install-recommends ca-certificates coreutils curl findutils iproute2 mawk openssl passwd python3 sed util-linux

  for command_name in \
    awk curl find flock getent groupadd groupdel head id install openssl passwd python3 readlink sed \
    sha256sum ss stat timeout tr uname useradd userdel; do
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
    --max-filesize 1048576 \
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
  local asset_size hashes_size expected actual hashes_actual reported_version minimum_relation
  architecture="$(detect_architecture)"
  asset="hysteria-linux-${architecture}"
  TMP_ROOT="$(mktemp -d /tmp/hy2-safe.XXXXXXXX)"
  metadata="${TMP_ROOT}/release.json"
  version="$(latest_version "$metadata")"
  minimum_relation="$(compare_versions "$version" "v2.8.0")" ||
    die "无法验证 Hysteria 最低兼容版本。"
  [[ "$minimum_relation" -ge 0 ]] ||
    die "Hysteria ${version} 低于本脚本所需的最低版本 v2.8.0，拒绝安装。"
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
  reported_version="$(
    timeout 10s "${TMP_ROOT}/${asset}" version 2>/dev/null |
      sed -n 's/.*Version:[[:space:]]*\(v[^[:space:]]*\).*/\1/p' |
      head -n 1
  )" || die "官方二进制无法运行或无法报告版本，拒绝安装。"
  [[ "$reported_version" == "$version" ]] ||
    die "二进制报告版本 ${reported_version:-未知}，与 Release 版本 ${version} 不一致。"

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

validate_acme_type() {
  case "$1" in
    http | tls | dns) return 0 ;;
    *) return 1 ;;
  esac
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

validate_cloudflare_token() {
  local token="$1"
  (("${#token}" >= 20 && "${#token}" <= 200)) || return 1
  [[ "$token" =~ ^[A-Za-z0-9_-]+$ ]]
}

validate_cloudflare_token_file() {
  validate_root_secret_file "$1" "Cloudflare API Token 文件"
}

verify_cloudflare_token_access() {
  local zone
  zone="$(
    python3 /dev/fd/3 "$DOMAIN" 3<<'PY' <<<"$CLOUDFLARE_API_TOKEN"
import json
import sys
import urllib.parse
import urllib.request

domain = sys.argv[1].lower()
token = sys.stdin.read(4096).strip()


def call(path, query=None):
    url = "https://api.cloudflare.com/client/v4" + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "hy2-safe",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(1_048_577)
    except Exception:
        raise SystemExit(1) from None
    if len(raw) > 1_048_576:
        raise SystemExit(1)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit(1) from None
    if not isinstance(value, dict) or value.get("success") is not True:
        raise SystemExit(1)
    return value.get("result")


verification = call("/user/tokens/verify")
if not isinstance(verification, dict) or verification.get("status") != "active":
    raise SystemExit(1)
labels = domain.split(".")
matched_zone = ""
for index in range(max(1, len(labels) - 1)):
    candidate = ".".join(labels[index:])
    zones = call(
        "/zones",
        {"name": candidate, "status": "active", "per_page": "1"},
    )
    if not isinstance(zones, list):
        raise SystemExit(1)
    if any(
        isinstance(zone, dict)
        and str(zone.get("name", "")).lower() == candidate
        for zone in zones
    ):
        matched_zone = candidate
        break
if not matched_zone:
    raise SystemExit(1)
print(matched_zone)
PY
  )" || die "Cloudflare Token 验证失败，或它无权读取 ${DOMAIN} 所属的 Zone。"
  info "Cloudflare Token 有效，并且可以访问 Zone：${zone}"
}

validate_telegram_chat_id() {
  local chat_id="$1"
  [[ "$chat_id" =~ ^[1-9][0-9]{0,18}$ ]]
}

validate_telegram_name() {
  python3 - "$1" <<'PY'
import sys
import unicodedata

value = sys.argv[1]
if (
    value != value.strip()
    or not 1 <= len(value) <= 64
    or any(unicodedata.category(char).startswith("C") for char in value)
):
    raise SystemExit(1)
PY
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

resolve_domain_addresses() {
  python3 - "$1" <<'PY'
import ipaddress
import socket
import sys

addresses = set()
try:
    records = socket.getaddrinfo(sys.argv[1], None, type=socket.SOCK_STREAM)
except socket.gaierror:
    raise SystemExit(1)
for record in records:
    try:
        address = ipaddress.ip_address(record[4][0].split("%", 1)[0])
    except ValueError:
        continue
    if address.is_global:
        addresses.add(str(address))
for address in sorted(addresses, key=lambda item: (":" in item, item)):
    print(address)
if not addresses:
    raise SystemExit(1)
PY
}

detect_public_ip() {
  local family="$1"
  local response address
  response="$(
    curl_secure \
      "-${family}" \
      --max-time 15 \
      --max-filesize 8192 \
      https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null
  )" || return 1
  address="$(awk -F= '$1 == "ip" { print $2; exit }' <<<"$response")"
  python3 - "$address" "$family" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
family = 4 if sys.argv[2] == "4" else 6
if address.version != family or not address.is_global:
    raise SystemExit(1)
print(address)
PY
}

preflight_domain() {
  local address public_v4="" public_v6="" expected=""
  local verified=0
  local -a addresses=()
  mapfile -t addresses < <(resolve_domain_addresses "$DOMAIN") ||
    die "域名 ${DOMAIN} 当前没有可用的公网 A/AAAA 解析，拒绝开始 ACME。"
  (("${#addresses[@]}" > 0)) ||
    die "域名 ${DOMAIN} 当前没有可用的公网 A/AAAA 解析，拒绝开始 ACME。"

  public_v4="$(detect_public_ip 4 || true)"
  public_v6="$(detect_public_ip 6 || true)"
  [[ -n "$public_v4" ]] && info "检测到本机公网 IPv4：${public_v4}"
  [[ -n "$public_v6" ]] && info "检测到本机公网 IPv6：${public_v6}"

  for address in "${addresses[@]}"; do
    if [[ "$address" == *:* ]]; then
      expected="$public_v6"
    else
      expected="$public_v4"
    fi
    if [[ -z "$expected" ]]; then
      warn "无法从本机验证域名地址 ${address} 对应的 IP 协议；请确认没有失效的 A/AAAA 记录。"
      continue
    fi
    [[ "$address" == "$expected" ]] ||
      die "域名 ${DOMAIN} 解析到 ${address}，但本机公网地址是 ${expected}。请关闭 Cloudflare 小黄云并修正 DNS。"
    verified=1
  done

  if [[ "$verified" -eq 0 ]]; then
    warn "未能自动比对域名与公网地址；脚本会继续，但 ACME 可能失败。"
  else
    info "域名解析与本机公网地址一致。"
  fi
}

preflight_ports() {
  local current_hysteria_start="${1:-}"
  local current_hysteria_end="${2:-${1:-}}"
  local acme_port port local_address
  local -a conflicts=()
  declare -A occupied_udp=()

  case "$ACME_TYPE" in
    http) acme_port=80 ;;
    tls) acme_port=443 ;;
    dns) acme_port="" ;;
    *) die "内部错误：未知 ACME 类型 ${ACME_TYPE}。" ;;
  esac
  if [[ -n "$acme_port" ]]; then
    if ss -H -lnt | awk -v target="$acme_port" '
      {
        address = $4
        sub(/^.*:/, "", address)
        if (address == target) {
          found = 1
        }
      }
      END { exit(found ? 0 : 1) }
    '; then
      die "ACME ${ACME_TYPE} 验证需要 TCP ${acme_port}，但该端口已被其他程序监听。"
    fi
  fi

  while IFS= read -r local_address; do
    port="${local_address##*:}"
    [[ "$port" =~ ^[0-9]+$ ]] && occupied_udp["$port"]=1
  done < <(ss -H -lun | awk '{ print $4 }')

  if [[ "$PORT_MODE" == "single" ]]; then
    if [[ -n "${occupied_udp[$PORT]:-}" ]] &&
      ! {
        [[ "$current_hysteria_start" =~ ^[0-9]+$ &&
          "$current_hysteria_end" =~ ^[0-9]+$ ]] &&
          ((PORT >= current_hysteria_start && PORT <= current_hysteria_end))
      }; then
      conflicts+=("$PORT")
    fi
  else
    for ((port = HOP_START; port <= HOP_END; port++)); do
      if [[ -n "${occupied_udp[$port]:-}" ]] &&
        ! {
          [[ "$current_hysteria_start" =~ ^[0-9]+$ &&
            "$current_hysteria_end" =~ ^[0-9]+$ ]] &&
            ((port >= current_hysteria_start && port <= current_hysteria_end))
        }; then
        conflicts+=("$port")
        (("${#conflicts[@]}" >= 5)) && break
      fi
    done
  fi
  if (("${#conflicts[@]}" > 0)); then
    die "请求的 Hy2 UDP 端口已被其他程序监听：${conflicts[*]}。请更换端口或先处理冲突。"
  fi

  if [[ -n "$acme_port" ]]; then
    info "端口预检查通过：ACME 使用 TCP ${acme_port}；Hy2 使用 UDP。"
  else
    info "端口预检查通过：Cloudflare DNS-01 不需要入站 TCP 端口；Hy2 使用 UDP。"
  fi
}

prompt_install_values() {
  local non_interactive="$1"
  local answer=""
  local masquerade_hint=""

  if [[ -z "$DOMAIN" && "$non_interactive" -eq 0 ]]; then
    prompt_input "证书/SNI 域名（必须解析到本 VPS）: " DOMAIN
  fi
  DOMAIN="${DOMAIN,,}"

  if [[ -z "$EMAIL" && "$non_interactive" -eq 0 ]]; then
    prompt_input "ACME 通知邮箱: " EMAIL
  fi

  if [[ "$ACME_TYPE_WAS_SET" -eq 0 && "$non_interactive" -eq 0 ]]; then
    if [[ "$ACME_TYPE" == "dns" ]]; then
      if prompt_yes_no "继续使用 Cloudflare DNS-01（不需要 TCP 80/443）？" yes; then
        ACME_TYPE="dns"
      else
        ACME_TYPE="http"
      fi
    elif prompt_yes_no "改用 Cloudflare DNS-01（不需要 TCP 80/443）？" no; then
      ACME_TYPE="dns"
    fi
  fi

  if [[ "$ACME_TYPE" == "dns" ]]; then
    if [[ "$CLOUDFLARE_TOKEN_WAS_SET" -eq 0 ]]; then
      if [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
        if [[ "$non_interactive" -eq 0 ]] &&
          prompt_yes_no "更换当前 Cloudflare API Token？" no; then
          prompt_secret "请输入新的 Cloudflare API Token（输入时不会显示）: " \
            CLOUDFLARE_API_TOKEN
        fi
      elif [[ "$non_interactive" -eq 0 ]]; then
        prompt_secret "请输入 Cloudflare API Token（输入时不会显示）: " \
          CLOUDFLARE_API_TOKEN
      else
        die "DNS-01 缺少 --cloudflare-token-file。"
      fi
    fi
  else
    [[ "$CLOUDFLARE_TOKEN_WAS_SET" -eq 0 ]] ||
      die "--cloudflare-token-file 只能与 --acme-type dns 一起使用。"
    CLOUDFLARE_API_TOKEN=""
  fi

  if [[ "$PORT_MODE_WAS_SET" -eq 0 && "$non_interactive" -eq 0 ]]; then
    if [[ "$PORT_MODE" == "range" ]]; then
      if prompt_yes_no "开启原生端口跳跃？" yes; then
        PORT_MODE="range"
      else
        PORT_MODE="single"
      fi
    else
      if prompt_yes_no "开启原生端口跳跃？" no; then
        PORT_MODE="range"
      else
        PORT_MODE="single"
      fi
    fi
  fi

  if [[ "$PORT_VALUE_WAS_SET" -eq 0 && "$non_interactive" -eq 0 ]]; then
    if [[ "$PORT_MODE" == "range" ]]; then
      prompt_input "UDP 跳跃端口范围 [直接回车默认：${HOP_START}-${HOP_END}]: " answer
      if [[ -n "$answer" ]]; then
        HOP_START="${answer%-*}"
        HOP_END="${answer#*-}"
      fi
    else
      prompt_input "Hysteria UDP 端口 [直接回车默认：${PORT}]: " answer
      [[ -n "$answer" ]] && PORT="$answer"
    fi
  fi

  if [[ "$MASQUERADE_WAS_SET" -eq 0 && "$non_interactive" -eq 0 ]]; then
    if [[ "$MASQUERADE_MODE" == "proxy" ]]; then
      masquerade_hint="保留当前反代 ${MASQUERADE_URL}"
    else
      masquerade_hint="使用本机静态伪装页"
    fi
    prompt_input "自定义 HTTPS 伪装站点 [直接回车默认：${masquerade_hint}]: " answer
    if [[ -n "$answer" ]]; then
      MASQUERADE_MODE="proxy"
      MASQUERADE_URL="$answer"
    fi
  fi

  if (
    [[ "${TELEGRAM_ENABLED:-0}" -eq 1 ]] &&
    [[ "$TELEGRAM_NAME_WAS_SET" -eq 0 ]] &&
    [[ "$non_interactive" -eq 0 ]]
  ); then
    prompt_input "Telegram 消息名称 [直接回车保留：${TELEGRAM_NAME}]: " answer
    [[ -z "$answer" ]] || TELEGRAM_NAME="$answer"
  fi

  if [[ "$AUTO_UPDATE_WAS_SET" -eq 0 && "$non_interactive" -eq 0 ]]; then
    if [[ "$AUTO_UPDATE" -eq 1 ]]; then
      if prompt_yes_no "开启每周自动更新并在失败时回滚？" yes; then
        AUTO_UPDATE=1
      else
        AUTO_UPDATE=0
      fi
    else
      if prompt_yes_no "开启每周自动更新并在失败时回滚？" no; then
        AUTO_UPDATE=1
      else
        AUTO_UPDATE=0
      fi
    fi
  fi

  [[ -n "$PASSWORD" ]] || PASSWORD="$(random_password)"
}

validate_install_values() {
  [[ -n "$DOMAIN" ]] || die "缺少 --domain。"
  validate_domain "$DOMAIN" || die "域名格式无效：$DOMAIN"
  [[ -n "$EMAIL" ]] || die "缺少 --email。"
  validate_email "$EMAIL" || die "邮箱格式无效：$EMAIL"
  validate_acme_type "$ACME_TYPE" ||
    die "ACME 验证方式只能是 http、tls 或 dns。"
  if [[ "$ACME_TYPE" == "dns" ]]; then
    validate_cloudflare_token "$CLOUDFLARE_API_TOKEN" ||
      die "Cloudflare API Token 格式无效。"
  elif [[ -n "${CLOUDFLARE_API_TOKEN:-}" ]]; then
    die "非 DNS-01 模式不能保留 Cloudflare API Token。"
  fi
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

  if [[ -n "${TELEGRAM_NAME:-}" ]]; then
    validate_telegram_name "$TELEGRAM_NAME" ||
      die "Telegram 消息名称必须是 1-64 个可见字符，且首尾不能有空格。"
  fi

  if [[ "${TELEGRAM_ENABLED:-0}" -eq 1 ]]; then
    validate_telegram_chat_id "$TELEGRAM_CHAT_ID" ||
      die "Telegram Chat ID 必须是私人聊天的正整数。"
    validate_port "$TELEGRAM_STATS_PORT" ||
      die "Telegram 在线统计端口无效。"
    validate_password "$TELEGRAM_STATS_SECRET" ||
      die "Telegram 在线统计密钥无效。"
  fi

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
  validate_root_secret_file "$SETTINGS_PATH" "hy2-safe 设置文件"
  TELEGRAM_NAME=""
  CLOUDFLARE_API_TOKEN=""
  # This file is generated by this script and is writable only by root.
  # shellcheck disable=SC1090
  source "$SETTINGS_PATH"
  ACME_TYPE="${ACME_TYPE:-http}"
  CLOUDFLARE_API_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
  PORT_MODE="${PORT_MODE:-single}"
  HOP_START="${HOP_START:-50000}"
  HOP_END="${HOP_END:-50500}"
  HOP_MIN_INTERVAL="${HOP_MIN_INTERVAL:-15}"
  HOP_MAX_INTERVAL="${HOP_MAX_INTERVAL:-45}"
  TELEGRAM_ENABLED="${TELEGRAM_ENABLED:-0}"
  TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
  TELEGRAM_STATS_PORT="${TELEGRAM_STATS_PORT:-}"
  TELEGRAM_STATS_SECRET="${TELEGRAM_STATS_SECRET:-}"
  TELEGRAM_NAME="${TELEGRAM_NAME:-${DOMAIN:-Hy2 节点}}"
}

save_settings() {
  local tmp
  tmp="$(mktemp "${CONFIG_DIR}/.hy2-safe.env.XXXXXX")"
  if ! {
    printf 'DOMAIN=%q\n' "$DOMAIN"
    printf 'EMAIL=%q\n' "$EMAIL"
    printf 'ACME_TYPE=%q\n' "$ACME_TYPE"
    printf 'CLOUDFLARE_API_TOKEN=%q\n' "$CLOUDFLARE_API_TOKEN"
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
    printf 'TELEGRAM_ENABLED=%q\n' "$TELEGRAM_ENABLED"
    printf 'TELEGRAM_CHAT_ID=%q\n' "$TELEGRAM_CHAT_ID"
    printf 'TELEGRAM_STATS_PORT=%q\n' "$TELEGRAM_STATS_PORT"
    printf 'TELEGRAM_STATS_SECRET=%q\n' "$TELEGRAM_STATS_SECRET"
    printf 'TELEGRAM_NAME=%q\n' "$TELEGRAM_NAME"
  } >"$tmp"; then
    rm -f -- "$tmp"
    return 1
  fi
  if ! chown root:root "$tmp" ||
    ! chmod 0600 "$tmp" ||
    ! mv -f -- "$tmp" "$SETTINGS_PATH"; then
    rm -f -- "$tmp"
    return 1
  fi
}

load_account_ownership() {
  local line=""
  local seen_format=0 seen_user=0 seen_group=0 seen_uid=0 seen_gid=0
  SERVICE_USER_CREATED=0
  SERVICE_GROUP_CREATED=0
  SERVICE_USER_UID=""
  SERVICE_GROUP_GID=""
  [[ -e "$ACCOUNT_OWNERSHIP_PATH" || -L "$ACCOUNT_OWNERSHIP_PATH" ]] || return 1
  validate_root_secret_file "$ACCOUNT_OWNERSHIP_PATH" "服务账号归属记录"
  [[ "$(stat -c '%g' -- "$ACCOUNT_OWNERSHIP_PATH")" == "0" ]] ||
    die "服务账号归属记录必须由 root 组拥有：$ACCOUNT_OWNERSHIP_PATH"
  [[ "$(stat -c '%a' -- "$ACCOUNT_OWNERSHIP_PATH")" == "600" ]] ||
    die "服务账号归属记录权限必须严格为 0600：$ACCOUNT_OWNERSHIP_PATH"

  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      FORMAT_VERSION=1)
        ((seen_format == 0)) || die "服务账号归属记录包含重复的 FORMAT_VERSION。"
        seen_format=1
        ;;
      SERVICE_USER_CREATED=0 | SERVICE_USER_CREATED=1)
        ((seen_user == 0)) || die "服务账号归属记录包含重复的 SERVICE_USER_CREATED。"
        SERVICE_USER_CREATED="${line#*=}"
        seen_user=1
        ;;
      SERVICE_GROUP_CREATED=0 | SERVICE_GROUP_CREATED=1)
        ((seen_group == 0)) || die "服务账号归属记录包含重复的 SERVICE_GROUP_CREATED。"
        SERVICE_GROUP_CREATED="${line#*=}"
        seen_group=1
        ;;
      SERVICE_USER_UID=- | SERVICE_USER_UID=[0-9]*)
        ((seen_uid == 0)) || die "服务账号归属记录包含重复的 SERVICE_USER_UID。"
        SERVICE_USER_UID="${line#*=}"
        [[ "$SERVICE_USER_UID" == "-" || "$SERVICE_USER_UID" =~ ^[0-9]+$ ]] ||
          die "服务账号归属记录中的 UID 无效。"
        seen_uid=1
        ;;
      SERVICE_GROUP_GID=- | SERVICE_GROUP_GID=[0-9]*)
        ((seen_gid == 0)) || die "服务账号归属记录包含重复的 SERVICE_GROUP_GID。"
        SERVICE_GROUP_GID="${line#*=}"
        [[ "$SERVICE_GROUP_GID" == "-" || "$SERVICE_GROUP_GID" =~ ^[0-9]+$ ]] ||
          die "服务账号归属记录中的 GID 无效。"
        seen_gid=1
        ;;
      *) die "服务账号归属记录包含未知或格式错误的内容，拒绝使用。" ;;
    esac
  done <"$ACCOUNT_OWNERSHIP_PATH"

  ((seen_format == 1 && seen_user == 1 && seen_group == 1 &&
    seen_uid == 1 && seen_gid == 1)) ||
    die "服务账号归属记录缺少必需字段。"
  if [[ "$SERVICE_USER_CREATED" -eq 1 ]]; then
    [[ "$SERVICE_USER_UID" =~ ^[0-9]+$ ]] ||
      die "服务账号归属记录声明创建了用户，但没有记录有效 UID。"
  else
    [[ "$SERVICE_USER_UID" == "-" ]] ||
      die "服务账号归属记录没有创建用户，却记录了 UID。"
  fi
  if [[ "$SERVICE_GROUP_CREATED" -eq 1 ]]; then
    [[ "$SERVICE_GROUP_GID" =~ ^[0-9]+$ ]] ||
      die "服务账号归属记录声明创建了组，但没有记录有效 GID。"
  else
    [[ "$SERVICE_GROUP_GID" == "-" ]] ||
      die "服务账号归属记录没有创建组，却记录了 GID。"
  fi
}

save_account_ownership() {
  local tmp user_uid="-" group_gid="-"
  [[ ! -L "$CONFIG_DIR" ]] || die "配置目录不能是符号链接：$CONFIG_DIR"
  install -d -m 0750 -o root -g hysteria "$CONFIG_DIR"
  if [[ "$SERVICE_USER_CREATED" -eq 1 ]]; then
    user_uid="$(id -u hysteria)"
  fi
  if [[ "$SERVICE_GROUP_CREATED" -eq 1 ]]; then
    group_gid="$(getent group hysteria | awk -F: '{print $3}')"
  fi
  [[ "$user_uid" == "-" || "$user_uid" =~ ^[0-9]+$ ]] ||
    die "无法记录 hysteria 服务用户 UID。"
  [[ "$group_gid" == "-" || "$group_gid" =~ ^[0-9]+$ ]] ||
    die "无法记录 hysteria 服务组 GID。"

  tmp="$(mktemp "${CONFIG_DIR}/.hy2-safe-account.env.XXXXXX")"
  {
    printf 'FORMAT_VERSION=1\n'
    printf 'SERVICE_USER_CREATED=%s\n' "$SERVICE_USER_CREATED"
    printf 'SERVICE_GROUP_CREATED=%s\n' "$SERVICE_GROUP_CREATED"
    printf 'SERVICE_USER_UID=%s\n' "$user_uid"
    printf 'SERVICE_GROUP_GID=%s\n' "$group_gid"
  } >"$tmp"
  chown root:root "$tmp"
  chmod 0600 "$tmp"
  mv -f -- "$tmp" "$ACCOUNT_OWNERSHIP_PATH"
  SERVICE_USER_UID="$user_uid"
  SERVICE_GROUP_GID="$group_gid"
}

validate_recorded_service_identity() {
  if [[ "$SERVICE_USER_CREATED" -eq 1 ]] && getent passwd hysteria >/dev/null 2>&1; then
    [[ "$(id -u hysteria)" == "$SERVICE_USER_UID" ]] ||
      die "hysteria 用户的 UID 与 hy2-safe 创建记录不一致，拒绝继续。"
  fi
  if [[ "$SERVICE_GROUP_CREATED" -eq 1 ]] && getent group hysteria >/dev/null 2>&1; then
    [[ "$(getent group hysteria | awk -F: '{print $3}')" == "$SERVICE_GROUP_GID" ]] ||
      die "hysteria 组的 GID 与 hy2-safe 创建记录不一致，拒绝继续。"
  fi
}

validate_service_group() {
  local group_entry group_gid group_members member
  local -a extra_group_members=()
  getent group hysteria >/dev/null 2>&1 ||
    die "缺少 hysteria 服务组。"
  group_entry="$(getent group hysteria)"
  group_gid="$(awk -F: '{print $3}' <<<"$group_entry")"
  group_members="$(awk -F: '{print $4}' <<<"$group_entry")"
  while IFS=: read -r member _; do
    [[ -z "$member" || "$member" == "hysteria" ]] ||
      die "hysteria 组还包含其他主组成员（${member}），配置密码可能被读取，拒绝继续。"
  done < <(getent passwd | awk -F: -v gid="$group_gid" '$4 == gid')
  if [[ -n "$group_members" ]]; then
    IFS=',' read -r -a extra_group_members <<<"$group_members"
    for member in "${extra_group_members[@]}"; do
      [[ -z "$member" || "$member" == "hysteria" ]] ||
        die "hysteria 组包含额外成员（${member}），配置密码可能被读取，拒绝继续。"
    done
  fi
}

validate_service_account() {
  local require_directories="${1:-1}"
  local passwd_entry primary_group account_home account_shell password_status member
  local service_uid service_gid
  getent passwd hysteria >/dev/null 2>&1 ||
    die "缺少 hysteria 服务用户。"
  passwd_entry="$(getent passwd hysteria)"
  account_home="$(awk -F: '{print $6}' <<<"$passwd_entry")"
  account_shell="$(awk -F: '{print $7}' <<<"$passwd_entry")"
  primary_group="$(id -gn hysteria)"
  [[ "$primary_group" == "hysteria" ]] ||
    die "现有 hysteria 用户的主组不是 hysteria，拒绝复用。"
  [[ "$account_home" == "$STATE_DIR" ]] ||
    die "现有 hysteria 用户的家目录不是 ${STATE_DIR}，拒绝复用。"
  case "$account_shell" in
    /usr/sbin/nologin | /sbin/nologin | /bin/false) ;;
    *) die "现有 hysteria 用户具有可登录 Shell，拒绝复用。" ;;
  esac
  password_status="$(passwd --status hysteria 2>/dev/null)" ||
    die "无法读取 hysteria 用户的密码锁定状态。"
  [[ "$(awk '{print $2}' <<<"$password_status")" == "L" ]] ||
    die "hysteria 用户的密码未锁定（状态必须为 L），拒绝启动服务。"
  [[ ! -e "${account_home}/.ssh" && ! -L "${account_home}/.ssh" ]] ||
    die "hysteria 服务账号家目录中存在 .ssh/authorized_keys 入口，拒绝启动服务。"

  while read -r member; do
    [[ -z "$member" || "$member" == "hysteria" ]] ||
      die "现有 hysteria 用户还属于其他组（${member}），拒绝以该账号运行服务。"
  done < <(id -nG hysteria | tr ' ' '\n')

  validate_service_group
  validate_recorded_service_identity

  if [[ "$require_directories" -eq 1 ]]; then
    service_uid="$(id -u hysteria)"
    service_gid="$(getent group hysteria | awk -F: '{print $3}')"
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] ||
      die "hysteria 家目录必须是非符号链接的真实目录。"
    [[ "$(stat -c '%u:%g:%a' -- "$STATE_DIR")" == "0:${service_gid}:750" ]] ||
      die "hysteria 家目录必须是 root:hysteria 0750，防止服务账号创建 SSH 密钥入口。"
    [[ -d "${STATE_DIR}/acme" && ! -L "${STATE_DIR}/acme" ]] ||
      die "ACME 状态目录必须是非符号链接的真实目录。"
    [[ "$(stat -c '%u:%g:%a' -- "${STATE_DIR}/acme")" == "${service_uid}:${service_gid}:750" ]] ||
      die "ACME 状态目录必须是 hysteria:hysteria 0750。"
  fi
}

ensure_service_user_and_directories() {
  local nologin_shell
  load_account_ownership || true
  validate_recorded_service_identity

  if ! getent group hysteria >/dev/null 2>&1; then
    [[ "$SERVICE_GROUP_CREATED" -eq 0 ]] ||
      die "hy2-safe 记录的 hysteria 服务组已消失，拒绝自动猜测并重建。"
    getent passwd hysteria >/dev/null 2>&1 &&
      die "存在 hysteria 用户但缺少同名服务组，拒绝修复未知账号。"
    groupadd --system hysteria
    SERVICE_GROUP_CREATED=1
    save_account_ownership
  fi
  if ! getent passwd hysteria >/dev/null 2>&1; then
    [[ "$SERVICE_USER_CREATED" -eq 0 ]] ||
      die "hy2-safe 记录的 hysteria 服务用户已消失，拒绝自动猜测并重建。"
    nologin_shell="$(command -v nologin || true)"
    [[ -n "$nologin_shell" ]] || nologin_shell="/bin/false"
    useradd \
      --system \
      --gid hysteria \
      --home-dir "$STATE_DIR" \
      --no-create-home \
      --shell "$nologin_shell" \
      hysteria
    if ! passwd --lock hysteria >/dev/null; then
      userdel hysteria >/dev/null 2>&1 || true
      die "无法锁定 hysteria 服务用户密码；已尝试撤销账号创建。"
    fi
    SERVICE_USER_CREATED=1
    save_account_ownership
  fi

  validate_service_account 0
  [[ ! -L "$CONFIG_DIR" ]] || die "配置目录不能是符号链接：$CONFIG_DIR"
  [[ ! -L "$STATE_DIR" ]] || die "服务状态目录不能是符号链接：$STATE_DIR"
  [[ ! -L "${STATE_DIR}/acme" ]] || die "ACME 状态目录不能是符号链接。"
  install -d -m 0750 -o root -g hysteria "$CONFIG_DIR"
  install -d -m 0750 -o root -g hysteria "$STATE_DIR"
  install -d -m 0750 -o hysteria -g hysteria "${STATE_DIR}/acme"
  install -d -m 0755 -o root -g root /usr/local/bin /usr/local/sbin /usr/local/libexec
  validate_service_account 1
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
    printf '  dir: "%s/acme"\n' "$STATE_DIR"
    printf '  type: "%s"\n' "$ACME_TYPE"
    if [[ "$ACME_TYPE" == "dns" ]]; then
      printf '  dns:\n'
      printf '    name: cloudflare\n'
      printf '    config:\n'
      printf '      cloudflare_api_token: "%s"\n' "$CLOUDFLARE_API_TOKEN"
    fi
    printf '\n'
    printf 'auth:\n'
    printf '  type: password\n'
    printf '  password: "%s"\n\n' "$PASSWORD"
    printf 'ignoreClientBandwidth: true\n\n'
    printf 'congestion:\n'
    printf '  type: bbr\n'
    printf '  bbrProfile: conservative\n\n'
    if [[ "${TELEGRAM_ENABLED:-0}" -eq 1 ]]; then
      printf 'trafficStats:\n'
      printf '  listen: "127.0.0.1:%s"\n' "$TELEGRAM_STATS_PORT"
      printf '  secret: "%s"\n\n' "$TELEGRAM_STATS_SECRET"
    fi
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

write_notifier_script() {
  local tmp
  install -d -m 0755 -o root -g root /usr/local/libexec
  tmp="$(mktemp /usr/local/libexec/.hy2-safe-notifier.XXXXXX)"
  cat >"$tmp" <<'PY'
#!/usr/bin/env python3
"""Send safe Hysteria connection alerts and persisted traffic reports."""

from __future__ import annotations

import datetime as dt
import html
import ipaddress
import json
import math
import os
import selectors
import signal
import subprocess
import sys
import time
import unicodedata
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


BEIJING = dt.timezone(dt.timedelta(hours=8))
HOURLY_SECONDS = 3600
QUIET_RESET_SECONDS = 86400
MAX_GROUPS = 512
MAX_OUTBOX = 128
PRUNE_AFTER_SECONDS = 90 * 86400
TICK_SECONDS = 30
TRAFFIC_SAMPLE_SECONDS = 60
REPORT_HOUR = 8
REPORT_MINUTE = 0
MONTHLY_REPORT_MINUTE = 5
TRAFFIC_DAY_RETENTION = 70
MAX_INTERFACES = 16
MAX_JOURNAL_BUFFER = 2 * 1024 * 1024

state_dir = Path(os.environ.get("STATE_DIRECTORY", "/var/lib/hy2-safe-notifier"))
state_path = state_dir / "state.json"
cursor_path = state_dir / "journal.cursor"
credential_dir = Path(os.environ["CREDENTIALS_DIRECTORY"])
config_path = credential_dir / "telegram-config"


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def atomic_write_text(path: Path, value: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(value, encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    atomic_write_text(
        path,
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n",
    )


def load_config() -> dict[str, Any]:
    value = json.loads(config_path.read_text(encoding="utf-8"))
    token = value.get("token")
    chat_id = str(value.get("chat_id", ""))
    stats_port = value.get("stats_port")
    stats_secret = value.get("stats_secret")
    display_name = value.get("display_name", "Hy2 节点")
    if (
        not isinstance(token, str)
        or not 20 <= len(token) <= 200
        or any(ch.isspace() for ch in token)
        or ":" not in token
    ):
        raise RuntimeError("invalid Telegram token credential")
    if (
        not chat_id.isdigit()
        or chat_id.startswith("0")
        or len(chat_id) > 19
    ):
        raise RuntimeError("invalid private Telegram Chat ID")
    if not isinstance(stats_port, int) or not 1 <= stats_port <= 65535:
        raise RuntimeError("invalid local traffic stats port")
    if not isinstance(stats_secret, str) or not 16 <= len(stats_secret) <= 128:
        raise RuntimeError("invalid local traffic stats secret")
    if (
        not isinstance(display_name, str)
        or display_name != display_name.strip()
        or not 1 <= len(display_name) <= 64
        or any(unicodedata.category(char).startswith("C") for char in display_name)
    ):
        raise RuntimeError("invalid Telegram display name")
    return {
        "token": token,
        "chat_id": chat_id,
        "stats_port": stats_port,
        "stats_secret": stats_secret,
        "display_name": display_name,
    }


def empty_day() -> dict[str, Any]:
    return {
        "hy2_upload": 0,
        "hy2_download": 0,
        "vps_receive": 0,
        "vps_send": 0,
        "hy2_samples": 0,
        "vps_samples": 0,
        "peak_online": 0,
        "sources": {},
    }


def default_state(now: float | None = None) -> dict[str, Any]:
    timestamp = time.time() if now is None else now
    today = dt.datetime.fromtimestamp(timestamp, BEIJING).date().isoformat()
    return {
        "version": 2,
        "reporting_started_date": today,
        "last_daily_report": "",
        "last_monthly_report": "",
        "groups": {},
        "outbox": {},
        "traffic": {
            "hy2_last": None,
            "interfaces_last": {},
            "days": {},
        },
    }


def nonnegative_int(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return 0


def nonnegative_float(value: Any) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(result) or result < 0:
        return 0.0
    return result


def normalize_groups(value: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not isinstance(value, dict):
        return result
    for key, group in list(value.items())[-MAX_GROUPS:]:
        if (
            not isinstance(key, str)
            or not 1 <= len(key) <= 128
            or not isinstance(group, dict)
        ):
            continue
        label = group.get("label")
        if not isinstance(label, str) or not 1 <= len(label) <= 128:
            continue
        first_seen = nonnegative_float(group.get("first_seen"))
        last_seen = nonnegative_float(group.get("last_seen"))
        last_summary = nonnegative_float(group.get("last_summary"))
        result[key] = {
            "label": label,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "total": nonnegative_int(group.get("total")),
            "pending_reconnects": nonnegative_int(group.get("pending_reconnects")),
            "last_summary": last_summary or first_seen,
        }
    return result


def normalize_day(value: Any) -> dict[str, Any]:
    result = empty_day()
    if not isinstance(value, dict):
        return result
    for key in (
        "hy2_upload",
        "hy2_download",
        "vps_receive",
        "vps_send",
        "hy2_samples",
        "vps_samples",
        "peak_online",
    ):
        result[key] = nonnegative_int(value.get(key))
    sources = value.get("sources")
    if isinstance(sources, dict):
        for key, count in list(sources.items())[:MAX_GROUPS]:
            if isinstance(key, str) and 1 <= len(key) <= 128:
                normalized_count = nonnegative_int(count)
                if normalized_count:
                    result["sources"][key] = normalized_count
    return result


def normalize_outbox(value: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if not isinstance(value, dict):
        return result
    for key, item in list(value.items())[-MAX_OUTBOX:]:
        if (
            not isinstance(key, str)
            or not isinstance(item, dict)
            or not isinstance(item.get("text"), str)
        ):
            continue
        result[key] = {
            "text": item["text"][:4096],
            "created": nonnegative_float(item.get("created")),
            "silent": bool(item.get("silent", False)),
        }
    return result


def is_iso_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return dt.date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def is_iso_month(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 7:
        return False
    try:
        return dt.date.fromisoformat(value + "-01").strftime("%Y-%m") == value
    except ValueError:
        return False


def normalize_state(value: Any, now: float | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("state is not an object")
    version = value.get("version")
    result = default_state(now)
    if version == 1:
        # v1 had no durable traffic counters. Preserve connection groups and
        # queued alerts, then start traffic accounting from the first v2 sample.
        result["groups"] = normalize_groups(value.get("groups"))
        result["outbox"] = normalize_outbox(value.get("outbox"))
        return result
    if version != 2:
        raise ValueError("unsupported state version")
    result["groups"] = normalize_groups(value.get("groups"))
    result["outbox"] = normalize_outbox(value.get("outbox"))
    candidate_start = value.get("reporting_started_date")
    if is_iso_date(candidate_start):
        result["reporting_started_date"] = candidate_start
    candidate_daily = value.get("last_daily_report")
    if candidate_daily == "" or is_iso_date(candidate_daily):
        result["last_daily_report"] = candidate_daily
    candidate_month = value.get("last_monthly_report")
    if candidate_month == "" or is_iso_month(candidate_month):
        result["last_monthly_report"] = candidate_month
    traffic = value.get("traffic")
    if not isinstance(traffic, dict):
        return result
    hy2_last = traffic.get("hy2_last")
    if isinstance(hy2_last, dict):
        result["traffic"]["hy2_last"] = {
            "upload": nonnegative_int(hy2_last.get("upload")),
            "download": nonnegative_int(hy2_last.get("download")),
        }
    interfaces_last = traffic.get("interfaces_last")
    if isinstance(interfaces_last, dict):
        for interface, counters in list(interfaces_last.items())[:MAX_INTERFACES]:
            if (
                isinstance(interface, str)
                and 1 <= len(interface) <= 64
                and isinstance(counters, dict)
            ):
                result["traffic"]["interfaces_last"][interface] = {
                    "receive": nonnegative_int(counters.get("receive")),
                    "send": nonnegative_int(counters.get("send")),
                }
    days = traffic.get("days")
    if isinstance(days, dict):
        for date_value, record in list(days.items())[-TRAFFIC_DAY_RETENTION:]:
            if is_iso_date(date_value):
                result["traffic"]["days"][date_value] = normalize_day(record)
    return result


def load_state() -> dict[str, Any]:
    try:
        value = json.loads(state_path.read_text(encoding="utf-8"))
        return normalize_state(value)
    except FileNotFoundError:
        return default_state()
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        log(f"忽略损坏的提醒状态文件：{exc}")
        return default_state()


def format_time(timestamp: float) -> str:
    return dt.datetime.fromtimestamp(timestamp, BEIJING).strftime("%Y-%m-%d %H:%M:%S")


def parse_remote_ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if address.startswith("["):
        closing = address.find("]")
        if closing < 0:
            raise ValueError("invalid bracketed address")
        host = address[1:closing]
    else:
        host, separator, port = address.rpartition(":")
        if not separator or not port.isdigit():
            raise ValueError("missing port")
    return ipaddress.ip_address(host.split("%", 1)[0])


def hidden_ip_group(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[str, str]:
    if isinstance(address, ipaddress.IPv4Address):
        network = ipaddress.ip_network(f"{address}/24", strict=False)
        pieces = str(address).split(".")
        return f"v4:{network.network_address}/24", ".".join(pieces[:3]) + ".*"
    network = ipaddress.ip_network(f"{address}/48", strict=False)
    pieces = [format(int(piece, 16), "x") for piece in address.exploded.split(":")[:3]]
    return f"v6:{network.network_address}/48", ":".join(pieces) + ":*"


def decode_journal_message(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    # journalctl represents fields containing control/binary bytes as integer
    # arrays in JSON output. Hysteria's ANSI-colored logs therefore arrive in
    # this form on some systemd versions even though the text itself is UTF-8.
    if (
        isinstance(value, list)
        and len(value) <= 1_048_576
        and all(
            isinstance(item, int)
            and not isinstance(item, bool)
            and 0 <= item <= 255
            for item in value
        )
    ):
        return bytes(value).decode("utf-8", errors="replace")
    return None


def extract_connection(entry: dict[str, Any]) -> tuple[str, float] | None:
    message = decode_journal_message(entry.get("MESSAGE"))
    if message is None or "client connected" not in message:
        return None
    start = message.find("{", message.find("client connected"))
    if start < 0:
        return None
    try:
        fields, _ = json.JSONDecoder().raw_decode(message[start:])
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(fields, dict):
        return None
    address = fields.get("addr")
    if not isinstance(address, str):
        return None
    raw_timestamp = entry.get("__REALTIME_TIMESTAMP")
    try:
        timestamp = int(raw_timestamp) / 1_000_000
    except (TypeError, ValueError):
        timestamp = time.time()
    return address, timestamp


def telegram_call(config: dict[str, Any], method: str, fields: dict[str, str]) -> Any:
    url = f"https://api.telegram.org/bot{config['token']}/{method}"
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        raw = response.read(1_048_577)
    if len(raw) > 1_048_576:
        raise RuntimeError("Telegram response is too large")
    result = json.loads(raw.decode("utf-8"))
    if not result.get("ok"):
        raise RuntimeError("Telegram API rejected the request")
    return result.get("result")


def send_message(config: dict[str, Any], text: str, silent: bool = False) -> None:
    telegram_call(
        config,
        "sendMessage",
        {
            "chat_id": config["chat_id"],
            "text": text[:4096],
            "parse_mode": "HTML",
            "disable_notification": "true" if silent else "false",
            "protect_content": "true",
        },
    )


def stats_json(config: dict[str, Any], path: str) -> Any:
    request = urllib.request.Request(
        f"http://127.0.0.1:{config['stats_port']}{path}",
        headers={"Authorization": config["stats_secret"]},
    )
    with urllib.request.urlopen(request, timeout=3) as response:
        raw = response.read(65_537)
    if len(raw) > 65_536:
        raise ValueError("traffic stats response is too large")
    return json.loads(raw.decode("utf-8"))


def online_count(config: dict[str, Any]) -> int | None:
    try:
        value = stats_json(config, "/online")
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    counts = list(value.values())
    if not all(
        isinstance(item, int) and not isinstance(item, bool) and item >= 0
        for item in counts
    ):
        return None
    return sum(counts)


def online_line(config: dict[str, Any]) -> str:
    count = online_count(config)
    if count is None:
        return "🟢 在线　<code>暂时无法读取</code>"
    return f"🟢 在线　<b>{count}</b> 台设备"


def instance_line(config: dict[str, Any]) -> str:
    return f"🏷️ 节点　<b>{html.escape(str(config['display_name']))}</b>"


def hy2_traffic_totals(config: dict[str, Any]) -> dict[str, int] | None:
    try:
        value = stats_json(config, "/traffic")
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    upload = 0
    download = 0
    for counters in value.values():
        if not isinstance(counters, dict):
            return None
        tx = counters.get("tx")
        rx = counters.get("rx")
        if not all(
            isinstance(item, int) and not isinstance(item, bool) and item >= 0
            for item in (tx, rx)
        ):
            return None
        upload += tx
        download += rx
    return {"upload": upload, "download": download}


def valid_interface_name(value: str) -> bool:
    return (
        1 <= len(value) <= 64
        and value not in {".", "..", "lo"}
        and "/" not in value
        and "\x00" not in value
    )


def default_route_interfaces() -> set[str]:
    interfaces: set[str] = set()
    try:
        lines = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
        for line in lines:
            fields = line.split()
            if len(fields) >= 4 and fields[1] == "00000000":
                try:
                    flags = int(fields[3], 16)
                except ValueError:
                    continue
                if flags & 0x1 and valid_interface_name(fields[0]):
                    interfaces.add(fields[0])
    except OSError:
        pass
    try:
        lines = Path("/proc/net/ipv6_route").read_text(encoding="ascii").splitlines()
        for line in lines:
            fields = line.split()
            if (
                len(fields) >= 10
                and fields[0] == "0" * 32
                and fields[1] == "00"
                and valid_interface_name(fields[-1])
            ):
                interfaces.add(fields[-1])
    except OSError:
        pass
    if interfaces:
        return interfaces
    try:
        candidates = sorted(Path("/sys/class/net").iterdir(), key=lambda path: path.name)
    except OSError:
        return interfaces
    ignored_prefixes = (
        "br-",
        "docker",
        "dummy",
        "tailscale",
        "veth",
        "virbr",
        "tun",
        "tap",
        "wg",
    )
    for candidate in candidates:
        name = candidate.name
        if (
            valid_interface_name(name)
            and not name.startswith(ignored_prefixes)
            and (candidate / "statistics" / "rx_bytes").is_file()
        ):
            interfaces.add(name)
            if len(interfaces) >= MAX_INTERFACES:
                break
    return interfaces


def network_counters() -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for interface in sorted(default_route_interfaces())[:MAX_INTERFACES]:
        base = Path("/sys/class/net") / interface / "statistics"
        try:
            receive = int((base / "rx_bytes").read_text(encoding="ascii").strip())
            send = int((base / "tx_bytes").read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            continue
        if receive < 0 or send < 0:
            continue
        result[interface] = {"receive": receive, "send": send}
    return result


def counter_delta(previous: int | None, current: int) -> int:
    if previous is None:
        return 0
    if current >= previous:
        return current - previous
    # Hysteria, the VPS, or an interface restarted and reset its counter.
    return current


def day_record(state: dict[str, Any], date_value: str) -> dict[str, Any]:
    days = state["traffic"]["days"]
    record = days.get(date_value)
    if not isinstance(record, dict):
        record = empty_day()
        days[date_value] = record
    return record


def sample_traffic(
    state: dict[str, Any], config: dict[str, Any], now: float
) -> None:
    date_value = dt.datetime.fromtimestamp(now, BEIJING).date().isoformat()
    record = day_record(state, date_value)
    traffic = state["traffic"]

    current_hy2 = hy2_traffic_totals(config)
    if current_hy2 is not None:
        previous_hy2 = traffic.get("hy2_last")
        if not isinstance(previous_hy2, dict):
            previous_hy2 = {}
        record["hy2_upload"] += counter_delta(
            previous_hy2.get("upload"), current_hy2["upload"]
        )
        record["hy2_download"] += counter_delta(
            previous_hy2.get("download"), current_hy2["download"]
        )
        record["hy2_samples"] += 1
        traffic["hy2_last"] = current_hy2

    current_interfaces = network_counters()
    if current_interfaces:
        previous_interfaces = traffic.get("interfaces_last")
        if not isinstance(previous_interfaces, dict):
            previous_interfaces = {}
        for interface, current in current_interfaces.items():
            previous = previous_interfaces.get(interface)
            if not isinstance(previous, dict):
                previous = {}
            record["vps_receive"] += counter_delta(
                previous.get("receive"), current["receive"]
            )
            record["vps_send"] += counter_delta(previous.get("send"), current["send"])
        record["vps_samples"] += 1
        traffic["interfaces_last"] = current_interfaces

    current_online = online_count(config)
    if current_online is not None:
        record["peak_online"] = max(record["peak_online"], current_online)


def format_bytes(value: int) -> str:
    amount = max(0, value)
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    if amount < 1024:
        return f"{amount} B"
    unit_index = min((amount.bit_length() - 1) // 10, len(units) - 1)
    divisor = 1024**unit_index
    hundredths = (amount * 100 + divisor // 2) // divisor
    return (
        f"{hundredths // 100}.{hundredths % 100:02d} "
        f"{units[unit_index]}"
    )


def queue_message(
    state: dict[str, Any],
    key: str,
    text: str,
    now: float,
    silent: bool = False,
) -> None:
    outbox = state["outbox"]
    outbox[key] = {"text": text, "created": now, "silent": silent}
    if len(outbox) <= MAX_OUTBOX:
        return
    oldest = sorted(
        outbox,
        key=lambda item: float(outbox[item].get("created", 0)),
    )
    for item in oldest[: len(outbox) - MAX_OUTBOX]:
        del outbox[item]


def record_source(
    state: dict[str, Any], key: str, timestamp: float
) -> None:
    date_value = dt.datetime.fromtimestamp(timestamp, BEIJING).date().isoformat()
    sources = day_record(state, date_value)["sources"]
    if key in sources:
        sources[key] = nonnegative_int(sources[key]) + 1
    elif len(sources) < MAX_GROUPS:
        sources[key] = 1


def process_connection(
    state: dict[str, Any],
    config: dict[str, Any],
    remote: str,
    timestamp: float,
) -> None:
    try:
        address = parse_remote_ip(remote)
    except ValueError:
        log("忽略无法识别的客户端地址")
        return
    key, label = hidden_ip_group(address)
    record_source(state, key, timestamp)
    groups = state["groups"]
    group = groups.get(key)
    if group is None:
        group = {
            "label": label,
            "first_seen": timestamp,
            "last_seen": timestamp,
            "total": 1,
            "pending_reconnects": 0,
            "last_summary": timestamp,
        }
        groups[key] = group
        queue_message(
            state,
            f"new:{key}",
            "\n".join(
                [
                    "<b>🛡️ Hy2 新连接</b>",
                    instance_line(config),
                    "",
                    f"🌐 来源　<code>{html.escape(label)}</code>",
                    f"🕐 时间　<code>{format_time(timestamp)}</code>",
                    online_line(config),
                    "",
                    "⚠️ 如果不是本人，请立即更换 Hy2 密码",
                ]
            ),
            timestamp,
        )
    else:
        previous_last_seen = float(group.get("last_seen", timestamp))
        group["last_seen"] = timestamp
        group["total"] = int(group.get("total", 0)) + 1
        group["pending_reconnects"] = int(group.get("pending_reconnects", 0)) + 1
        if timestamp - previous_last_seen >= QUIET_RESET_SECONDS:
            queue_message(
                state,
                f"returned:{key}",
                "\n".join(
                    [
                        "<b>🛡️ Hy2 来源再次出现</b>",
                        instance_line(config),
                        "",
                        f"🌐 来源　<code>{html.escape(label)}</code>",
                        f"🕐 时间　<code>{format_time(timestamp)}</code>",
                        online_line(config),
                        "",
                        "ℹ️ 该来源超过 24 小时没有出现",
                    ]
                ),
                timestamp,
            )
            group["pending_reconnects"] = 0
            group["last_summary"] = timestamp


def queue_hourly_summaries(
    state: dict[str, Any], config: dict[str, Any], now: float
) -> None:
    for key, group in state["groups"].items():
        pending = int(group.get("pending_reconnects", 0))
        last_summary = float(group.get("last_summary", group.get("first_seen", now)))
        if pending <= 0 or now - last_summary < HOURLY_SECONDS:
            continue
        queue_message(
            state,
            f"hourly:{key}",
            "\n".join(
                [
                    "<b>🔄 Hy2 重连汇总</b>",
                    instance_line(config),
                    "",
                    f"🌐 来源　<code>{html.escape(str(group['label']))}</code>",
                    f"🕐 最近　<code>{format_time(float(group['last_seen']))}</code>",
                    f"🔁 重连　<b>{pending}</b> 次",
                    online_line(config),
                ]
            ),
            now,
        )
        group["pending_reconnects"] = 0
        group["last_summary"] = now


def aggregate_days(records: list[dict[str, Any]]) -> dict[str, Any]:
    result = empty_day()
    for record in records:
        for key in (
            "hy2_upload",
            "hy2_download",
            "vps_receive",
            "vps_send",
            "hy2_samples",
            "vps_samples",
        ):
            result[key] += nonnegative_int(record.get(key))
        result["peak_online"] = max(
            result["peak_online"], nonnegative_int(record.get("peak_online"))
        )
        sources = record.get("sources")
        if isinstance(sources, dict):
            for key, count in sources.items():
                result["sources"][key] = (
                    nonnegative_int(result["sources"].get(key))
                    + nonnegative_int(count)
                )
    return result


def records_for_month(
    state: dict[str, Any], month: str, through: str | None = None
) -> list[tuple[str, dict[str, Any]]]:
    result = []
    for date_value, record in state["traffic"]["days"].items():
        if date_value.startswith(month + "-") and (
            through is None or date_value <= through
        ):
            result.append((date_value, record))
    result.sort(key=lambda item: item[0])
    return result


def traffic_block(
    title: str,
    first_label: str,
    first_value: int,
    second_label: str,
    second_value: int,
    available: bool,
) -> list[str]:
    lines = [f"<b>{title}</b>"]
    if not available:
        lines.append("　<code>暂无可用采样</code>")
        return lines
    lines.extend(
        [
            f"{first_label}　<code>{format_bytes(first_value)}</code>",
            f"{second_label}　<code>{format_bytes(second_value)}</code>",
            f"∑ 合计　<code>{format_bytes(first_value + second_value)}</code>",
        ]
    )
    return lines


def daily_report_text(
    state: dict[str, Any], config: dict[str, Any], date_value: str
) -> str:
    record = day_record(state, date_value)
    month_records = [
        item[1] for item in records_for_month(state, date_value[:7], date_value)
    ]
    month_total = aggregate_days(month_records)
    source_count = len(record["sources"])
    connection_count = sum(nonnegative_int(item) for item in record["sources"].values())
    lines = [
        "<b>📊 Hy2 每日简报</b>",
        instance_line(config),
        f"<code>{date_value}</code> · 北京时间",
        "",
        *traffic_block(
            "🔐 Hy2 代理流量",
            "⬆️ 上传",
            record["hy2_upload"],
            "⬇️ 下载",
            record["hy2_download"],
            record["hy2_samples"] > 0,
        ),
        "",
        *traffic_block(
            "🖥️ VPS 网卡流量",
            "📥 接收",
            record["vps_receive"],
            "📤 发送",
            record["vps_send"],
            record["vps_samples"] > 0,
        ),
        "",
        f"📈 当月 Hy2　<code>{format_bytes(month_total['hy2_upload'] + month_total['hy2_download'])}</code>",
        f"🟢 峰值在线　<b>{record['peak_online']}</b> 台设备",
        f"🌐 来源网段　<b>{source_count}</b> 个",
        f"🔁 成功连接　<b>{connection_count}</b> 次",
        "",
        "ℹ️ 两类流量口径不同；云厂商面板是计费准则",
    ]
    if state.get("reporting_started_date") == date_value:
        lines.append("ℹ️ 当日数据从启用流量统计后开始")
    return "\n".join(lines)


def monthly_report_text(
    state: dict[str, Any], config: dict[str, Any], month: str
) -> str:
    records = records_for_month(state, month)
    total = aggregate_days([item[1] for item in records])
    sampled_days = [
        item
        for item in records
        if nonnegative_int(item[1].get("hy2_samples")) > 0
    ]
    hy2_total = total["hy2_upload"] + total["hy2_download"]
    daily_average = hy2_total // len(sampled_days) if sampled_days else 0
    highest_date = ""
    highest_value = 0
    for date_value, record in sampled_days:
        value = record["hy2_upload"] + record["hy2_download"]
        if value >= highest_value:
            highest_date = date_value
            highest_value = value
    lines = [
        "<b>🗓️ Hy2 月度报告</b>",
        instance_line(config),
        f"<code>{month}</code> · 北京时间",
        "",
        *traffic_block(
            "🔐 Hy2 代理流量",
            "⬆️ 上传",
            total["hy2_upload"],
            "⬇️ 下载",
            total["hy2_download"],
            total["hy2_samples"] > 0,
        ),
        "",
        *traffic_block(
            "🖥️ VPS 网卡流量",
            "📥 接收",
            total["vps_receive"],
            "📤 发送",
            total["vps_send"],
            total["vps_samples"] > 0,
        ),
        "",
        (
            f"📊 采样日均　<code>{format_bytes(daily_average)}</code>"
            if sampled_days
            else "📊 采样日均　<code>暂无数据</code>"
        ),
        (
            f"🔥 最高单日　<code>{highest_date} · {format_bytes(highest_value)}</code>"
            if sampled_days
            else "🔥 最高单日　<code>暂无数据</code>"
        ),
        f"🟢 峰值在线　<b>{total['peak_online']}</b> 台设备",
        f"🌐 来源网段　<b>{len(total['sources'])}</b> 个",
        "",
        "ℹ️ 两类流量口径不同；云厂商面板是计费准则",
    ]
    started = str(state.get("reporting_started_date", ""))
    if started.startswith(month + "-") and started != month + "-01":
        lines.append("ℹ️ 本月为启用流量统计后的部分数据")
    return "\n".join(lines)


def manual_report_text(
    state: dict[str, Any], config: dict[str, Any], now: float
) -> str:
    date_value = dt.datetime.fromtimestamp(now, BEIJING).date().isoformat()
    record = day_record(state, date_value)
    month_total = aggregate_days(
        [item[1] for item in records_for_month(state, date_value[:7], date_value)]
    )
    return "\n".join(
        [
            "<b>📈 Hy2 当前流量</b>",
            instance_line(config),
            f"<code>{format_time(now)}</code> · 北京时间",
            "",
            *traffic_block(
                "🔐 今日 Hy2",
                "⬆️ 上传",
                record["hy2_upload"],
                "⬇️ 下载",
                record["hy2_download"],
                record["hy2_samples"] > 0,
            ),
            "",
            *traffic_block(
                "🖥️ 今日 VPS",
                "📥 接收",
                record["vps_receive"],
                "📤 发送",
                record["vps_send"],
                record["vps_samples"] > 0,
            ),
            "",
            f"📅 本月 Hy2　<code>{format_bytes(month_total['hy2_upload'] + month_total['hy2_download'])}</code>",
            f"🟢 今日峰值　<b>{record['peak_online']}</b> 台设备",
            f"🌐 今日来源　<b>{len(record['sources'])}</b> 个网段",
            "",
            "ℹ️ VPS 网卡与 Hy2 统计口径不同，不能直接相减",
        ]
    )


def queue_scheduled_reports(
    state: dict[str, Any], config: dict[str, Any], now: float
) -> None:
    local = dt.datetime.fromtimestamp(now, BEIJING)
    today = local.date()
    yesterday = (today - dt.timedelta(days=1)).isoformat()
    daily_ready = (local.hour, local.minute) >= (REPORT_HOUR, REPORT_MINUTE)
    if daily_ready and state.get("last_daily_report") != yesterday:
        if str(state.get("reporting_started_date", today.isoformat())) <= yesterday:
            queue_message(
                state,
                f"daily:{yesterday}",
                daily_report_text(state, config, yesterday),
                now,
                silent=True,
            )
        state["last_daily_report"] = yesterday

    monthly_ready = (local.hour, local.minute) >= (
        REPORT_HOUR,
        MONTHLY_REPORT_MINUTE,
    )
    previous_month_date = today.replace(day=1) - dt.timedelta(days=1)
    previous_month = previous_month_date.strftime("%Y-%m")
    if monthly_ready and state.get("last_monthly_report") != previous_month:
        started = str(state.get("reporting_started_date", today.isoformat()))
        if (
            records_for_month(state, previous_month)
            or started <= previous_month_date.isoformat()
        ):
            queue_message(
                state,
                f"monthly:{previous_month}",
                monthly_report_text(state, config, previous_month),
                now,
                silent=True,
            )
        state["last_monthly_report"] = previous_month


def queue_manual_report(
    state: dict[str, Any], config: dict[str, Any], now: float
) -> None:
    queue_message(
        state,
        f"manual:{int(now)}",
        manual_report_text(state, config, now),
        now,
    )


def prune_traffic_days(state: dict[str, Any], now: float) -> None:
    cutoff = (
        dt.datetime.fromtimestamp(now, BEIJING).date()
        - dt.timedelta(days=TRAFFIC_DAY_RETENTION)
    ).isoformat()
    days = state["traffic"]["days"]
    for date_value in list(days):
        if date_value < cutoff:
            del days[date_value]
    if len(days) > TRAFFIC_DAY_RETENTION:
        for date_value in sorted(days)[: len(days) - TRAFFIC_DAY_RETENTION]:
            del days[date_value]


def prune_state(state: dict[str, Any], now: float) -> None:
    groups = state["groups"]
    expired = [
        key
        for key, group in groups.items()
        if now - float(group.get("last_seen", 0)) > PRUNE_AFTER_SECONDS
    ]
    for key in expired:
        del groups[key]
    if len(groups) > MAX_GROUPS:
        oldest = sorted(groups, key=lambda key: float(groups[key].get("last_seen", 0)))
        for key in oldest[: len(groups) - MAX_GROUPS]:
            del groups[key]


def flush_outbox(
    state: dict[str, Any],
    config: dict[str, Any],
    retry_after: float,
) -> float:
    now = time.time()
    if now < retry_after or not state["outbox"]:
        return retry_after
    ordered = sorted(
        state["outbox"],
        key=lambda key: float(state["outbox"][key].get("created", 0)),
    )
    sent = 0
    for key in ordered:
        try:
            item = state["outbox"][key]
            send_message(
                config,
                str(item["text"]),
                silent=bool(item.get("silent", False)),
            )
        except Exception as exc:  # Telegram/network errors must not stop Hysteria.
            log(f"Telegram 发送失败，将在 5 分钟后重试：{type(exc).__name__}")
            return now + 300
        del state["outbox"][key]
        sent += 1
        if sent >= 3:
            break
    atomic_write_json(state_path, state)
    return now + (2 if state["outbox"] else 0)


def start_journal(use_saved_cursor: bool = True) -> tuple[subprocess.Popen[bytes], bool]:
    args = [
        "/usr/bin/journalctl",
        "--no-pager",
        "--follow",
        "--output=json",
        "--unit=hysteria-server.service",
    ]
    cursor = ""
    if use_saved_cursor:
        try:
            cursor = cursor_path.read_text(encoding="utf-8").strip()
        except FileNotFoundError:
            pass
    if cursor:
        args.append(f"--after-cursor={cursor}")
    else:
        args.append("--since=now")
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=None,
        text=False,
        bufsize=0,
    )
    if process.stdout is None:
        raise RuntimeError("journalctl stdout is unavailable")
    os.set_blocking(process.stdout.fileno(), False)
    return process, bool(cursor)


def drain_journal(
    process: subprocess.Popen[bytes], buffer: bytes
) -> tuple[bytes, list[dict[str, Any]], bool]:
    if process.stdout is None:
        raise RuntimeError("journalctl stdout is unavailable")
    entries: list[dict[str, Any]] = []
    eof = False
    while True:
        try:
            chunk = os.read(process.stdout.fileno(), 65536)
        except BlockingIOError:
            break
        if not chunk:
            eof = True
            break
        buffer += chunk
        while b"\n" in buffer:
            raw, buffer = buffer.split(b"\n", 1)
            if not raw:
                continue
            try:
                entry = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(entry, dict):
                entries.append(entry)
        if len(buffer) > MAX_JOURNAL_BUFFER:
            raise RuntimeError("journalctl produced an oversized unterminated record")
    return buffer, entries, eof


manual_report_requested = False


def request_manual_report(_signum: int, _frame: Any) -> None:
    global manual_report_requested
    manual_report_requested = True


def main() -> int:
    global manual_report_requested
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    config = load_config()
    state = load_state()
    signal.signal(signal.SIGUSR1, request_manual_report)
    now = time.time()
    sample_traffic(state, config, now)
    atomic_write_json(state_path, state)
    next_sample = now + TRAFFIC_SAMPLE_SECONDS
    process, cursor_used = start_journal()
    journal_buffer = b""
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    retry_after = 0.0

    while True:
        events = selector.select(timeout=TICK_SECONDS)
        if events:
            journal_buffer, entries, eof = drain_journal(process, journal_buffer)
            for entry in entries:
                connection = extract_connection(entry)
                if connection is not None:
                    process_connection(state, config, *connection)
                cursor = entry.get("__CURSOR")
                if isinstance(cursor, str) and cursor:
                    atomic_write_text(cursor_path, cursor + "\n")
                atomic_write_json(state_path, state)
            if eof and process.poll() is not None:
                selector.unregister(process.stdout)
                process.stdout.close()
                if cursor_used:
                    log("保存的 journal 游标已失效，改为从当前日志位置继续。")
                    cursor_path.unlink(missing_ok=True)
                    process, cursor_used = start_journal(use_saved_cursor=False)
                    journal_buffer = b""
                    selector.register(process.stdout, selectors.EVENT_READ)
                else:
                    raise RuntimeError(
                        f"journalctl exited with status {process.returncode}"
                    )

        now = time.time()
        if now >= next_sample or manual_report_requested:
            sample_traffic(state, config, now)
            next_sample = now + TRAFFIC_SAMPLE_SECONDS
        if manual_report_requested:
            queue_manual_report(state, config, now)
            manual_report_requested = False
        queue_hourly_summaries(state, config, now)
        queue_scheduled_reports(state, config, now)
        prune_state(state, now)
        prune_traffic_days(state, now)
        atomic_write_json(state_path, state)
        retry_after = flush_outbox(state, config, retry_after)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(0)
    except Exception as exc:
        log(f"提醒服务退出：{type(exc).__name__}: {exc}")
        raise SystemExit(1)
PY
  chmod 0755 "$tmp"
  chown root:root "$tmp"
  mv -f -- "$tmp" "$NOTIFIER_PATH"
}

write_notifier_unit() {
  cat >"$NOTIFIER_SERVICE_PATH" <<EOF
[Unit]
Description=Telegram alerts and traffic reports for Hysteria 2
Documentation=https://core.telegram.org/bots/api
Requires=hysteria-server.service
PartOf=hysteria-server.service
After=hysteria-server.service network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${NOTIFIER_PATH}
Restart=on-failure
RestartSec=15s
DynamicUser=yes
SupplementaryGroups=systemd-journal
StateDirectory=hy2-safe-notifier
StateDirectoryMode=0700
LoadCredential=telegram-config:${NOTIFIER_CONFIG_PATH}
UMask=0077

NoNewPrivileges=true
CapabilityBoundingSet=
LockPersonality=true
MemoryDenyWriteExecute=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
# journalctl needs /proc/sys/kernel/random/boot_id; ProcSubset=pid would hide it.
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$NOTIFIER_SERVICE_PATH"
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
ExecStartPre=+${MANAGER_PATH} verify-service-account
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
ProtectProc=invisible
ProcSubset=pid
ProtectSystem=strict
ReadOnlyPaths=${CONFIG_DIR}
ReadWritePaths=${STATE_DIR}
MemoryDenyWriteExecute=true
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
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProcSubset=pid
ProtectSystem=strict
ReadWritePaths=/usr/local/bin /run/lock
MemoryDenyWriteExecute=true
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

  cat >"$HEALTH_SERVICE_PATH" <<EOF
[Unit]
Description=Check the Hysteria 2 ACME certificate
OnFailure=hy2-safe-health-alert.service

[Service]
Type=oneshot
ExecStart=${MANAGER_PATH} certificate-check --quiet --systemd-probe
UMask=0077
NoNewPrivileges=true
# CertMagic intentionally stores ACME directories as 0700 and certificates as
# 0600 under the unprivileged hysteria account. The checker runs as root but
# needs this read-only capability after systemd drops every other capability.
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_DAC_READ_SEARCH
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProcSubset=pid
ProtectSystem=strict
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_UNIX
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
EOF

  cat >"$HEALTH_ALERT_SERVICE_PATH" <<EOF
[Unit]
Description=Send a Telegram alert for a failed Hy2 certificate check
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=${MANAGER_PATH} certificate-alert --quiet
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProcSubset=pid
ProtectSystem=strict
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
EOF

  cat >"$HEALTH_TIMER_PATH" <<'EOF'
[Unit]
Description=Daily Hysteria 2 certificate health check

[Timer]
OnCalendar=*-*-* 09:00
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF

  write_notifier_script
  write_notifier_unit
  chmod 0644 \
    "$SERVICE_PATH" \
    "$UPDATE_SERVICE_PATH" \
    "$UPDATE_TIMER_PATH" \
    "$HEALTH_SERVICE_PATH" \
    "$HEALTH_ALERT_SERVICE_PATH" \
    "$HEALTH_TIMER_PATH"
  systemctl daemon-reload
}

configure_update_timer() {
  if [[ "$AUTO_UPDATE" -eq 1 ]]; then
    systemctl enable --now "$TIMER_NAME"
  else
    systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
  fi
}

configure_health_timer() {
  systemctl enable --now "$HEALTH_TIMER_NAME"
}

refresh_managed_runtime() {
  require_systemd
  install_dependencies
  load_existing_settings || die "请先安装 Hy2。"
  exec 8>"$LOCK_PATH"
  flock -n 8 || die "另一个 hy2-safe 任务正在运行。"
  ensure_service_user_and_directories
  install_manager_copy
  write_systemd_units
  flock -u 8
  configure_update_timer
  configure_health_timer
  info "管理脚本、服务账号权限和 systemd 单元已同步到当前版本。"
}

discover_telegram_chats() {
  local token_file="$1"
  local candidates_file="$2"
  local pairing_code="$3"
  python3 - "$token_file" "$candidates_file" "$pairing_code" <<'PY'
import datetime as dt
import json
import sys
import urllib.parse
import urllib.request

token_path, candidates_path, pairing_code = sys.argv[1:]
token = open(token_path, "r", encoding="utf-8").read().strip()


def call(method, fields=None):
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = urllib.parse.urlencode(fields or {}).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(1_048_577)
    except Exception as exc:
        raise SystemExit(f"Telegram API 连接失败：{type(exc).__name__}") from None
    if len(raw) > 1_048_576:
        raise SystemExit("Telegram API 响应异常过大")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit("Telegram API 返回了无效响应") from None
    if not result.get("ok"):
        description = str(result.get("description", "请求被拒绝"))
        raise SystemExit(f"Telegram API 错误：{description[:200]}")
    return result.get("result")


bot = call("getMe")
username = bot.get("username", "未知")
print(f"机器人验证成功：@{username}")
updates = call(
    "getUpdates",
    {
        "limit": "100",
        "timeout": "0",
        "allowed_updates": json.dumps(["message"], separators=(",", ":")),
    },
)
chats = {}
for update in updates:
    message = update.get("message")
    if not isinstance(message, dict):
        continue
    if message.get("text") != pairing_code:
        continue
    chat = message.get("chat")
    if not isinstance(chat, dict) or chat.get("type") != "private":
        continue
    chat_id = chat.get("id")
    if not isinstance(chat_id, int) or chat_id <= 0:
        continue
    name = " ".join(
        str(chat.get(key, "")).strip() for key in ("first_name", "last_name")
    ).strip()
    username = str(chat.get("username", "")).strip()
    date = message.get("date")
    when = ""
    if isinstance(date, int):
        timezone = dt.timezone(dt.timedelta(hours=8))
        when = dt.datetime.fromtimestamp(date, timezone).strftime("%Y-%m-%d %H:%M:%S")
    chats[str(chat_id)] = {
        "id": str(chat_id),
        "name": "".join(ch for ch in name if ch.isprintable())[:80],
        "username": "".join(ch for ch in username if ch.isprintable())[:80],
        "time": when,
    }

with open(candidates_path, "w", encoding="utf-8") as handle:
    json.dump(sorted(chats.values(), key=lambda item: item["id"]), handle)

if not chats:
    raise SystemExit(
        "没有找到发送了本次一次性配对码的私人聊天。"
        "请确认消息发给了正确机器人，并重新运行设置。"
    )

if len(chats) != 1:
    raise SystemExit("一次性配对码对应多个私人聊天，拒绝自动绑定；请重新运行设置。")

print("已通过一次性配对码找到私人聊天：")
for item in sorted(chats.values(), key=lambda value: value["id"]):
    identity = item["name"] or "未显示姓名"
    if item["username"]:
        identity += f" (@{item['username']})"
    print(f"  Chat ID {item['id']}  {identity}  最近消息：{item['time'] or '未知'}")
PY
}

read_discovered_chat_id() {
  local candidates_file="$1"
  python3 - "$candidates_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    candidates = json.load(handle)
if len(candidates) != 1:
    raise SystemExit(1)
chat_id = str(candidates[0].get("id", ""))
if not chat_id.isdigit() or int(chat_id) <= 0:
    raise SystemExit(1)
print(chat_id)
PY
}

telegram_send_test() {
  local token_file="$1"
  local chat_id="$2"
  local display_name="$3"
  python3 - "$token_file" "$chat_id" "$display_name" <<'PY'
import html
import json
import sys
import urllib.parse
import urllib.request

token = open(sys.argv[1], "r", encoding="utf-8").read().strip()
chat_id = sys.argv[2]
display_name = sys.argv[3]
url = f"https://api.telegram.org/bot{token}/sendMessage"
data = urllib.parse.urlencode(
    {
        "chat_id": chat_id,
        "text": (
            "<b>✅ hy2-safe 验证成功</b>\n\n"
            f"🏷️ 节点　<b>{html.escape(display_name)}</b>\n\n"
            "连接提醒、流量日报和月报将发送到此私人聊天。"
        ),
        "parse_mode": "HTML",
        "protect_content": "true",
    }
).encode("utf-8")
request = urllib.request.Request(url, data=data, method="POST")
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(1_048_577)
except Exception as exc:
    raise SystemExit(f"Telegram 测试消息发送失败：{type(exc).__name__}") from None
if len(raw) > 1_048_576:
    raise SystemExit("Telegram API 响应异常过大")
try:
    result = json.loads(raw.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit("Telegram API 返回了无效响应") from None
if not result.get("ok"):
    description = str(result.get("description", "请求被拒绝"))
    raise SystemExit(f"Telegram 测试消息被拒绝：{description[:200]}")
message = result.get("result")
actual_chat = str(message.get("chat", {}).get("id", ""))
if actual_chat != chat_id:
    raise SystemExit("Telegram 返回的 Chat ID 与设置不一致")
PY
}

write_telegram_config() {
  local token_file="$1"
  local tmp
  tmp="$(mktemp "${CONFIG_DIR}/.telegram-notifier.XXXXXX")"
  if ! python3 - \
    "$token_file" \
    "$TELEGRAM_CHAT_ID" \
    "$TELEGRAM_STATS_PORT" \
    "$TELEGRAM_STATS_SECRET" \
    "$TELEGRAM_NAME" \
    "$tmp" <<'PY'
import json
import sys

token_path, chat_id, stats_port, stats_secret, display_name, output_path = sys.argv[1:]
token = open(token_path, "r", encoding="utf-8").read().strip()
value = {
    "token": token,
    "chat_id": chat_id,
    "stats_port": int(stats_port),
    "stats_secret": stats_secret,
    "display_name": display_name,
}
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(value, handle, separators=(",", ":"))
    handle.write("\n")
PY
  then
    rm -f -- "$tmp"
    return 1
  fi
  if ! chown root:root "$tmp" ||
    ! chmod 0600 "$tmp" ||
    ! mv -f -- "$tmp" "$NOTIFIER_CONFIG_PATH"; then
    rm -f -- "$tmp"
    return 1
  fi
}

sync_telegram_name_config() {
  local tmp
  validate_telegram_name "$TELEGRAM_NAME" ||
    return 1
  tmp="$(mktemp "${CONFIG_DIR}/.telegram-notifier.XXXXXX")"
  if ! python3 - "$NOTIFIER_CONFIG_PATH" "$TELEGRAM_NAME" "$tmp" <<'PY'
import json
import sys

source_path, display_name, output_path = sys.argv[1:]
with open(source_path, "r", encoding="utf-8") as handle:
    value = json.load(handle)
if not isinstance(value, dict):
    raise SystemExit("Telegram config root must be an object")
value["display_name"] = display_name
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(value, handle, ensure_ascii=False, separators=(",", ":"))
    handle.write("\n")
PY
  then
    rm -f -- "$tmp"
    return 1
  fi
  if ! chown root:root "$tmp" ||
    ! chmod 0600 "$tmp" ||
    ! mv -f -- "$tmp" "$NOTIFIER_CONFIG_PATH"; then
    rm -f -- "$tmp"
    return 1
  fi
}

stored_telegram_send_test() {
  python3 - "$NOTIFIER_CONFIG_PATH" <<'PY'
import html
import json
import sys
import urllib.parse
import urllib.request

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    config = json.load(handle)
token = config["token"]
chat_id = str(config["chat_id"])
display_name = str(config.get("display_name", "Hy2 节点"))
url = f"https://api.telegram.org/bot{token}/sendMessage"
data = urllib.parse.urlencode(
    {
        "chat_id": chat_id,
        "text": (
            "<b>✅ hy2-safe 通知正常</b>\n\n"
            f"🏷️ 节点　<b>{html.escape(display_name)}</b>\n\n"
            "连接提醒与流量统计服务可以向此私人聊天发送消息。"
        ),
        "parse_mode": "HTML",
        "protect_content": "true",
    }
).encode("utf-8")
request = urllib.request.Request(url, data=data, method="POST")
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(1_048_577)
except Exception as exc:
    raise SystemExit(f"Telegram 测试失败：{type(exc).__name__}") from None
if len(raw) > 1_048_576:
    raise SystemExit("Telegram API 响应异常过大")
try:
    result = json.loads(raw.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit("Telegram API 返回了无效响应") from None
if not result.get("ok"):
    description = str(result.get("description", "请求被拒绝"))
    raise SystemExit(f"Telegram 测试被拒绝：{description[:200]}")
PY
}

send_telegram_system_event() {
  local event="$1"
  local detail="${2:-}"
  [[ -f "$NOTIFIER_CONFIG_PATH" && ! -L "$NOTIFIER_CONFIG_PATH" ]] || return 0
  [[ "$(stat -c '%u:%a' -- "$NOTIFIER_CONFIG_PATH" 2>/dev/null || true)" == "0:600" ]] ||
    return 0
  python3 - "$NOTIFIER_CONFIG_PATH" "$event" "$detail" <<'PY'
import html
import json
import sys
import urllib.parse
import urllib.request

config_path, event, detail = sys.argv[1:]
with open(config_path, "r", encoding="utf-8") as handle:
    config = json.load(handle)
token = config["token"]
chat_id = str(config["chat_id"])
display_name = html.escape(str(config.get("display_name", "Hy2 节点")))
messages = {
    "update-failed": (
        "<b>❌ Hysteria 自动更新失败</b>",
        "本次更新没有完成；原服务会保持或尝试回滚到旧版本。\n"
        "请登录 VPS 运行 <code>systemctl status hy2-safe-update.service</code>。",
        False,
    ),
    "update-success": (
        "<b>✅ Hysteria 更新完成</b>",
        f"当前核心版本　<code>{html.escape(detail)}</code>",
        True,
    ),
    "certificate-warning": (
        "<b>⚠️ Hy2 证书需要检查</b>",
        html.escape(detail) if detail else (
            "没有找到与节点域名匹配且有效期超过 21 天的证书。\n"
            "请检查 Hysteria 服务日志。"
        ),
        False,
    ),
}
if event not in messages:
    raise SystemExit("unsupported system event")
title, body, silent = messages[event]
text = "\n".join([title, f"🏷️ 节点　<b>{display_name}</b>", "", body])
url = f"https://api.telegram.org/bot{token}/sendMessage"
data = urllib.parse.urlencode(
    {
        "chat_id": chat_id,
        "text": text[:4096],
        "parse_mode": "HTML",
        "disable_notification": "true" if silent else "false",
        "protect_content": "true",
    }
).encode("utf-8")
request = urllib.request.Request(url, data=data, method="POST")
try:
    with urllib.request.urlopen(request, timeout=15) as response:
        raw = response.read(1_048_577)
except Exception:
    raise SystemExit(1) from None
if len(raw) > 1_048_576:
    raise SystemExit(1)
try:
    result = json.loads(raw.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit(1) from None
if not result.get("ok"):
    raise SystemExit(1)
PY
}

certificate_matches_domain() {
  local certificate="$1"
  local domain="$2"
  openssl x509 -in "$certificate" -noout -checkhost "$domain" >/dev/null 2>&1
}

certificate_valid_beyond() {
  local certificate="$1"
  local seconds="$2"
  openssl x509 -in "$certificate" -noout -checkend "$seconds" >/dev/null 2>&1
}

certificate_acme_hint() {
  case "${ACME_TYPE:-http}" in
    http)
      printf '当前使用 HTTP-01；请检查域名灰云解析、入站 TCP 80 和 Hysteria 日志。'
      ;;
    tls)
      printf '当前使用 TLS-ALPN-01；请检查域名灰云解析、入站 TCP 443 和 Hysteria 日志。'
      ;;
    dns)
      printf '当前使用 Cloudflare DNS-01，不需要入站 TCP 80/443；请检查 Token、Zone 权限和 Hysteria 日志。'
      ;;
    *)
      printf '请检查域名解析和 Hysteria 日志。'
      ;;
  esac
}

command_certificate_check() {
  local certificate quiet=0 systemd_probe=0 matching=0 healthy=0 warning_detail acme_hint
  local -a certificates=()
  require_root
  load_existing_settings || die "请先安装 Hy2。"
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --quiet)
        quiet=1
        QUIET=1
        shift
        ;;
      --systemd-probe)
        systemd_probe=1
        shift
        ;;
      -h | --help)
        printf '用法：hy2-safe certificate-check [--quiet]\n'
        return
        ;;
      *) die "certificate-check 的未知选项：$1" ;;
    esac
  done

  if [[ -d "${STATE_DIR}/acme" && ! -L "${STATE_DIR}/acme" ]]; then
    mapfile -d '' -t certificates < <(
      find "${STATE_DIR}/acme" -xdev -type f -name '*.crt' -print0 2>/dev/null
    )
  fi
  for certificate in "${certificates[@]}"; do
    if certificate_matches_domain "$certificate" "$DOMAIN"; then
      matching=1
      if certificate_valid_beyond "$certificate" 1814400; then
        healthy=1
        break
      fi
    fi
  done

  if [[ "$healthy" -eq 1 ]]; then
    [[ "$quiet" -eq 1 ]] || info "ACME 证书与 ${DOMAIN} 匹配，且有效期超过 21 天。"
    return
  fi
  if [[ "$matching" -eq 1 ]]; then
    warn "与 ${DOMAIN} 匹配的证书将在 21 天内到期或已经到期。"
    warning_detail="已找到与 ${DOMAIN} 匹配的证书，但它将在 21 天内到期或已经到期。"
  else
    warn "没有找到与 ${DOMAIN} 匹配的 ACME 证书。"
    warning_detail="没有在本机 ACME 缓存中找到与 ${DOMAIN} 匹配的证书。"
  fi
  acme_hint="$(certificate_acme_hint)"
  warning_detail+=$'\n'
  warning_detail+="${acme_hint}"
  if [[ "$systemd_probe" -eq 1 ]]; then
    return 1
  fi
  send_telegram_system_event certificate-warning "$warning_detail" || true
}

command_certificate_alert() {
  local quiet=0 warning_detail acme_hint
  require_root
  load_existing_settings || die "请先安装 Hy2。"
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --quiet)
        quiet=1
        QUIET=1
        shift
        ;;
      *) die "certificate-alert 的未知选项：$1" ;;
    esac
  done
  acme_hint="$(certificate_acme_hint)"
  warning_detail="本机证书健康检查未通过。"
  warning_detail+=$'\n'
  warning_detail+="${acme_hint}"
  send_telegram_system_event certificate-warning "$warning_detail" || true
  [[ "$quiet" -eq 1 ]] || warn "$warning_detail"
}

configure_notifier_service() {
  if [[ "${TELEGRAM_ENABLED:-0}" -eq 1 ]]; then
    if [[ ! -f "$NOTIFIER_CONFIG_PATH" ]]; then
      warn "Telegram 凭据文件不存在，提醒服务未启动。"
      systemctl disable --now "$NOTIFIER_NAME" >/dev/null 2>&1 || true
      return 1
    fi
    validate_root_secret_file "$NOTIFIER_CONFIG_PATH" "Telegram 凭据文件"
    sync_telegram_name_config || return 1
    systemctl enable "$NOTIFIER_NAME" || return 1
    systemctl restart "$NOTIFIER_NAME" || return 1
    wait_for_unit "$NOTIFIER_NAME"
  else
    systemctl disable --now "$NOTIFIER_NAME" >/dev/null 2>&1 || true
  fi
}

parse_config_options() {
  NON_INTERACTIVE=0
  ACME_TYPE_WAS_SET=0
  CLOUDFLARE_TOKEN_WAS_SET=0
  PORT_MODE_WAS_SET=0
  PORT_VALUE_WAS_SET=0
  MASQUERADE_WAS_SET=0
  AUTO_UPDATE_WAS_SET=0
  TELEGRAM_NAME_WAS_SET=0

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
      --acme-type)
        [[ "$#" -ge 2 ]] || die "--acme-type 缺少参数。"
        ACME_TYPE="${2,,}"
        ACME_TYPE_WAS_SET=1
        shift 2
        ;;
      --cloudflare-token-file)
        [[ "$#" -ge 2 ]] || die "--cloudflare-token-file 缺少参数。"
        validate_cloudflare_token_file "$2"
        CLOUDFLARE_API_TOKEN="$(head -n 1 -- "$2" | tr -d '\r\n')"
        CLOUDFLARE_TOKEN_WAS_SET=1
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
      --telegram-name)
        [[ "$#" -ge 2 ]] || die "--telegram-name 缺少参数。"
        TELEGRAM_NAME="$2"
        TELEGRAM_NAME_WAS_SET=1
        shift 2
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
  warn "下面会显示完整 Hy2 密码和分享链接；不要截图、录屏或发送到群聊/公开仓库。"
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
auth: "${PASSWORD}"
tls:
  sni: ${DOMAIN}
congestion:
  type: bbr
  bbrProfile: conservative
${transport_config}
socks5:
  listen: 127.0.0.1:1080

${share_output}

需要放行的 UDP 端口：${firewall_ports}
EOF
}

command_install() {
  local install_arg acme_requirement
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
    ACME_TYPE="http"
    CLOUDFLARE_API_TOKEN=""
    PORT="443"
    PORT_MODE="range"
    HOP_START="50000"
    HOP_END="50500"
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
    TELEGRAM_NAME=""
  fi
  parse_config_options "$@"
  [[ -n "$TELEGRAM_NAME" ]] || TELEGRAM_NAME="${DOMAIN:-Hy2 节点}"
  prompt_install_values "$NON_INTERACTIVE"
  validate_install_values
  ensure_port_hopping_backend
  preflight_domain
  [[ "$ACME_TYPE" != "dns" ]] || verify_cloudflare_token_access
  preflight_ports
  case "$ACME_TYPE" in
    http) acme_requirement="TCP 80" ;;
    tls) acme_requirement="TCP 443" ;;
    dns) acme_requirement="Cloudflare DNS-01（不需要入站 TCP 80/443）" ;;
  esac

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
  configure_health_timer

  systemctl enable "$SERVICE_NAME"
  if ! systemctl restart "$SERVICE_NAME" || ! wait_for_service; then
    journalctl --no-pager -n 40 -u "$SERVICE_NAME" >&2 || true
    die "Hysteria 服务启动失败。请检查域名解析、${acme_requirement}、UDP 端口和服务日志。"
  fi
  if [[ "$TELEGRAM_ENABLED" -eq 1 ]]; then
    configure_notifier_service ||
      warn "Hysteria 正常运行，但 Telegram 提醒服务启动失败；请运行 hy2-safe telegram-logs。"
  fi

  info "安装完成，服务已作为非特权用户 hysteria 运行。"
  printf '\n'
  show_client
  if [[ "$ACME_TYPE" == "dns" ]]; then
    if [[ "$PORT_MODE" == "range" ]]; then
      printf '\n请确认防火墙/安全组已放行：UDP %s-%s。DNS-01 不需要放行入站 TCP 80/443。\n' \
        "$HOP_START" "$HOP_END"
    else
      printf '\n请确认防火墙/安全组已放行：UDP %s。DNS-01 不需要放行入站 TCP 80/443。\n' \
        "$PORT"
    fi
  elif [[ "$PORT_MODE" == "range" ]]; then
    printf '\n请确认防火墙/安全组已放行：UDP %s-%s，以及 ACME 所需的 %s。\n' \
      "$HOP_START" "$HOP_END" "$acme_requirement"
  else
    printf '\n请确认防火墙/安全组已放行：UDP %s，以及 ACME 所需的 %s。\n' \
      "$PORT" "$acme_requirement"
  fi
  if [[ "$NON_INTERACTIVE" -eq 0 && "$TELEGRAM_ENABLED" -eq 0 ]]; then
    printf '\nTelegram 提醒是可选功能；设置失败不会影响已经运行的 Hy2。\n'
    if prompt_yes_no "是否现在开启 Telegram 成功连接提醒？" no; then
      cleanup
      TMP_ROOT=""
      flock -u 9
      command_telegram_setup
    else
      printf '已跳过。以后需要时可运行：hy2-safe telegram-setup\n'
    fi
  fi
}

command_configure() {
  local old_auto_update old_udp_start="" old_udp_end=""
  require_root
  require_systemd
  load_existing_settings || die "请先执行 install。"
  old_auto_update="$AUTO_UPDATE"
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    if [[ "$PORT_MODE" == "range" ]]; then
      old_udp_start="$HOP_START"
      old_udp_end="$HOP_END"
    else
      old_udp_start="$PORT"
      old_udp_end="$PORT"
    fi
  fi
  parse_config_options "$@"
  prompt_install_values "$NON_INTERACTIVE"
  validate_install_values
  ensure_port_hopping_backend
  preflight_domain
  [[ "$ACME_TYPE" != "dns" ]] || verify_cloudflare_token_access
  preflight_ports "$old_udp_start" "$old_udp_end"

  exec 9>"$LOCK_PATH"
  flock -n 9 || die "另一个 hy2-safe 任务正在运行。"

  ensure_service_user_and_directories
  TMP_ROOT="$(mktemp -d /tmp/hy2-safe.XXXXXXXX)"
  cp --preserve=mode,ownership,timestamps -- "$CONFIG_PATH" "${TMP_ROOT}/config.yaml"
  cp --preserve=mode,ownership,timestamps -- "$SETTINGS_PATH" "${TMP_ROOT}/hy2-safe.env"
  cp --preserve=mode,ownership,timestamps -- "$SERVICE_PATH" "${TMP_ROOT}/hysteria-server.service"
  install_manager_copy
  write_config
  save_settings
  write_systemd_units
  configure_update_timer
  configure_health_timer
  if ! systemctl restart "$SERVICE_NAME" || ! wait_for_service; then
    warn "新配置启动失败，正在恢复上一份配置。"
    cp --preserve=mode,ownership,timestamps -- "${TMP_ROOT}/config.yaml" "$CONFIG_PATH"
    cp --preserve=mode,ownership,timestamps -- "${TMP_ROOT}/hy2-safe.env" "$SETTINGS_PATH"
    cp --preserve=mode,ownership,timestamps -- \
      "${TMP_ROOT}/hysteria-server.service" "$SERVICE_PATH"
    systemctl daemon-reload
    AUTO_UPDATE="$old_auto_update"
    configure_update_timer
    configure_health_timer
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
  load_existing_settings || die "恢复 Telegram 变更后无法重新读取原设置。"
  TELEGRAM_ENABLED="$old_enabled"
  configure_notifier_service >/dev/null 2>&1 || true
}

command_telegram_setup() {
  local token_input_file=""
  local requested_chat_id=""
  local name_was_set=0
  local token_file candidates_file old_enabled pairing_code confirmation answer
  require_root
  require_systemd
  install_dependencies
  load_existing_settings || die "请先安装 Hy2，再运行 telegram-setup。"
  install_manager_copy

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
      --name)
        [[ "$#" -ge 2 ]] || die "--name 缺少参数。"
        TELEGRAM_NAME="$2"
        name_was_set=1
        shift 2
        ;;
      -h | --help)
        printf '用法：hy2-safe telegram-setup [--token-file FILE --chat-id ID --name NAME]\n'
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
  ensure_service_user_and_directories
  TMP_ROOT="$(mktemp -d /tmp/hy2-safe.XXXXXXXX)"
  token_file="${TMP_ROOT}/telegram-token"
  candidates_file="${TMP_ROOT}/telegram-candidates.json"

  if [[ -n "$token_input_file" ]]; then
    head -n 1 -- "$token_input_file" | tr -d '\r\n' >"$token_file"
  else
    printf '请先通过 Telegram 的 @BotFather 创建机器人。\n'
    prompt_secret "请输入 Bot Token（输入时不会显示）: " TELEGRAM_BOT_TOKEN
    printf '%s' "$TELEGRAM_BOT_TOKEN" >"$token_file"
    unset TELEGRAM_BOT_TOKEN
  fi
  chmod 0600 "$token_file"
  validate_telegram_token "$(cat "$token_file")" ||
    die "Bot Token 格式无效。"

  if [[ -z "$requested_chat_id" ]]; then
    prompt_input "私人 Chat ID [知道请直接输入；不知道请直接回车使用一次性配对码]: " requested_chat_id
    if [[ -n "$requested_chat_id" ]]; then
      validate_telegram_chat_id "$requested_chat_id" ||
        die "Chat ID 必须是私人聊天的正整数。"
    else
      pairing_code="HY2-$(openssl rand -hex 8)"
      printf '请在 Telegram 私聊机器人中发送下面这段一次性配对码：\n\n%s\n\n' "$pairing_code"
      prompt_input "确认配对码已经成功发送后，请直接回车继续: " confirmation
      discover_telegram_chats "$token_file" "$candidates_file" "$pairing_code"
      requested_chat_id="$(read_discovered_chat_id "$candidates_file")" ||
        die "无法安全确定唯一的私人 Chat ID。"
      validate_telegram_chat_id "$requested_chat_id" ||
        die "Telegram 返回了无效的私人 Chat ID。"
    fi
  fi

  if [[ "$name_was_set" -eq 0 && -t 0 ]]; then
    prompt_input "Telegram 消息名称 [直接回车默认：${TELEGRAM_NAME}]: " answer
    [[ -z "$answer" ]] || TELEGRAM_NAME="$answer"
  fi
  validate_telegram_name "$TELEGRAM_NAME" ||
    die "Telegram 消息名称必须是 1-64 个可见字符，且首尾不能有空格。"

  info "发送 Telegram 测试消息。"
  telegram_send_test "$token_file" "$requested_chat_id" "$TELEGRAM_NAME"
  if [[ -t 0 && -z "$token_input_file" ]]; then
    prompt_input "请确认自己的 Telegram 已收到测试消息；确认请输入 YES: " confirmation
    [[ "$confirmation" == "YES" ]] ||
      die "未确认收到测试消息，未保存 Telegram 配置。"
  fi

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

  info "Telegram 提醒已启用，消息名称为【${TELEGRAM_NAME}】，只会向 Chat ID ${TELEGRAM_CHAT_ID} 主动发送消息。"
  printf '规则：新 IP 网段立即提醒；相同网段一小时内合并；北京时间每天 08:00 静默发送前一日日报，每月 1 日 08:05 静默发送上月月报。\n'
}

command_telegram_replace() {
  require_root
  load_existing_settings || die "请先安装 Hy2。"
  [[ "$TELEGRAM_ENABLED" -eq 1 && -f "$NOTIFIER_CONFIG_PATH" ]] ||
    die "Telegram 提醒尚未启用，请选择 '添加 Telegram 通知'。"
  info "新机器人通过 Token、Chat ID 和测试消息验证后才会替换旧机器人；失败时保留旧配置。"
  command_telegram_setup "$@"
}

command_telegram_add() {
  require_root
  load_existing_settings || die "请先安装 Hy2。"
  [[ "$TELEGRAM_ENABLED" -eq 0 ]] ||
    die "Telegram 提醒已经启用；如需更换 Token，请选择 '更换 Telegram 机器人'。"
  command_telegram_setup
}

command_telegram_test() {
  require_root
  load_existing_settings || die "请先安装 Hy2。"
  [[ "$TELEGRAM_ENABLED" -eq 1 && -f "$NOTIFIER_CONFIG_PATH" ]] ||
    die "Telegram 提醒尚未启用。"
  validate_root_secret_file "$NOTIFIER_CONFIG_PATH" "Telegram 凭据文件"
  stored_telegram_send_test
  info "Telegram 测试消息发送成功。"
}

command_telegram_report() {
  require_root
  require_systemd
  load_existing_settings || die "请先安装 Hy2。"
  [[ "$TELEGRAM_ENABLED" -eq 1 && -f "$NOTIFIER_CONFIG_PATH" ]] ||
    die "Telegram 提醒尚未启用。"
  systemctl is-active --quiet "$NOTIFIER_NAME" ||
    die "Telegram 提醒服务没有运行，请先执行 hy2-safe telegram-logs 检查。"
  systemctl kill --kill-whom=main --signal=SIGUSR1 "$NOTIFIER_NAME"
  info "已请求发送当前流量报告，通常会在 30 秒内送达。"
}

command_telegram_name() {
  local requested_name="" old_name
  require_root
  require_systemd
  load_existing_settings || die "请先安装 Hy2。"
  [[ "$TELEGRAM_ENABLED" -eq 1 && -f "$NOTIFIER_CONFIG_PATH" ]] ||
    die "Telegram 提醒尚未启用。"
  validate_root_secret_file "$NOTIFIER_CONFIG_PATH" "Telegram 凭据文件"

  if [[ "$#" -gt 1 ]]; then
    die "用法：hy2-safe telegram-name [NAME]"
  elif [[ "$#" -eq 1 ]]; then
    case "$1" in
      -h | --help)
        printf '用法：hy2-safe telegram-name [NAME]\n'
        printf '不提供 NAME 时会交互输入；名称会显示在所有 Telegram 通知中。\n'
        return
        ;;
      *) requested_name="$1" ;;
    esac
  elif [[ -t 0 ]]; then
    prompt_input "新的 Telegram 消息名称 [直接回车保留：${TELEGRAM_NAME}]: " requested_name
    [[ -n "$requested_name" ]] || requested_name="$TELEGRAM_NAME"
  else
    die "非交互模式请提供名称：hy2-safe telegram-name NAME"
  fi

  validate_telegram_name "$requested_name" ||
    die "Telegram 消息名称必须是 1-64 个可见字符，且首尾不能有空格。"
  old_name="$TELEGRAM_NAME"

  exec 9>"$LOCK_PATH"
  flock -n 9 || die "另一个 hy2-safe 任务正在运行。"
  TMP_ROOT="$(mktemp -d /tmp/hy2-safe.XXXXXXXX)"
  cp --preserve=mode,ownership,timestamps -- "$SETTINGS_PATH" "${TMP_ROOT}/hy2-safe.env"
  cp --preserve=mode,ownership,timestamps -- \
    "$NOTIFIER_CONFIG_PATH" "${TMP_ROOT}/telegram-notifier.json"

  TELEGRAM_NAME="$requested_name"
  if ! save_settings || ! sync_telegram_name_config ||
    ! systemctl restart "$NOTIFIER_NAME" || ! wait_for_unit "$NOTIFIER_NAME"; then
    TELEGRAM_NAME="$old_name"
    cp --preserve=mode,ownership,timestamps -- \
      "${TMP_ROOT}/hy2-safe.env" "$SETTINGS_PATH"
    cp --preserve=mode,ownership,timestamps -- \
      "${TMP_ROOT}/telegram-notifier.json" "$NOTIFIER_CONFIG_PATH"
    systemctl restart "$NOTIFIER_NAME" >/dev/null 2>&1 || true
    die "Telegram 消息名称修改失败，已恢复原名称。"
  fi

  info "Telegram 消息名称已设置为【${TELEGRAM_NAME}】。"
  if ! stored_telegram_send_test; then
    warn "名称已经保存，但 Telegram 测试消息发送失败；请运行 hy2-safe telegram-test 重试。"
  fi
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
  install_manager_copy
  if [[ "$TELEGRAM_ENABLED" -eq 0 ]]; then
    systemctl disable --now "$NOTIFIER_NAME" >/dev/null 2>&1 || true
    rm -f -- "$NOTIFIER_CONFIG_PATH"
    remove_managed_tree "$NOTIFIER_STATE_DIR"
    remove_managed_tree "$NOTIFIER_PRIVATE_STATE_DIR"
    info "Telegram 提醒已经关闭；残留 Token 和通知状态也已清理。"
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
  remove_managed_tree "$NOTIFIER_STATE_DIR"
  remove_managed_tree "$NOTIFIER_PRIVATE_STATE_DIR"
  info "Telegram 提醒已关闭，Bot Token 和提醒状态已从服务器删除。"
}

command_update() {
  local before_version after_version
  require_root
  require_systemd
  [[ -f "$SETTINGS_PATH" ]] || die "未检测到 hy2-safe 管理的安装，拒绝更新未知实例。"
  validate_root_secret_file "$SETTINGS_PATH" "hy2-safe 设置文件"
  load_existing_settings || die "无法读取 hy2-safe 设置。"
  command_verify_service_account
  install_manager_copy
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
  before_version="$(installed_version || true)"
  FAILURE_EVENT="update-failed"
  fetch_verified_release
  install_fetched_binary 1
  FAILURE_EVENT=""
  after_version="$(installed_version || true)"
  if [[ -n "$after_version" && "$after_version" != "$before_version" ]]; then
    send_telegram_system_event update-success "$after_version" || true
  fi
}

command_rotate_password() {
  local answer="" old_password
  require_root
  require_systemd
  load_existing_settings || die "请先安装 Hy2。"
  [[ -t 0 ]] || die "密码轮换必须在交互式终端中执行。"

  printf '此操作会生成全新的高强度 Hy2 密码，现有客户端会立即失效。\n'
  prompt_input "确认继续请输入 ROTATE: " answer
  [[ "$answer" == "ROTATE" ]] || {
    info "已取消密码轮换，没有修改任何内容。"
    return
  }

  exec 9>"$LOCK_PATH"
  flock -n 9 || die "另一个 hy2-safe 任务正在运行。"
  ensure_service_user_and_directories
  TMP_ROOT="$(mktemp -d /tmp/hy2-safe.XXXXXXXX)"
  cp --preserve=mode,ownership,timestamps -- "$CONFIG_PATH" "${TMP_ROOT}/config.yaml"
  cp --preserve=mode,ownership,timestamps -- "$SETTINGS_PATH" "${TMP_ROOT}/hy2-safe.env"
  old_password="$PASSWORD"
  PASSWORD="$(random_password)"
  validate_password "$PASSWORD" || die "生成的新密码没有通过内部格式检查。"
  [[ "$PASSWORD" != "$old_password" ]] || die "新密码意外与旧密码相同，拒绝继续。"

  if ! write_config || ! save_settings ||
    ! systemctl restart "$SERVICE_NAME" || ! wait_for_service; then
    warn "新密码没有成功启用，正在恢复旧配置。"
    cp --preserve=mode,ownership,timestamps -- "${TMP_ROOT}/config.yaml" "$CONFIG_PATH"
    cp --preserve=mode,ownership,timestamps -- "${TMP_ROOT}/hy2-safe.env" "$SETTINGS_PATH"
    systemctl restart "$SERVICE_NAME" || true
    wait_for_service || warn "恢复旧密码后服务仍未正常运行，请检查日志。"
    die "密码轮换失败，已恢复原密码。"
  fi
  configure_notifier_service ||
    warn "Hy2 密码已经轮换，但 Telegram 提醒服务未能重新启动；请运行 hy2-safe telegram-logs。"
  info "Hy2 密码已安全轮换，旧客户端配置已经失效。"
  show_client
}

command_verify_service_account() {
  require_root
  load_account_ownership || true
  validate_recorded_service_identity
  validate_service_account
}

command_version() {
  printf 'hy2-safe 管理脚本版本：v%s\n' "$PROGRAM_VERSION"
  printf 'Hysteria 2 核心版本：%s\n' "$(installed_version || printf '未安装')"
}

command_status() {
  local current_version
  require_root
  load_existing_settings || true
  current_version="$(installed_version || printf '未安装')"
  printf 'hy2-safe 管理脚本版本：v%s\n' "$PROGRAM_VERSION"
  printf '当前 Hysteria 2 版本：%s\n' "$current_version"
  case "${ACME_TYPE:-http}" in
    http) printf '证书验证：HTTP-01（需要入站 TCP 80）\n' ;;
    tls) printf '证书验证：TLS-ALPN-01（需要入站 TCP 443）\n' ;;
    dns) printf '证书验证：Cloudflare DNS-01（不需要入站 TCP 80/443）\n' ;;
  esac
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    printf 'Hy2 服务：正在运行\n'
  else
    printf 'Hy2 服务：未运行或异常\n'
  fi
  if systemctl is-enabled --quiet "$TIMER_NAME" 2>/dev/null; then
    printf '每周自动更新：已开启（下面显示下次检查时间）\n'
    systemctl list-timers --no-pager "$TIMER_NAME" || true
  else
    printf '每周自动更新：未开启\n'
  fi
  if systemctl is-enabled --quiet "$HEALTH_TIMER_NAME" 2>/dev/null; then
    printf '证书健康检查：已开启（每天检查，证书不足 21 天时告警）\n'
  else
    printf '证书健康检查：未开启或尚未同步到当前版本\n'
  fi
  if [[ "${TELEGRAM_ENABLED:-0}" -eq 1 ]]; then
    printf 'Telegram 消息名称：%s\n' "$TELEGRAM_NAME"
    if systemctl is-active --quiet "$NOTIFIER_NAME" 2>/dev/null; then
      printf 'Telegram 提醒：已开启并正在运行\n'
      printf 'Telegram 流量报告：每天 08:00 报告前一日；每月 1 日 08:05 报告上月（北京时间、静默消息）\n'
    else
      printf 'Telegram 提醒：已配置但服务异常\n'
    fi
  else
    printf 'Telegram 提醒：未开启\n'
  fi
  printf '\n详细 systemd 状态：\n'
  systemctl --no-pager --full status "$SERVICE_NAME" || true
}

command_logs() {
  require_root
  journalctl --no-pager -e -u "$SERVICE_NAME"
}

service_user_has_processes() {
  local expected_uid="$1"
  local status_path real_uid
  for status_path in /proc/[0-9]*/status; do
    [[ -r "$status_path" ]] || continue
    real_uid="$(awk '$1 == "Uid:" { print $2; exit }' "$status_path" 2>/dev/null || true)"
    [[ "$real_uid" == "$expected_uid" ]] && return 0
  done
  return 1
}

command_uninstall() {
  local assume_yes=0 answer="" managed_install=0 ownership_recorded=0 service_uid=""
  require_root
  require_systemd
  if [[ -f "$SETTINGS_PATH" ]]; then
    validate_root_secret_file "$SETTINGS_PATH" "hy2-safe 设置文件"
    managed_install=1
  fi
  if load_account_ownership; then
    ownership_recorded=1
    managed_install=1
    validate_recorded_service_identity
  fi
  [[ "$managed_install" -eq 1 ]] ||
    die "未检测到 hy2-safe 设置或账号归属记录，拒绝删除未知实例。"

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --yes)
        assume_yes=1
        shift
        ;;
      -h | --help)
        printf '用法：hy2-safe uninstall [--yes]\n'
        printf '警告：会永久删除 Hy2 配置、证书、密码和 Telegram Token。\n'
        return
        ;;
      *) die "uninstall 的未知选项：$1" ;;
    esac
  done

  printf '即将永久删除：\n'
  printf '  - Hysteria 2 程序、旧版本、管理脚本和 systemd 服务\n'
  printf '  - Hy2 服务端配置、客户端密码和 ACME 证书\n'
  printf '  - Cloudflare DNS-01 API Token（如果已经配置）\n'
  printf '  - Telegram Bot Token、通知程序和通知状态\n'
  if [[ "$ownership_recorded" -eq 1 ]] &&
    { [[ "$SERVICE_USER_CREATED" -eq 1 ]] || [[ "$SERVICE_GROUP_CREATED" -eq 1 ]]; }; then
    printf '  - 有 UID/GID 归属记录证明由 hy2-safe 创建的 hysteria 服务账号/组\n'
  else
    printf '  - hysteria 服务账号/组缺少创建归属证明，将保留并明确提示\n'
  fi
  printf '自动安装的通用系统依赖不会删除，以免影响其他程序。\n'
  printf '警告：短时间反复完整卸载重装会反复申请新证书，可能触发证书机构频率限制。\n'
  if [[ "$assume_yes" -eq 0 ]]; then
    [[ -t 0 ]] || die "非交互卸载必须明确添加 --yes。"
    prompt_input "此操作无法撤销；确认完整卸载请输入 DELETE: " answer
    [[ "$answer" == "DELETE" ]] || {
      info "已取消卸载，没有删除任何内容。"
      return
    }
  fi

  exec 9>"$LOCK_PATH"
  flock -n 9 || die "另一个 hy2-safe 任务正在运行。"

  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl disable --now "$TIMER_NAME" >/dev/null 2>&1 || true
  systemctl disable --now "$HEALTH_TIMER_NAME" >/dev/null 2>&1 || true
  systemctl stop hy2-safe-health-alert.service >/dev/null 2>&1 || true
  systemctl disable --now "$NOTIFIER_NAME" >/dev/null 2>&1 || true
  systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null &&
    die "Hysteria 服务仍在运行，拒绝继续卸载。"
  systemctl is-active --quiet "$NOTIFIER_NAME" 2>/dev/null &&
    die "Telegram 提醒服务仍在运行，拒绝继续卸载。"

  if [[ "$SERVICE_USER_CREATED" -eq 1 ]] && getent passwd hysteria >/dev/null 2>&1; then
    service_uid="$(id -u hysteria)"
    service_user_has_processes "$service_uid" &&
      die "停止服务后仍有进程使用 hysteria 用户（UID ${service_uid}），拒绝删除账号。"
    userdel hysteria
    getent passwd hysteria >/dev/null 2>&1 &&
      die "userdel 返回成功，但 hysteria 用户仍然存在。"
  fi
  if [[ "$SERVICE_GROUP_CREATED" -eq 1 ]] && getent group hysteria >/dev/null 2>&1; then
    validate_service_group
    groupdel hysteria
    getent group hysteria >/dev/null 2>&1 &&
      die "groupdel 返回成功，但 hysteria 组仍然存在。"
  fi

  rm -f -- \
    "$SERVICE_PATH" \
    "$UPDATE_SERVICE_PATH" \
    "$UPDATE_TIMER_PATH" \
    "$HEALTH_SERVICE_PATH" \
    "$HEALTH_ALERT_SERVICE_PATH" \
    "$HEALTH_TIMER_PATH" \
    "$NOTIFIER_SERVICE_PATH" \
    "$BIN_PATH" \
    "$PREVIOUS_BIN_PATH" \
    "$NOTIFIER_PATH" \
    "$MANAGER_PATH" \
    "$DEFAULT_DOWNLOAD_PATH"
  remove_managed_tree "$CONFIG_DIR"
  if [[ "$SERVICE_USER_CREATED" -eq 1 ]]; then
    remove_managed_tree "$STATE_DIR"
  elif [[ -L "$STATE_DIR" ]]; then
    warn "未删除缺少归属证明且为符号链接的 hysteria 家目录：$STATE_DIR"
  else
    remove_managed_tree "${STATE_DIR}/acme"
    rmdir -- "$STATE_DIR" >/dev/null 2>&1 || true
  fi
  remove_managed_tree "$NOTIFIER_STATE_DIR"
  remove_managed_tree "$NOTIFIER_PRIVATE_STATE_DIR"
  systemctl daemon-reload
  systemctl reset-failed \
    "$SERVICE_NAME" \
    hy2-safe-update.service \
    hy2-safe-health.service \
    hy2-safe-health-alert.service \
    "$NOTIFIER_NAME" >/dev/null 2>&1 || true

  info "Hy2 程序、配置、证书、密码、Cloudflare/Telegram Token 和通知状态已完整删除。"
  if [[ "$ownership_recorded" -eq 1 ]] &&
    { [[ "$SERVICE_USER_CREATED" -eq 1 ]] || [[ "$SERVICE_GROUP_CREATED" -eq 1 ]]; }; then
    printf '有归属记录的 hysteria 服务账号/组已删除；root 登录账号未被修改。\n'
  else
    printf '保留了通用系统依赖。hysteria 账号/组因缺少 hy2-safe 创建归属证明也已保留，未冒险误删。\n'
  fi
}

command_menu() {
  local choice=""
  require_root
  printf '\n%b%b========================================%b\n' \
    "$COLOR_BOLD" "$COLOR_CYAN" "$COLOR_RESET"
  printf '%b%b  hy2-safe v%s · Hysteria 2 管理菜单%b\n' \
    "$COLOR_BOLD" "$COLOR_CYAN" "$PROGRAM_VERSION" "$COLOR_RESET"
  printf '%b%b========================================%b\n' \
    "$COLOR_BOLD" "$COLOR_CYAN" "$COLOR_RESET"
  if [[ -f "$SETTINGS_PATH" ]]; then
    validate_root_secret_file "$SETTINGS_PATH" "hy2-safe 设置文件"
    printf '%b当前状态：已安装 Hy2%b\n' "$COLOR_GREEN" "$COLOR_RESET"
  else
    printf '%b当前状态：尚未安装 Hy2%b\n' "$COLOR_YELLOW" "$COLOR_RESET"
  fi
  printf '\n'
  menu_item "1" "安装 Hy2"
  menu_item "2" "完整卸载 Hy2"
  menu_item "3" "添加 Telegram 通知"
  menu_item "4" "更换 Telegram 机器人"
  menu_item "5" "删除 Telegram 通知"
  menu_item "6" "显示客户端配置"
  menu_item "7" "修改 Hy2 配置"
  menu_item "8" "立即检查更新（默认另有每周自动更新）"
  menu_item "9" "查看版本、服务和自动更新状态"
  menu_item "10" "立即发送 Telegram 流量报告"
  menu_item "11" "设置 Telegram 消息名称"
  menu_item "12" "一键重置 Hy2 密码"
  menu_item "0" "退出"
  printf '\n'
  prompt_input "请输入菜单编号 [0-12]: " choice
  case "$choice" in
    1)
      if [[ -f "$SETTINGS_PATH" ]]; then
        die "已经安装 Hy2；如需修改请选择 7，如需修复请运行 hy2-safe install --reinstall。"
      fi
      command_install
      ;;
    2) command_uninstall ;;
    3)
      refresh_managed_runtime
      command_telegram_add
      ;;
    4)
      refresh_managed_runtime
      command_telegram_replace
      ;;
    5)
      refresh_managed_runtime
      command_telegram_disable
      ;;
    6)
      refresh_managed_runtime
      show_client
      ;;
    7) command_configure ;;
    8)
      refresh_managed_runtime
      command_update
      ;;
    9)
      refresh_managed_runtime
      command_status
      ;;
    10)
      refresh_managed_runtime
      configure_notifier_service ||
        die "Telegram 提醒服务重载失败，请运行 hy2-safe telegram-logs。"
      command_telegram_report
      ;;
    11)
      refresh_managed_runtime
      command_telegram_name
      ;;
    12)
      refresh_managed_runtime
      command_rotate_password
      ;;
    0) info "已退出。" ;;
    *) die "无效选项：$choice" ;;
  esac
}

main() {
  local command
  if [[ "$#" -eq 0 ]]; then
    if [[ -t 0 && -t 1 ]]; then
      command_menu
    else
      usage
    fi
    return
  fi
  command="$1"
  shift
  case "$command" in
    install) command_install "$@" ;;
    configure) command_configure "$@" ;;
    update) command_update "$@" ;;
    rotate-password) command_rotate_password "$@" ;;
    certificate-check) command_certificate_check "$@" ;;
    certificate-alert) command_certificate_alert "$@" ;;
    show-client) show_client "$@" ;;
    status) command_status "$@" ;;
    version | -V | --version) command_version ;;
    logs) command_logs "$@" ;;
    telegram-setup) command_telegram_setup "$@" ;;
    telegram-test) command_telegram_test "$@" ;;
    telegram-report) command_telegram_report "$@" ;;
    telegram-name) command_telegram_name "$@" ;;
    telegram-logs) command_telegram_logs "$@" ;;
    telegram-disable) command_telegram_disable "$@" ;;
    telegram-replace) command_telegram_replace "$@" ;;
    verify-service-account) command_verify_service_account "$@" ;;
    uninstall) command_uninstall "$@" ;;
    help | -h | --help) usage ;;
    *) die "未知命令：$command。请运行 $PROGRAM help。" ;;
  esac
}

if [[ "${HY2_SAFE_SOURCE_ONLY:-0}" != "1" ]]; then
  main "$@"
fi
