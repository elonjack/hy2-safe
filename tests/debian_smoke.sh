#!/usr/bin/env bash
set -Eeuo pipefail

TEST_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TEST_ROOT
export HY2_SAFE_SOURCE_ONLY=1
# shellcheck source=../hy2-safe.sh
source "${TEST_ROOT}/hy2-safe.sh"

[[ "$PROGRAM_VERSION" == "1.1.13" ]]
validate_domain "hy2.example.com"
! validate_domain "invalid_domain"
validate_email "owner@example.com"
validate_acme_type "http"
validate_acme_type "tls"
validate_acme_type "dns"
! validate_acme_type "both"
validate_cloudflare_token "cfut_0123456789abcdefghijklmnop"
! validate_cloudflare_token "bad token"
validate_port "443"
validate_port "65535"
! validate_port "0"
validate_password "0123456789abcdef"
! validate_password "too-short"
[[ "$(compare_versions v2.10.0 v2.9.0)" == "1" ]]
[[ "$(compare_versions v2.10.0 v2.10.0)" == "0" ]]
[[ "$(compare_versions v2.9.0 v2.10.0)" == "-1" ]]
[[ "$(menu_item "1" "single-digit")" == "   1) single-digit" ]]
[[ "$(menu_item "10" "double-digit")" == "  10) double-digit" ]]

manager_latest_version_for_notice() {
  printf 'v1.1.14\n'
}
update_notice="$(notice_manager_update_available)"
[[ "$update_notice" == *"发现可用的 hy2-safe 管理脚本更新：v1.1.13 → v1.1.14"* ]]
manager_latest_version_for_notice() {
  printf 'v1.1.13\n'
}
[[ -z "$(notice_manager_update_available)" ]]
manager_latest_version_for_notice() {
  return 1
}
[[ -z "$(notice_manager_update_available)" ]]

journalctl() {
  return 1
}
[[ -z "$(service_log_cursor)" ]]
unset -f journalctl

curl_secure() {
  return 22
}
failed_metadata="$(mktemp /tmp/hy2-safe-metadata.XXXXXXXX)"
rm -f -- "$failed_metadata"
! manager_latest_version "$failed_metadata" 2>/dev/null
[[ ! -e "$failed_metadata" ]]
[[ ! -e "${failed_metadata}.headers" ]]
unset -f curl_secure

api_headers="$(mktemp /tmp/hy2-safe-api-headers.XXXXXXXX)"
cat >"$api_headers" <<'EOF'
HTTP/2 403
x-ratelimit-remaining: 0
x-ratelimit-reset: 1795092218
retry-after: 60
EOF
api_error="$(report_github_api_failure "$api_headers" "测试 API" 2>&1)"
[[ "$api_error" == *"HTTP 403"* ]]
[[ "$api_error" == *"剩余请求数：0"* ]]
[[ "$api_error" == *"等待 60 秒"* ]]
rm -f -- "$api_headers"

local_manager_source="$(mktemp /tmp/hy2-safe-local-manager.XXXXXXXX)"
install -m 0600 -o root -g root "${TEST_ROOT}/hy2-safe.sh" "$local_manager_source"
local_manager_sha="$(sha256sum "$local_manager_source" | awk '{print $1}')"
chmod 0666 "$local_manager_source"
! (prepare_local_manager_update "$local_manager_source" "$local_manager_sha") 2>/dev/null
chmod 0600 "$local_manager_source"
! (prepare_local_manager_update "$local_manager_source" "$(printf '0%.0s' {1..64})") 2>/dev/null
prepare_local_manager_update "$local_manager_source" "$local_manager_sha"
[[ "$FETCHED_MANAGER_VERSION" == "v1.1.13" ]]
[[ -f "$FETCHED_MANAGER_SCRIPT" ]]
rm -f -- "$local_manager_source"
rm -rf -- "$TMP_ROOT"
TMP_ROOT=""

systemctl_calls=()
systemctl() {
  systemctl_calls+=("${1:-}:${2:-}")
}
restart_hysteria_service
[[ "${systemctl_calls[0]}" == "reset-failed:hysteria-server.service" ]]
[[ "${systemctl_calls[1]}" == "restart:hysteria-server.service" ]]
unset -f systemctl

acquire_manager_lock
[[ "$(stat -c '%u:%g:%a' -- "$LOCK_DIR")" == "0:0:700" ]]
[[ "$(stat -c '%u:%g:%a' -- "$LOCK_PATH")" == "0:0:600" ]]
release_manager_lock
rm -f -- "$LOCK_PATH"
rmdir -- "$LOCK_DIR"

generated_password="$(random_password)"
validate_password "$generated_password"
[[ "${#generated_password}" -ge 40 ]]

python_trap_dir="$(mktemp -d)"
printf '%s\n' 'raise RuntimeError("current-directory module hijack")' >"${python_trap_dir}/re.py"
(
  cd "$python_trap_dir"
  [[ "$(compare_versions v2.10.0 v2.9.0)" == "1" ]]
)
rm -rf -- "$python_trap_dir"

binary_probe_dir="$(mktemp -d)"
binary_probe_result="/tmp/hy2-safe-binary-probe.$$.result"
chmod 0711 "$binary_probe_dir"
cat >"${binary_probe_dir}/hysteria" <<EOF
#!/bin/sh
printf '%s\n' "\$(id -u):\${HY2_SAFE_UNTRUSTED_ENV-unset}" >"${binary_probe_result}"
printf '%s\n' 'Version: v9.9.9'
EOF
chmod 0755 "${binary_probe_dir}/hysteria"
chown root:root "${binary_probe_dir}/hysteria"
export HY2_SAFE_UNTRUSTED_ENV=preserved
[[ "$(binary_version "${binary_probe_dir}/hysteria")" == "v9.9.9" ]]
[[ "$(cat "$binary_probe_result")" == "$(id -u nobody):unset" ]]
unset HY2_SAFE_UNTRUSTED_ENV
rm -f -- "$binary_probe_result"
rm -rf -- "$binary_probe_dir"

certificate_test_dir="$(mktemp -d)"
trap 'rm -rf -- "$certificate_test_dir"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj '/CN=hy2.example.com' \
  -addext 'subjectAltName=DNS:hy2.example.com' \
  -keyout "${certificate_test_dir}/test.key" \
  -out "${certificate_test_dir}/test.crt" >/dev/null 2>&1
certificate_matches_domain "${certificate_test_dir}/test.crt" "hy2.example.com"
! certificate_matches_domain "${certificate_test_dir}/test.crt" "wrong.example.com"
certificate_valid_beyond "${certificate_test_dir}/test.crt" 1814400
! certificate_valid_beyond "${certificate_test_dir}/test.crt" 2678400

printf 'Debian helper smoke checks passed\n'
