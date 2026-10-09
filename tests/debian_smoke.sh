#!/usr/bin/env bash
set -Eeuo pipefail

TEST_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TEST_ROOT
export HY2_SAFE_SOURCE_ONLY=1
# shellcheck source=../hy2-safe.sh
source "${TEST_ROOT}/hy2-safe.sh"

[[ "$PROGRAM_VERSION" == "1.1.11" ]]
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
  printf 'v1.1.12\n'
}
update_notice="$(notice_manager_update_available)"
[[ "$update_notice" == *"发现可用的 hy2-safe 管理脚本更新：v1.1.11 → v1.1.12"* ]]
manager_latest_version_for_notice() {
  printf 'v1.1.11\n'
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
