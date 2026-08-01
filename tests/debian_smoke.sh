#!/usr/bin/env bash
set -Eeuo pipefail

TEST_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly TEST_ROOT
export HY2_SAFE_SOURCE_ONLY=1
# shellcheck source=../hy2-safe.sh
source "${TEST_ROOT}/hy2-safe.sh"

[[ "$PROGRAM_VERSION" == "1.0.9" ]]
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

generated_password="$(random_password)"
validate_password "$generated_password"
[[ "${#generated_password}" -ge 40 ]]

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
