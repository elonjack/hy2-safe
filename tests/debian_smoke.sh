#!/usr/bin/env bash
set -Eeuo pipefail

readonly TEST_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
export HY2_SAFE_SOURCE_ONLY=1
# shellcheck source=../hy2-safe.sh
source "${TEST_ROOT}/hy2-safe.sh"

[[ "$PROGRAM_VERSION" == "1.0.7" ]]
validate_domain "hy2.example.com"
! validate_domain "invalid_domain"
validate_email "owner@example.com"
validate_acme_type "http"
validate_acme_type "tls"
! validate_acme_type "both"
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

printf 'Debian helper smoke checks passed\n'
