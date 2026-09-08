#!/bin/bash

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Unit tests for wet_parse_enrollment_token() and its helpers wet_b64url_decode()/
# wet_json_parse(). Sources register_configure_agent.sh directly (rather than as a
# subprocess, as test_register_configure_agent.sh does) to reach these functions in
# isolation -- the guarded 'main "$@"' exists for exactly this.
#
#   ./test_enrollment_token.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SCRIPT_DIR}/../register_configure_agent.sh"

# shellcheck source=/dev/null
. "${TARGET}"

failures=0
checks=0

check_ok() {

    local name="$1" token="$2" expect_ver="$3" expect_adr="$4" expect_pin="$5" expect_key="$6" expect_ca="$7"

    checks=$(( checks + 1 ))
    if wet_parse_enrollment_token "${token}" \
        && [ "${WET_VER}" = "${expect_ver}" ] \
        && [ "${WET_ADR}" = "${expect_adr}" ] \
        && [ "${WET_PIN}" = "${expect_pin}" ] \
        && [ "${WET_KEY}" = "${expect_key}" ] \
        && [ "${WET_CA}" = "${expect_ca}" ]; then
        echo "ok   - ${name}"
    else
        failures=$(( failures + 1 ))
        echo "FAIL - ${name}"
        echo "    got: ver=${WET_VER} adr=${WET_ADR} pin=${WET_PIN} key=${WET_KEY} ca=${WET_CA} error=${WET_ERROR_CODE}"
    fi

}

check_error() {

    local name="$1" token="$2" expect_code="$3"

    checks=$(( checks + 1 ))
    if wet_parse_enrollment_token "${token}"; then
        failures=$(( failures + 1 ))
        echo "FAIL - ${name} (expected failure, parsed ok)"
    elif [ "${WET_ERROR_CODE}" = "${expect_code}" ]; then
        echo "ok   - ${name}"
    else
        failures=$(( failures + 1 ))
        echo "FAIL - ${name} (expected ${expect_code}, got ${WET_ERROR_CODE}: ${WET_ERROR_MESSAGE})"
    fi

}

# --- Sample tokens -----------------------------------------------------------------
# Built from {"ver":1,"adr":"manager.example.com","pin":"<64 a's>","key":"k1"} etc.,
# base64url-encoded without padding, matching the token's real shape (unpadded
# base64url of a flat JSON object).

VALID_TOKEN="eyJ2ZXIiOjEsImFkciI6Im1hbmFnZXIuZXhhbXBsZS5jb20iLCJwaW4iOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwia2V5IjoiazEifQ"
VALID_PIN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

# {"ver":2,"adr":"manager.example.com","ca":"<64 b's>"} -- anchor via 'ca' instead of 'pin'.
CA_ONLY_TOKEN="eyJ2ZXIiOjIsImFkciI6Im1hbmFnZXIuZXhhbXBsZS5jb20iLCJjYSI6ImJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIifQ"
CA_ONLY_CA="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

# Same payload as VALID_TOKEN plus a "ca" field alongside "pin" -- both anchors present.
BOTH_ANCHOR_TOKEN="eyJ2ZXIiOjEsImFkciI6Im1hbmFnZXIuZXhhbXBsZS5jb20iLCJwaW4iOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwiY2EiOiJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIn0"

# {"ver":1,"adr":"manager.example.com"} -- no pin, no ca: neither anchor present.
NEITHER_ANCHOR_TOKEN="eyJ2ZXIiOjEsImFkciI6Im1hbmFnZXIuZXhhbXBsZS5jb20ifQ"

# {"ver": 1, "adr": "manager.example.com", "pin": "aaaa...} -- truncated mid-string,
# missing the closing quote and brace: malformed JSON.
MALFORMED_JSON_TOKEN="eyJ2ZXIiOiAxLCAiYWRyIjogIm1hbmFnZXIuZXhhbXBsZS5jb20iLCAicGluIjogImFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"

# The above with extra characters outside the base64url alphabet appended.
MALFORMED_BASE64_TOKEN="${VALID_TOKEN}!!!not-base64"

# --- Cases ---------------------------------------------------------------------------

check_ok "valid token, anchor via pin" "${VALID_TOKEN}" "1" "manager.example.com" "${VALID_PIN}" "k1" ""
check_ok "valid token, anchor via ca" "${CA_ONLY_TOKEN}" "2" "manager.example.com" "" "" "${CA_ONLY_CA}"

check_error "malformed base64 (invalid alphabet)" "${MALFORMED_BASE64_TOKEN}" "${WET_ERR_BAD_BASE64}"
check_error "malformed base64 (length % 4 == 1)" "abcde" "${WET_ERR_BAD_BASE64}"
check_error "malformed base64 (empty token)" "" "${WET_ERR_BAD_BASE64}"

check_error "malformed JSON (truncated payload)" "${MALFORMED_JSON_TOKEN}" "${WET_ERR_BAD_JSON}"

check_error "both pin and ca present" "${BOTH_ANCHOR_TOKEN}" "${WET_ERR_ANCHOR_BOTH}"
check_error "neither pin nor ca present" "${NEITHER_ANCHOR_TOKEN}" "${WET_ERR_ANCHOR_NEITHER}"

# Missing required fields entirely: {"pin":"..."} has no 'ver' or 'adr'.
MISSING_REQUIRED_TOKEN="$(printf '{"pin":"%s"}' "${VALID_PIN}" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')"
check_error "missing required 'ver'/'adr' fields" "${MISSING_REQUIRED_TOKEN}" "${WET_ERR_MISSING_FIELD}"

# 'ver' present but not a scalar integer (an object) -- rejected as malformed JSON by
# wet_json_parse(), since nested object/array values are outside its supported grammar;
# this is also the guarantee that a non-scalar 'ver' can never reach a type check that
# might dereference it as one.
VER_NOT_SCALAR_TOKEN="$(printf '{"ver":{"x":1},"adr":"manager.example.com","pin":"%s"}' "${VALID_PIN}" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '=')"
check_error "'ver' as a nested object is rejected" "${VER_NOT_SCALAR_TOKEN}" "${WET_ERR_BAD_JSON}"

echo
echo "${checks} checks, ${failures} failed"
[ "${failures}" -eq 0 ]
