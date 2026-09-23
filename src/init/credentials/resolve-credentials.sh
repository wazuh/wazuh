#!/bin/sh

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
#
# The manager's half of the credential resolution ladder.
#
# The shared half -- the credentials file, its locking convention, password generation and
# validation, the CA, and the manager's own certificates -- lives in wazuh-credentials.sh and
# wazuh-manager-certificates.sh, which are common to all three components and versioned together.
# This file adds only what is specific to the manager: which keys it owns, which it consumes, and
# where each resolved value is stored.
#
# The same script runs at two moments, and the difference between them is the whole design:
#
#   --install    From postinst / %post. Creates what it can, and has no opinion about
#                whether the manager can run. Never fails: a maintainer script that aborts
#                leaves the package half-configured, breaks `apt install -f` and fails image
#                builds. Exits 0 whatever it could not resolve.
#
#   --prestart   From wazuh-manager-control start, which is what the systemd unit's ExecStart
#                runs -- so it covers the systemd and the manual start alike. Runs the same ladder
#                again, not merely a check, so a manager installed before the indexer picks up what
#                became available since and configures itself. Exits non-zero naming every key it
#                could not resolve.
#
# Validating at start rather than at install is deliberate: the answer changes between the two
# moments and only the answer at start matters. A manager installed first resolves nothing;
# by the time it is started the indexer has published its key, and it resolves. Checking at
# install would have declared a problem that no longer exists.
#
# The step never opens a network connection. It validates presence and format only -- making a
# service's start depend on reaching its peer would break boot ordering and cluster restarts.
# A credential that is present but wrong still fails as a 401 at runtime, exactly as today.

MODE="prestart"
DIR=""

# ${1-} rather than $1, matching the helpers' convention: the bare form is an "unbound variable"
# error under a caller that runs us with `set -u`, and `shift 2` on a lone -H is a hard error in
# dash rather than a diagnosable one.
while [ -n "${1-}" ]; do
    case "${1-}" in
        --install)  MODE="install" ; shift ;;
        --prestart) MODE="prestart"; shift ;;
        -H)
            if [ -z "${2-}" ]; then
                echo "resolve-credentials: -H needs a directory" >&2
                exit 2
            fi
            DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--install|--prestart] [-H <home>]"
            exit 0
            ;;
        *)
            echo "resolve-credentials: unknown option: ${1-}" >&2
            exit 2
            ;;
    esac
done

# Derive the installation directory from our own location, so a tree installed under a
# non-default USER_DIR resolves against itself rather than against a compiled-in path.
if [ -z "${DIR}" ]; then
    _self=$(readlink -f "$0" 2>/dev/null || echo "$0")
    DIR=$(dirname "$(dirname "${_self}")")
fi

# Installed layout puts the helpers in lib/; the source tree has them beside this file, which is
# what lets the test suite drive the ladder without an install.
if [ -f "${DIR}/lib/wazuh-credentials.sh" ]; then
    HELPER_DIR="${DIR}/lib"
elif [ -f "$(dirname "$0")/wazuh-credentials.sh" ]; then
    HELPER_DIR="$(dirname "$0")"
else
    echo "resolve-credentials: cannot find wazuh-credentials.sh" >&2
    exit 2
fi

# Order matters: the certificate helper checks for the shared functions at call time and refuses
# to run without them.
. "${HELPER_DIR}/wazuh-credentials.sh"
. "${HELPER_DIR}/wazuh-manager-certificates.sh"

# The certificate helper reads the manager's home from the environment, so a tree installed under
# a non-default USER_DIR issues into its own etc/certs rather than /var/wazuh-manager's.
WAZUH_MANAGER_HOME="${DIR}"
export WAZUH_MANAGER_HOME

KEYSTORE="${DIR}/bin/wazuh-manager-keystore"
RBAC_CONTROL="${DIR}/bin/rbac_control"
RBAC_DB="${DIR}/api/configuration/security/rbac.db"

LOG_TAG="resolve-credentials"

log() {
    echo "${LOG_TAG}: $*"
}

err() {
    echo "${LOG_TAG}: $*" >&2
}

# Accumulated verdicts. A key is *unresolved* when nothing supplied it and we may not invent it;
# it is *invalid* when something supplied it and the value failed the policy. The two are reported
# differently because they need different fixes, but both block the start.
UNRESOLVED=""
INVALID=""

mark_unresolved() {
    UNRESOLVED="${UNRESOLVED} $1"
}

mark_invalid() {
    INVALID="${INVALID} $1"
}

# Process environment, then the credentials file. The environment wins because it is the more
# deliberate and more immediate input, and because an orchestrator setting a value should not be
# silently overridden by a file left behind from an earlier install. This mirrors what
# wazuh_ca_get_dir() does for the CA directory; wazuh_env_get() itself reads only the file.
#
# An explicitly empty value is treated as absent rather than as a policy failure: for a password
# that is what an operator who cleared a line means, and it leaves the key unresolved with a
# message rather than blocking the install on a validation error.
#
# Prints the value and returns 0 when set, 1 when absent, 2 when the file itself is unusable.
setting_get() {
    _sg_name="$1"

    if eval "[ \"\${${_sg_name}+x}\" = x ]"; then
        eval "_sg_env=\${${_sg_name}-}"
        if [ -n "${_sg_env}" ]; then
            printf '%s' "${_sg_env}"
            return 0
        fi
        return 1
    fi

    _sg_status=0
    _sg_value=$(wazuh_env_get "${_sg_name}") || _sg_status=$?
    case "${_sg_status}" in
        0) [ -n "${_sg_value}" ] || return 1
           printf '%s' "${_sg_value}"
           return 0
           ;;
        1) return 1 ;;
        *) return 2 ;;
    esac
}

# -----------------------------------------------------------------------------------------
# Step 0 tests
#
# Each is a definite marker. Inferring "already present" from a file that ships with the
# package does not work -- it would make every upgrade and every restart a coin toss.
# -----------------------------------------------------------------------------------------

rbac_is_seeded() {
    [ -s "${RBAC_DB}" ]
}

indexer_password_is_stored() {
    [ -x "${KEYSTORE}" ] || return 1
    "${KEYSTORE}" -f indexer -k password -g >/dev/null 2>&1
}

# -----------------------------------------------------------------------------------------
# Owned: the two Server API accounts
#
# Both live in rbac.db, hashed on seeding. They are resolved together because they are seeded
# together: rbac.db is created once, with both users, and is never reseeded afterwards.
# -----------------------------------------------------------------------------------------

API_PASSWORD=""
WUI_PASSWORD=""

resolve_api_passwords() {
    if rbac_is_seeded; then
        # Step 0 wins over both channels. Whatever the keys now say -- including a value an
        # operator edited into the file -- the database already holds a credential, and a
        # package must never reconfigure what is already configured.
        log "rbac.db is already seeded; WAZUH_MANAGER_API_PASSWORD and WAZUH_MANAGER_WUI_PASSWORD are ignored"
        return 0
    fi

    for _rap_key in WAZUH_MANAGER_API_PASSWORD WAZUH_MANAGER_WUI_PASSWORD; do
        _rap_status=0
        _rap_value=$(setting_get "${_rap_key}") || _rap_status=$?

        if [ "${_rap_status}" -eq 2 ]; then
            mark_unresolved "${_rap_key}"
            continue
        fi

        if [ "${_rap_status}" -eq 0 ]; then
            # An invalid value stops here rather than falling through to generation: replacing
            # what the operator asked for would discard their intent silently and leave the
            # deployment holding a credential nobody else has.
            if ! wazuh_password_validate "${_rap_value}"; then
                err "${_rap_key} was rejected by the password policy"
                mark_invalid "${_rap_key}"
                continue
            fi
            log "using the supplied ${_rap_key}"
        else
            # We own the account, so generating the value makes it true.
            _rap_value=$(wazuh_password_generate) || {
                err "could not generate ${_rap_key}"
                mark_unresolved "${_rap_key}"
                continue
            }
            log "generated ${_rap_key}"
        fi

        if [ "${_rap_key}" = "WAZUH_MANAGER_API_PASSWORD" ]; then
            API_PASSWORD="${_rap_value}"
        else
            WUI_PASSWORD="${_rap_value}"
        fi
    done

    [ -n "${INVALID}" ] && return 1
    [ -n "${API_PASSWORD}" ] && [ -n "${WUI_PASSWORD}" ] || return 1

    # A seeding failure has to be recorded, not merely returned: the caller ignores the return
    # value, so without this the run would end with nothing marked and the service would be
    # allowed to start against a database that was never created.
    if ! seed_rbac; then
        mark_unresolved "rbac.db"
        return 1
    fi

    # A component publishes every credential it owns, whether it generated the value or was
    # given one, so a sibling installed later finds it.
    wazuh_env_set WAZUH_MANAGER_API_PASSWORD "${API_PASSWORD}" || return 1
    wazuh_env_set WAZUH_MANAGER_WUI_PASSWORD "${WUI_PASSWORD}" || return 1
    log "published WAZUH_MANAGER_API_PASSWORD and WAZUH_MANAGER_WUI_PASSWORD"

    return 0
}

# Values reach the seeding path through stdin, never argv: a secret on a command line is
# world-readable in ps for as long as the process lives.
seed_rbac() {
    if [ ! -x "${RBAC_CONTROL}" ]; then
        err "cannot seed rbac.db: ${RBAC_CONTROL} is missing"
        return 1
    fi

    _sr_api=$(json_escape "${API_PASSWORD}")
    _sr_wui=$(json_escape "${WUI_PASSWORD}")

    if printf '{"wazuh": "%s", "wazuh-wui": "%s"}' "${_sr_api}" "${_sr_wui}" \
        | "${RBAC_CONTROL}" seed --passwords-file - >/dev/null 2>&1; then
        log "seeded rbac.db"
        return 0
    fi

    err "could not seed rbac.db"
    return 1
}

json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# -----------------------------------------------------------------------------------------
# Consumed: the manager's account on the indexer
#
# Never generated. Inventing a password does not make the peer accept it, so this credential
# can only ever be supplied -- and when it is not, the manager is unresolved and will not
# start. That is the one case the operator is expected to meet on a fresh all-in-one host,
# and it clears itself the moment the indexer publishes its key.
# -----------------------------------------------------------------------------------------

resolve_indexer_password() {
    if indexer_password_is_stored; then
        log "the indexer credential is already in the keystore"
        return 0
    fi

    _rip_status=0
    _rip_value=$(setting_get WAZUH_INDEXER_MANAGER_PASSWORD) || _rip_status=$?

    if [ "${_rip_status}" -ne 0 ]; then
        mark_unresolved WAZUH_INDEXER_MANAGER_PASSWORD
        return 1
    fi

    if ! wazuh_password_validate "${_rip_value}"; then
        err "WAZUH_INDEXER_MANAGER_PASSWORD was rejected by the password policy"
        mark_invalid WAZUH_INDEXER_MANAGER_PASSWORD
        return 1
    fi

    if [ ! -x "${KEYSTORE}" ]; then
        err "cannot store the indexer credential: ${KEYSTORE} is missing"
        mark_unresolved WAZUH_INDEXER_MANAGER_PASSWORD
        return 1
    fi

    # Through stdin, never argv. Storing it in the manager's own keystore is what makes step 0
    # true for every later start, which is why the credentials file can be deleted once every
    # component is installed and running.
    printf '%s' "wazuh-manager" | "${KEYSTORE}" -f indexer -k username >/dev/null 2>&1
    if ! printf '%s' "${_rip_value}" | "${KEYSTORE}" -f indexer -k password >/dev/null 2>&1; then
        err "could not write the indexer credential to the keystore"
        mark_unresolved WAZUH_INDEXER_MANAGER_PASSWORD
        return 1
    fi

    log "stored the indexer credential in the keystore"

    # Never published: that key belongs to whoever owns the account, and two writers for one
    # name is how values get lost.
    return 0
}

# -----------------------------------------------------------------------------------------
# Owned: the manager's own certificates
#
# wazuh_manager_certificates_ensure() decides between minting a bootstrap CA, issuing from the
# CA it finds, and leaving an anchor-only deployment unresolved -- from the contents of the CA
# directory, with no mode flag. It also issues both pairs the manager needs (the indexer
# connector's clientAuth leaf and remoted's serverAuth leaf) and leaves an existing complete
# pair alone, which is how an operator supplies a pre-issued one.
# -----------------------------------------------------------------------------------------

resolve_certificates() {
    # ensure() only, deliberately -- NOT ensure() followed by validate(). _wmc_ensure_locked() ends
    # by calling _wmc_validate_locked(), so a successful ensure() already means a full validation
    # passed: matching key, right trust anchor, correct ownership and mode, unexpired certificate,
    # expected extended key usage. Calling validate() after it runs the same ~35 openssl
    # invocations a second time and adds 0.5s to every single service start for no coverage --
    # verified by breaking a key's mode and swapping in a foreign key, both of which ensure() alone
    # rejects.
    if ! wazuh_manager_certificates_ensure; then
        mark_unresolved "certificates"
        return 1
    fi

    log "certificates are in place"
    return 0
}

# -----------------------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------------------

resolve_api_passwords
resolve_indexer_password
resolve_certificates

# The installer has no opinion about whether the component can run: no warning, no failure, no
# special state. Nothing checks credentials until something needs them.
if [ "${MODE}" = "install" ]; then
    exit 0
fi

if [ -z "${UNRESOLVED}" ] && [ -z "${INVALID}" ]; then
    exit 0
fi

CREDENTIALS_FILE=$(wazuh_env_get_file 2>/dev/null) || CREDENTIALS_FILE="/etc/wazuh/credentials.env"

# The message goes to the journal, which is where someone looks when a service will not start.
# It names every missing key and where to set it, and never prints a value.
for _key in ${INVALID}; do
    err "INVALID ${_key}: the supplied value does not meet the password policy"
    err "        (12-64 characters, with at least one letter and one digit)"
    err "        correct it in ${CREDENTIALS_FILE} and start the service again"
done

for _key in ${UNRESOLVED}; do
    case "${_key}" in
        WAZUH_INDEXER_MANAGER_PASSWORD)
            err "MISSING WAZUH_INDEXER_MANAGER_PASSWORD"
            err "        set it in ${CREDENTIALS_FILE}, or install wazuh-indexer on this host first"
            ;;
        certificates)
            err "MISSING usable TLS certificates for the manager"
            err "        the diagnostics above name the file at fault; a CA directory holding only a"
            err "        trust anchor cannot sign, so place an issued pair in ${DIR}/etc/certs"
            ;;
        rbac.db)
            err "MISSING rbac.db: the Server API database could not be created"
            ;;
        *)
            err "MISSING ${_key}"
            err "        set it in ${CREDENTIALS_FILE}"
            ;;
    esac
done

err "see https://documentation.wazuh.com/current/user-manual/manager/credentials.html"

exit 1
