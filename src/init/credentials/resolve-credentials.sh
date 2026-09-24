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
# validation, and the CA -- lives in wazuh-credentials.sh, which the manager, the indexer and the
# dashboard must agree on exactly. It is therefore NOT in this repository: it is owned by
# wazuh-installation-assistant and downloaded by `make deps` into src/external/wazuh-credentials/.
# wazuh-manager-certificates.sh, beside this file, is the manager's own and shared with nobody,
# though the two are still a pair at runtime -- it refuses to run without the shared functions.
#
# This file adds only what is specific to the manager: which keys it owns, which it consumes, and
# where each resolved value is stored.
#
# The same script runs at three moments, and the difference between them is the whole design:
#
#   --install    From a FRESH postinst / %post / install.sh -- never from an upgrade. Creates what
#                it can, and has no opinion about whether the manager can run. Never fails: a
#                maintainer script that aborts leaves the package half-configured, breaks
#                `apt install -f` and fails image builds. Exits 0 whatever it could not resolve.
#                This is the only moment that issues TLS certificates (see below).
#
#   --upgrade    From postinst / %post / install.sh when a previous version was already installed.
#                Identical to --install for the passwords and the keystore -- every one of those is
#                a step-0 no-op once resolved, so the only values it can fill in are the ones this
#                host never had -- but it does NOT touch the certificates. An operator who replaced
#                the shipped pair with their own PKI must not find it re-examined, re-anchored or
#                reissued by a package upgrade.
#
#   --prestart   From wazuh-manager-control start, which is what the systemd unit's ExecStart
#                runs -- so it covers the systemd and the manual start alike. Runs the same ladder
#                again, not merely a check, so a manager installed before the indexer picks up what
#                became available since and configures itself. Exits non-zero naming every key it
#                could not resolve. Like --upgrade, it does not touch the certificates.
#
#   --clear      Removes every credential this manager owns or stores, so the next --install or
#                --prestart resolves from nothing. Nothing in the product calls it: it exists for
#                an image that was built by installing the package, whose postinst therefore
#                seeded rbac.db, minted a bootstrap CA and issued certificates into the image
#                layer. Every container started from such an image would otherwise share one
#                database, one CA private key and one certificate -- which the specification calls
#                out as worse than the defect this whole mechanism closes, because it looks random.
#                Run it at the end of the Dockerfile, or once from an entrypoint before the first
#                start.
#
# Validating at start rather than at install is deliberate: the answer changes between the two
# moments and only the answer at start matters. A manager installed first resolves nothing;
# by the time it is started the indexer has published its key, and it resolves. Checking at
# install would have declared a problem that no longer exists.
#
# Certificates are the one credential that does NOT work that way, which is why they are issued at
# install and never looked at again:
#
#   * Their resolution is not a lookup, it is a signature. Every run that re-examines them has to
#     re-derive the trust chain, which means the shared CA directory has to still be there, still
#     hold the anchor this manager's material was issued from, and still match it byte for byte.
#     A deployment that brings its own PKI stages a pair and nothing else -- it has no reason to
#     keep a copy of its root CA on every manager forever, and no reason to accept that a manager
#     refuses to boot because that copy drifted or was tidied away.
#
#   * They are the credential an operator legitimately replaces out of band. A password lives in
#     one place this script owns; a certificate is rotated by whatever issues the rest of the
#     estate's certificates. Re-running the ladder over someone else's material can only produce
#     false verdicts about it.
#
# So /etc/wazuh/ca is a bootstrap handoff, not a standing dependency: it exists so a manager that
# was given nothing can still come up, and once the pair is in etc/certs nothing consults it again.
# What certificates the daemons will actually accept is decided by the daemons -- the configuration
# validator checks the files exist, remoted probes them with access(R_OK) after dropping privileges
# (w_remoted_check_tls_files(), src/remoted/src/secure.c), and the TLS handshake decides the rest.
# Those checks run against the files as they are at start, which is the only state that matters.
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
        --upgrade)  MODE="upgrade" ; shift ;;
        --prestart) MODE="prestart"; shift ;;
        --clear)    MODE="clear"   ; shift ;;
        -H)
            if [ -z "${2-}" ]; then
                echo "resolve-credentials: -H needs a directory" >&2
                exit 2
            fi
            DIR="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--install|--upgrade|--prestart|--clear] [-H <home>]"
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

# The two halves sit together once installed and apart in the source tree, so they are resolved
# separately.
#
#   * wazuh-manager-certificates.sh is ours and lives beside this file.
#   * wazuh-credentials.sh is shared with the indexer and the dashboard, so it is owned by
#     wazuh-installation-assistant and downloaded by `make deps` into src/external/wazuh-credentials/
#     -- it is NOT in this repository. WAZUH_SHARED_HELPER_DIR overrides where to look for it.
#
# Resolving from the source tree at all is what lets the test suites drive the ladder without an
# install; on an installed manager the first branch of each wins and the rest never runs.
_self_dir=$(dirname "$0")

if [ -f "${DIR}/lib/wazuh-manager-certificates.sh" ]; then
    HELPER_DIR="${DIR}/lib"
elif [ -f "${_self_dir}/wazuh-manager-certificates.sh" ]; then
    HELPER_DIR="${_self_dir}"
else
    echo "resolve-credentials: cannot find wazuh-manager-certificates.sh" >&2
    exit 2
fi

if [ -n "${WAZUH_SHARED_HELPER_DIR-}" ] && [ -f "${WAZUH_SHARED_HELPER_DIR}/wazuh-credentials.sh" ]; then
    SHARED_HELPER_DIR="${WAZUH_SHARED_HELPER_DIR}"
elif [ -f "${DIR}/lib/wazuh-credentials.sh" ]; then
    SHARED_HELPER_DIR="${DIR}/lib"
elif [ -f "${_self_dir}/../../external/wazuh-credentials/wazuh-credentials.sh" ]; then
    SHARED_HELPER_DIR="${_self_dir}/../../external/wazuh-credentials"
elif [ -f "${_self_dir}/wazuh-credentials.sh" ]; then
    SHARED_HELPER_DIR="${_self_dir}"
else
    echo "resolve-credentials: cannot find wazuh-credentials.sh" >&2
    echo "        it is downloaded from wazuh-installation-assistant by 'make -C src deps TARGET=manager'" >&2
    exit 2
fi

# Order matters: the certificate helper checks for the shared functions at call time and refuses
# to run without them.
. "${SHARED_HELPER_DIR}/wazuh-credentials.sh"
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

# The indexer connector needs both keys. A username the operator already stored is kept, so only
# an absent one gets the manager's account.
store_indexer_username() {
    "${KEYSTORE}" -f indexer -k username -g >/dev/null 2>&1 && return 0
    printf '%s' "wazuh-manager" | "${KEYSTORE}" -f indexer -k username >/dev/null 2>&1
}

# wazuh_password_validate() rejects only line breaks. Any other control character would pass it
# and then break the JSON that seeds rbac.db, so it fails the policy here instead.
password_is_valid() {
    case "$1" in
        *[[:cntrl:]]*) return 1 ;;
    esac
    wazuh_password_validate "$1"
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
            if ! password_is_valid "${_rap_value}"; then
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

    # A component publishes every credential it owns, whether it generated the value or was
    # given one, so a sibling installed later finds it. Publishing comes first: once rbac.db
    # exists nothing reads these keys again, so a value seeded but never published would be lost.
    # A failed seed then reuses the published values on the next run.
    #
    # Either failure has to be recorded, not merely returned: the caller ignores the return value,
    # so without this the run would end with nothing marked and the service would be allowed to
    # start.
    if ! wazuh_env_set WAZUH_MANAGER_API_PASSWORD "${API_PASSWORD}" ||
       ! wazuh_env_set WAZUH_MANAGER_WUI_PASSWORD "${WUI_PASSWORD}"; then
        err "could not publish WAZUH_MANAGER_API_PASSWORD and WAZUH_MANAGER_WUI_PASSWORD"
        mark_unresolved "rbac.db"
        return 1
    fi
    log "published WAZUH_MANAGER_API_PASSWORD and WAZUH_MANAGER_WUI_PASSWORD"

    if ! seed_rbac; then
        mark_unresolved "rbac.db"
        return 1
    fi

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
        if ! store_indexer_username; then
            err "could not write the indexer username to the keystore"
            mark_unresolved WAZUH_INDEXER_MANAGER_PASSWORD
            return 1
        fi
        log "the indexer credential is already in the keystore"
        return 0
    fi

    _rip_status=0
    _rip_value=$(setting_get WAZUH_INDEXER_MANAGER_PASSWORD) || _rip_status=$?

    if [ "${_rip_status}" -ne 0 ]; then
        mark_unresolved WAZUH_INDEXER_MANAGER_PASSWORD
        return 1
    fi

    if ! password_is_valid "${_rip_value}"; then
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
    if ! store_indexer_username ||
       ! printf '%s' "${_rip_value}" | "${KEYSTORE}" -f indexer -k password >/dev/null 2>&1; then
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
    # Not mark_unresolved(): that list is the set of keys the SERVICE will refuse to start without,
    # and only --prestart reports it. Certificates are resolved at install and nowhere else, so the
    # caller reports this failure at the moment it happens instead.
    if ! wazuh_manager_certificates_ensure; then
        return 1
    fi

    log "certificates are in place"

    # A wrong name fails only at the first peer connection, not here, so the DN and SANs each leaf
    # carries are logged. -text rather than -ext keeps this working on OpenSSL older than 1.1.1.
    for _rc_leaf in indexer-connector remoted; do
        _rc_text=$(openssl x509 -in "${DIR}/etc/certs/${_rc_leaf}.pem" -noout -subject -text 2>/dev/null) || continue
        _rc_dn=$(printf '%s\n' "${_rc_text}" | sed -n 's/^subject= *//p' | head -n 1)
        _rc_sans=$(printf '%s\n' "${_rc_text}" | sed -n '/X509v3 Subject Alternative Name:/{n;s/^ *//p;}')
        log "${_rc_leaf}.pem: DN ${_rc_dn}; SANs ${_rc_sans}"
    done
    return 0
}

# -----------------------------------------------------------------------------------------
# --clear
#
# The one destructive path in a tool whose every other rule is "never overwrite, never repair,
# leave what is already there alone". It exists for exactly one situation: an image built by
# installing the package, which ran the resolver in its postinst and therefore baked this host's
# credentials into a layer that every container will share.
#
# Two things it deliberately does NOT remove:
#
#   * A CA directory holding only an anchor. No private key beside it means the CA was issued
#     elsewhere and handed to this host; it is not ours to destroy, and a container that was given
#     a real CA should keep trusting it.
#   * Anything outside the managed block of the credentials file, or any sibling component's keys.
# -----------------------------------------------------------------------------------------

manager_is_running() {
    for _mir_pid in "${DIR}"/var/run/*.pid; do
        [ -e "${_mir_pid}" ] || continue
        _mir_n=$(cat "${_mir_pid}" 2>/dev/null)
        [ -n "${_mir_n}" ] || continue
        # A stale pidfile from an unclean stop is not a running manager.
        kill -0 "${_mir_n}" 2>/dev/null && return 0
    done
    return 1
}

clear_credentials() {
    if manager_is_running; then
        err "refusing to clear credentials while the manager is running"
        err "        stop it first: wazuh-manager-control stop"
        return 1
    fi

    # rbac.db holds every user, role, policy and rule -- the two default users are only part of it,
    # so this is named rather than folded into a quiet list.
    if [ -e "${RBAC_DB}" ]; then
        rm -f "${RBAC_DB}" "${RBAC_DB}.tmp"
        log "removed ${RBAC_DB} (every Server API user, role and policy it held, not only the defaults)"
    fi

    # The keystore has no delete verb -- writing an empty value is refused -- so the RocksDB files
    # go directly. The directory itself stays, keeping its ownership and mode.
    if [ -d "${DIR}/queue/keystore" ]; then
        rm -rf "${DIR}"/queue/keystore/* 2>/dev/null
        log "cleared the keystore (the indexer credential)"
    fi

    for _cc_file in remoted.pem remoted-key.pem indexer-connector.pem indexer-connector-key.pem root-ca.pem; do
        if [ -e "${DIR}/etc/certs/${_cc_file}" ]; then
            rm -f "${DIR}/etc/certs/${_cc_file}"
            log "removed etc/certs/${_cc_file}"
        fi
    done

    _cc_ca=$(wazuh_ca_get_dir 2>/dev/null) || _cc_ca=""
    if [ -n "${_cc_ca}" ] && [ -f "${_cc_ca}/root-ca.key" ]; then
        rm -f "${_cc_ca}/root-ca.pem" "${_cc_ca}/root-ca.key" "${_cc_ca}/root-ca.srl"
        log "removed the bootstrap CA in ${_cc_ca}"
    elif [ -n "${_cc_ca}" ] && [ -f "${_cc_ca}/root-ca.pem" ]; then
        log "keeping the trust anchor in ${_cc_ca}: it carries no private key, so it was issued elsewhere"
    fi

    # Only this component's keys, and only inside the managed block.
    for _cc_key in WAZUH_MANAGER_API_PASSWORD WAZUH_MANAGER_WUI_PASSWORD; do
        wazuh_env_unset "${_cc_key}" >/dev/null 2>&1 || true
    done
    log "removed the manager's published keys from the credentials file"

    log "cleared; the next start resolves from nothing"
    return 0
}

# -----------------------------------------------------------------------------------------
# Run
# -----------------------------------------------------------------------------------------

if [ "${MODE}" = "clear" ]; then
    clear_credentials
    exit $?
fi

resolve_api_passwords
resolve_indexer_password

# Certificates are issued once, on a fresh install, and are not part of the ladder at any other
# moment -- see the header. An upgrade that re-derived the chain would have to find the shared CA
# directory unchanged, which is exactly the standing dependency this design refuses to create.
if [ "${MODE}" = "install" ]; then
    # This is the only chance to issue them, so say so plainly rather than exiting 0 in silence and
    # letting the operator meet it later as "(1244) file not found" from the configuration
    # validator. The helper has already printed which file or which rule was at fault.
    if ! resolve_certificates; then
        err "the manager has no TLS certificates and this install could not issue them"
        err "        provision the pair into ${DIR}/etc/certs before starting the service"
        err "        (e.g. with wazuh-certs-tool); the service will not start without it"
    fi
fi

# The installer has no opinion about whether the component can run: no warning, no failure, no
# special state. Nothing checks credentials until something needs them.
if [ "${MODE}" = "install" ] || [ "${MODE}" = "upgrade" ]; then
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
    err "        (12-64 characters, with at least one letter and one digit, and no control characters)"
    err "        correct it in ${CREDENTIALS_FILE} and start the service again"
done

for _key in ${UNRESOLVED}; do
    case "${_key}" in
        WAZUH_INDEXER_MANAGER_PASSWORD)
            err "MISSING WAZUH_INDEXER_MANAGER_PASSWORD"
            err "        set it in ${CREDENTIALS_FILE}, or install wazuh-indexer on this host first"
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

exit 1
