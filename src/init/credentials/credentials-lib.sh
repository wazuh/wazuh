# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
#
# Shared half of the credential resolution ladder: the credentials file, the locking
# convention, path validation, and password generation and validation. Everything here is
# common to the manager, the indexer and the dashboard; the component-specific half (which
# keys it owns, where it stores them) lives in that component's resolve-credentials.
#
# POSIX sh, deliberately: this is sourced from a Debian postinst and an RPM %post, both of
# which run under /bin/sh, and from a systemd pre-start step that runs before any of the
# product's own interpreters exist. No arrays, no [[ ]], no local.
#
# Nothing in this file ever prints a credential value. Diagnostics name the key and the rule
# it failed, because maintainer script output is captured in /var/log/apt/term.log,
# /var/log/dnf.log, the journal, Ansible and AWX job output, and CI logs.

# The file's own path is fixed, because it is where the key that would move the CA directory
# is itself written.
#
# CRED_DIR and CRED_TRUST_ROOT are overridable only so the test suite can drive the ladder
# against a throwaway tree. Nothing that ships sets either, so a real run resolves
# /etc/wazuh/credentials.env and validates its ancestry from / down. Neither is a privilege
# boundary in any case: the ladder already takes credentials from the process environment by
# design, so whoever controls its environment is already root.
CRED_DIR="${CRED_DIR:-/etc/wazuh}"
CRED_TRUST_ROOT="${CRED_TRUST_ROOT:-}"
CRED_FILE="${CRED_DIR}/credentials.env"
CRED_LOCK="${CRED_DIR}/.credentials.env.lock"

# The delimiters of the region the packages own. Everything outside them belongs to the
# operator -- formatting and ordering included -- and is copied through untouched.
CRED_BLOCK_BEGIN="# >>> wazuh generated - do not edit"
CRED_BLOCK_END="# >>> end wazuh generated"

# Generated passwords draw from this set. The omissions are deliberate: quotes, backslash,
# backtick, $, ! and # are left out so a value is safe to paste through shell, YAML, JSON and
# docker-compose interpolation without escaping. 32 characters of this alphabet is ~190 bits,
# far above what the policy asks for, so the omission costs nothing.
CRED_PW_ALPHABET='A-Za-z0-9.,_+:@%^=~-'
CRED_PW_LENGTH=32

# Policy bounds. The upper bound and the character classes are the Server API's own rule
# (framework/wazuh/security.py). It is stricter than PCI DSS v4.0 8.3.6, which asks only for
# twelve characters with letters and digits, and being stricter is what keeps a value we
# generate or accept here from being one the API itself would later reject.
CRED_PW_MIN=12
CRED_PW_MAX=64

CRED_LOG_TAG="resolve-credentials"

cred_log() {
    echo "${CRED_LOG_TAG}: $*"
}

cred_err() {
    echo "${CRED_LOG_TAG}: $*" >&2
}

# -----------------------------------------------------------------------------------------
# Location validation
# -----------------------------------------------------------------------------------------

# Every directory from / down to the target must be root-owned and not group- or
# world-writable, and none may be a symlink. Checked on every run, not only at creation:
# WAZUH_CA_DIR can point anywhere, and a tree under a writable parent can be replaced between
# two runs, which would let an unprivileged user choose the material the next component
# adopts. A path more permissive than this is reported and treated as unresolved rather than
# repaired -- it is either a mistake or an attack, and fixing it silently hides both.
cred_check_dir_chain() {
    _ccdc_target="$1"

    # Ownership is checked against the euid we are running as, which is root everywhere this
    # ships -- the ladder runs from postinst and from an ExecStartPre carrying the + prefix.
    # Stating it this way rather than hardcoding 0 is the same rule (a non-root process can
    # only ever write files it already owns) and is what lets the suite run unprivileged.
    _ccdc_uid=$(id -u)

    # CRED_TRUST_ROOT is where the walk begins; empty means the real root, which is the only
    # value anything that ships uses. The test suite sets it so a throwaway tree under /tmp
    # is not rejected for /tmp's own 1777.
    _ccdc_walked="${CRED_TRUST_ROOT}"
    _ccdc_rest="${_ccdc_target}"
    case "${_ccdc_target}" in
        "${CRED_TRUST_ROOT}"/*) _ccdc_rest="${_ccdc_target#"${CRED_TRUST_ROOT}"}" ;;
    esac

    # Split the path and re-walk it from the root, so each intermediate directory is checked
    # in its own right rather than only the leaf.
    for _ccdc_part in $(echo "${_ccdc_rest}" | tr '/' ' '); do
        _ccdc_walked="${_ccdc_walked}/${_ccdc_part}"

        [ -e "${_ccdc_walked}" ] || return 0

        if [ -L "${_ccdc_walked}" ]; then
            cred_err "refusing to use ${_ccdc_target}: ${_ccdc_walked} is a symlink"
            return 1
        fi

        _ccdc_owner=$(stat -c '%u' "${_ccdc_walked}" 2>/dev/null)
        if [ "${_ccdc_owner}" != "${_ccdc_uid}" ]; then
            cred_err "refusing to use ${_ccdc_target}: ${_ccdc_walked} is not owned by the resolver's own user"
            return 1
        fi

        _ccdc_mode=$(stat -c '%a' "${_ccdc_walked}" 2>/dev/null)
        if [ $(( 0${_ccdc_mode} & 0022 )) -ne 0 ]; then
            cred_err "refusing to use ${_ccdc_target}: ${_ccdc_walked} is group- or world-writable (${_ccdc_mode})"
            return 1
        fi
    done

    return 0
}

# The file itself carries every plaintext password in the deployment, so it is held to more
# than its ancestors: root:root and readable by nobody else.
cred_check_file() {
    [ -e "${CRED_FILE}" ] || return 0

    if [ -L "${CRED_FILE}" ]; then
        cred_err "refusing to read ${CRED_FILE}: it is a symlink"
        return 1
    fi

    # root:root in production, for the reason given in cred_check_dir_chain.
    _ccf_owner=$(stat -c '%u' "${CRED_FILE}" 2>/dev/null)
    if [ "${_ccf_owner}" != "$(id -u)" ]; then
        cred_err "refusing to read ${CRED_FILE}: it is not owned by the resolver's own user"
        return 1
    fi

    _ccf_mode=$(stat -c '%a' "${CRED_FILE}" 2>/dev/null)
    if [ $(( 0${_ccf_mode} & 0077 )) -ne 0 ]; then
        cred_err "refusing to read ${CRED_FILE}: it is group- or world-accessible (${_ccf_mode})"
        return 1
    fi

    return 0
}

# Both checks, in the order a caller needs them. A failure here means every key resolves as
# unresolved -- we do not fall back to reading a file we have just declared untrustworthy.
cred_check_location() {
    cred_check_dir_chain "${CRED_DIR}" || return 1
    cred_check_file || return 1
    return 0
}

# install -d rather than mkdir -p, with the mode stated explicitly: maintainer scripts
# inherit the caller's umask, which is 022 in a terminal and sometimes 0 in build and CI
# contexts, so mkdir -p would produce a different mode depending on who invoked the package
# manager.
cred_ensure_dir() {
    [ -d "${CRED_DIR}" ] && return 0

    if ! install -d -m 0700 -o root -g root "${CRED_DIR}" 2>/dev/null; then
        cred_err "could not create ${CRED_DIR}"
        return 1
    fi

    return 0
}

# -----------------------------------------------------------------------------------------
# Locking
# -----------------------------------------------------------------------------------------

# systemd starts units in parallel, so three pre-start steps can reach one file at once.
# Without a lock, generated values are lost silently at boot -- the last writer wins and the
# other two components' keys vanish from a file they already believe they published to.
#
# flock is the normal path. The mkdir fallback exists because the lock is load-bearing: if
# flock is unavailable we take a slower lock rather than proceeding unlocked.
cred_lock() {
    CRED_LOCK_MODE=""

    if command -v flock >/dev/null 2>&1; then
        # fd 9 is held for the duration; closing it in cred_unlock releases the lock.
        if ( exec 9>"${CRED_LOCK}" ) 2>/dev/null; then
            exec 9>"${CRED_LOCK}"
            if flock -w 30 9; then
                CRED_LOCK_MODE="flock"
                return 0
            fi
            exec 9>&-
            cred_err "timed out waiting for the lock on ${CRED_FILE}"
            return 1
        fi
    fi

    _cl_waited=0
    while ! mkdir "${CRED_LOCK}.d" 2>/dev/null; do
        _cl_waited=$(( _cl_waited + 1 ))
        if [ "${_cl_waited}" -gt 300 ]; then
            cred_err "timed out waiting for the lock on ${CRED_FILE}"
            return 1
        fi
        sleep 0.1 2>/dev/null || sleep 1
    done

    CRED_LOCK_MODE="mkdir"
    return 0
}

cred_unlock() {
    if [ "${CRED_LOCK_MODE}" = "flock" ]; then
        exec 9>&-
    elif [ "${CRED_LOCK_MODE}" = "mkdir" ]; then
        rmdir "${CRED_LOCK}.d" 2>/dev/null
    fi

    CRED_LOCK_MODE=""
}

# -----------------------------------------------------------------------------------------
# Reading
# -----------------------------------------------------------------------------------------

# The file is parsed, never sourced. Sourcing executes its contents as shell, as root, from a
# file the packages did not write -- an operator typo becomes an arbitrary command, and an
# attacker who can write the file owns the host outright.
#
# Format: KEY=VALUE, one per line, with the value optionally wrapped in single or double
# quotes. Inside single quotes the one escape is '\'' (the shell's own spelling), which is
# how a value containing a quote round-trips; inside double quotes the quotes are stripped
# and nothing else is interpreted.
cred_file_get() {
    _cfg_key="$1"

    [ -f "${CRED_FILE}" ] || return 1

    # Last assignment wins, matching how a shell would read the same file.
    _cfg_raw=$(sed -n "s/^[[:space:]]*${_cfg_key}=\\(.*\\)$/\\1/p" "${CRED_FILE}" 2>/dev/null | tail -n 1)
    [ -n "${_cfg_raw}" ] || return 1

    case "${_cfg_raw}" in
        \'*\')
            _cfg_val=$(printf '%s' "${_cfg_raw}" | sed -e "s/^'//" -e "s/'\$//" -e "s/'\\\\''/'/g")
            ;;
        \"*\")
            _cfg_val=$(printf '%s' "${_cfg_raw}" | sed -e 's/^"//' -e 's/"$//')
            ;;
        *)
            _cfg_val="${_cfg_raw}"
            ;;
    esac

    printf '%s' "${_cfg_val}"
    return 0
}

# Two channels, read in this order: the file, then the process environment, which overrides
# it. The environment wins because it is the more deliberate and more immediate input, and
# because an orchestrator setting a value should not be silently overridden by a file left
# behind from an earlier install. Containers use the environment exclusively and have no file.
cred_get() {
    _cg_key="$1"

    # eval is confined to reading one variable whose name we validated as a key we know --
    # it never touches the value.
    _cg_env=$(eval "printf '%s' \"\${${_cg_key}-}\"")
    if [ -n "${_cg_env}" ]; then
        printf '%s' "${_cg_env}"
        return 0
    fi

    cred_file_get "${_cg_key}"
}

# -----------------------------------------------------------------------------------------
# Writing
# -----------------------------------------------------------------------------------------

# Quote a value for the file. Single-quoting with '\'' for an embedded quote is total: there
# is no character it cannot carry, and it is the same spelling the shell uses, so the file
# stays readable by a human who knows shell without being executable by one.
cred_quote() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# Publish a key into the managed block, creating the block if it is absent. Lines outside the
# block are copied through byte for byte -- the operator's are theirs, even when they carry
# the same key, because the packages own only their block.
cred_publish() {
    _cp_key="$1"
    _cp_value="$2"

    cred_ensure_dir || return 1
    cred_lock || return 1

    _cp_tmp="${CRED_FILE}.tmp.$$"
    _cp_old_umask=$(umask)
    umask 077

    if ! : > "${_cp_tmp}" 2>/dev/null; then
        umask "${_cp_old_umask}"
        cred_unlock
        cred_err "could not write ${CRED_FILE}"
        return 1
    fi

    _cp_quoted=$(cred_quote "${_cp_value}")

    # The assembled line travels through the environment, never through awk -v: awk processes
    # escape sequences in a -v assignment, which would silently eat a backslash in a value.
    # ENVIRON[] is taken literally.
    CRED_PUBLISH_LINE="${_cp_key}=${_cp_quoted}"
    export CRED_PUBLISH_LINE

    if [ -f "${CRED_FILE}" ] && grep -qF "${CRED_BLOCK_BEGIN}" "${CRED_FILE}" 2>/dev/null; then
        # Rewrite in place: copy everything, replacing the key inside the block and appending
        # it at the end of the block when it was not already there.
        awk -v begin="${CRED_BLOCK_BEGIN}" -v end="${CRED_BLOCK_END}" -v key="${_cp_key}" '
            $0 == begin { inblock = 1; print; next }
            $0 == end   {
                if (inblock && !written) { print ENVIRON["CRED_PUBLISH_LINE"]; written = 1 }
                inblock = 0; print; next
            }
            inblock && index($0, key "=") == 1 {
                if (!written) { print ENVIRON["CRED_PUBLISH_LINE"]; written = 1 }
                next
            }
            { print }
        ' "${CRED_FILE}" > "${_cp_tmp}"
    else
        [ -f "${CRED_FILE}" ] && cat "${CRED_FILE}" >> "${_cp_tmp}"
        # printf, not echo: some /bin/sh implementations interpret backslashes in echo.
        {
            printf '%s\n' "${CRED_BLOCK_BEGIN}"
            printf '%s\n' "# Editing a value here does not change the deployment: a component that already"
            printf '%s\n' "# holds the credential keeps it. To rotate, use wazuh-passwords-tool.sh."
            printf '%s\n' "${CRED_PUBLISH_LINE}"
            printf '%s\n' "${CRED_BLOCK_END}"
        } >> "${_cp_tmp}"
    fi

    unset CRED_PUBLISH_LINE

    umask "${_cp_old_umask}"

    chown root:root "${_cp_tmp}" 2>/dev/null
    chmod 0600 "${_cp_tmp}" 2>/dev/null

    # Same directory, so the rename is atomic: a concurrent reader sees either the old file
    # or the new one, never a half-written one.
    if ! mv -f "${_cp_tmp}" "${CRED_FILE}" 2>/dev/null; then
        rm -f "${_cp_tmp}"
        cred_unlock
        cred_err "could not replace ${CRED_FILE}"
        return 1
    fi

    cred_unlock
    cred_log "published ${_cp_key}"
    return 0
}

# Remove every key matching a prefix from the managed block, on purge. This is what scoping
# key names by owning component buys: a purge can identify exactly which keys are its own,
# and leaves the other components' and the operator's alone.
cred_purge_prefix() {
    _cpp_prefix="$1"

    [ -f "${CRED_FILE}" ] || return 0
    cred_check_file || return 1
    cred_lock || return 1

    _cpp_tmp="${CRED_FILE}.tmp.$$"
    _cpp_old_umask=$(umask)
    umask 077

    awk -v begin="${CRED_BLOCK_BEGIN}" -v end="${CRED_BLOCK_END}" -v prefix="${_cpp_prefix}" '
        $0 == begin { inblock = 1; print; next }
        $0 == end   { inblock = 0; print; next }
        inblock && index($0, prefix) == 1 { next }
        { print }
    ' "${CRED_FILE}" > "${_cpp_tmp}" 2>/dev/null

    umask "${_cpp_old_umask}"

    chown root:root "${_cpp_tmp}" 2>/dev/null
    chmod 0600 "${_cpp_tmp}" 2>/dev/null
    mv -f "${_cpp_tmp}" "${CRED_FILE}" 2>/dev/null || rm -f "${_cpp_tmp}"

    cred_unlock
    return 0
}

# True when the managed block holds no key at all, which is how the last component out knows
# it may remove the file and the directory.
cred_block_is_empty() {
    [ -f "${CRED_FILE}" ] || return 0

    _cbie_count=$(awk -v begin="${CRED_BLOCK_BEGIN}" -v end="${CRED_BLOCK_END}" '
        $0 == begin { inblock = 1; next }
        $0 == end   { inblock = 0; next }
        inblock && /^[A-Za-z_][A-Za-z0-9_]*=/ { n++ }
        END { print n + 0 }
    ' "${CRED_FILE}" 2>/dev/null)

    [ "${_cbie_count}" = "0" ]
}

# -----------------------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------------------

# An invalid value does not fall through. A caller that gets a non-zero answer here stops,
# rather than continuing to generation: falling back would discard the operator's intent
# silently and leave the deployment holding a credential nobody else has -- which is the
# defect this whole mechanism exists to close.
#
# The key is named, the rule is named, the value never is.
cred_validate_password() {
    _cvp_key="$1"
    _cvp_value="$2"

    _cvp_len=${#_cvp_value}
    if [ "${_cvp_len}" -lt "${CRED_PW_MIN}" ] || [ "${_cvp_len}" -gt "${CRED_PW_MAX}" ]; then
        cred_err "${_cvp_key} rejected: must be ${CRED_PW_MIN} to ${CRED_PW_MAX} characters"
        return 1
    fi

    if ! printf '%s' "${_cvp_value}" | grep -q '[a-z]'; then
        cred_err "${_cvp_key} rejected: must contain a lowercase letter"
        return 1
    fi

    if ! printf '%s' "${_cvp_value}" | grep -q '[A-Z]'; then
        cred_err "${_cvp_key} rejected: must contain an uppercase letter"
        return 1
    fi

    if ! printf '%s' "${_cvp_value}" | grep -q '[0-9]'; then
        cred_err "${_cvp_key} rejected: must contain a digit"
        return 1
    fi

    if ! printf '%s' "${_cvp_value}" | grep -q '[^A-Za-z0-9]'; then
        cred_err "${_cvp_key} rejected: must contain a symbol"
        return 1
    fi

    return 0
}

# -----------------------------------------------------------------------------------------
# Generation
# -----------------------------------------------------------------------------------------

cred_rand_int() {
    _cri_max="$1"
    _cri_n=$(od -An -N4 -tu4 < /dev/urandom 2>/dev/null | tr -d ' \n')
    [ -n "${_cri_n}" ] || return 1
    echo $(( _cri_n % _cri_max ))
}

cred_rand_from() {
    _crf_set="$1"
    _crf_c=$(LC_ALL=C tr -dc "${_crf_set}" < /dev/urandom 2>/dev/null | dd bs=1 count=1 2>/dev/null)
    [ -n "${_crf_c}" ] || return 1
    printf '%s' "${_crf_c}"
}

cred_set_char() {
    _csc_s="$1"
    _csc_i="$2"
    _csc_c="$3"

    _csc_pre=""
    [ "${_csc_i}" -gt 1 ] && _csc_pre=$(printf '%s' "${_csc_s}" | cut -c1-$(( _csc_i - 1 )))
    _csc_post=$(printf '%s' "${_csc_s}" | cut -c$(( _csc_i + 1 ))-)

    printf '%s%s%s' "${_csc_pre}" "${_csc_c}" "${_csc_post}"
}

# 32 characters over the alphabet above, with one lowercase, one uppercase, one digit and one
# symbol guaranteed by construction rather than by generate-and-retry: the four are placed at
# a random offset inside four disjoint eight-character blocks, so their positions are
# distinct without needing a collision check and the result still passes cred_validate_password
# on the first attempt, every time.
cred_generate_password() {
    _cgp_pw=$(LC_ALL=C tr -dc "${CRED_PW_ALPHABET}" < /dev/urandom 2>/dev/null | dd bs=1 count=${CRED_PW_LENGTH} 2>/dev/null)

    if [ "${#_cgp_pw}" -ne "${CRED_PW_LENGTH}" ]; then
        cred_err "could not read ${CRED_PW_LENGTH} bytes from /dev/urandom"
        return 1
    fi

    _cgp_block=$(( CRED_PW_LENGTH / 4 ))
    _cgp_slot=0

    for _cgp_class in 'a-z' 'A-Z' '0-9' '.,_+:@%^=~-'; do
        _cgp_c=$(cred_rand_from "${_cgp_class}") || return 1
        _cgp_off=$(cred_rand_int "${_cgp_block}") || return 1
        _cgp_pos=$(( _cgp_slot * _cgp_block + _cgp_off + 1 ))
        _cgp_pw=$(cred_set_char "${_cgp_pw}" "${_cgp_pos}" "${_cgp_c}")
        _cgp_slot=$(( _cgp_slot + 1 ))
    done

    printf '%s' "${_cgp_pw}"
    return 0
}
