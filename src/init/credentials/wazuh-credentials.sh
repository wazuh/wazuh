#!/bin/sh

# Shared credential helpers for Wazuh package scripts.
#
# This file is a library. Source it with:
#
#   . /usr/share/wazuh-<component>/lib/wazuh-credentials.sh
#
# Importing it performs no action and does not change the caller's shell
# options, umask, IFS, working directory, or traps.
#
# Public functions and return values
# ----------------------------------
#   wazuh_base_get_dir / wazuh_env_get_file
#       Base: process WAZUH_BASE_DIR or /etc/wazuh. ENV: <base>/credentials.env.
#       The base cannot come from that file (circular lookup). Empty is invalid.
#       Getters do not create anything; writers create missing parents safely.
#       All helpers on a host MUST use the same base to share the same lock.
#   wazuh_ca_get_dir
#       Prints the resolved CA directory. Resolution order is the value in
#       <base>/credentials.env, then WAZUH_CA_DIR from the process
#       environment, with <base>/ca as default. Empty is invalid.
#       WAZUH_CA_DIR moves only the CA, never the ENV or the lock.
#
#   wazuh_ca_validate
#       Returns 0 for a valid anchor, with or without its matching private key.
#       Returns non-zero for an absent, partial, invalid, or insecure CA.
#
#   wazuh_ca_ensure
#       Creates root-ca.pem and root-ca.key only when both are absent. Existing
#       material is validated and never regenerated. An anchor without a key is
#       a valid external CA; a key without an anchor is an error.
#
#   wazuh_env_get NAME
#       Reads data only; unquoted values or single/double quoted single lines.
#       Writes require a newline-terminated file; multiline values are rejected.
#       Prints the last value assigned to NAME in credentials.env without
#       sourcing the file. Returns 0 when found, 1 when absent, and 2 when the
#       file or request is invalid.
#
#   wazuh_env_set NAME VALUE
#       Adds or replaces NAME inside the Wazuh-managed block only.
#
#   wazuh_env_unset NAME
#       Removes NAME from the Wazuh-managed block only.
#
#   wazuh_password_generate
#       Prints a 32-character password generated from /dev/urandom.
#
#   wazuh_password_validate VALUE
#       Enforces 12-64 characters containing at least one ASCII letter and one
#       digit. The rejected value is never included in diagnostics.
#
# The library deliberately uses flock(1), GNU stat(1), OpenSSL, awk, and the
# usual Linux userland (including ln -T) on Debian- and RPM-based systems.
# Capture password output; do not use shell xtrace around secret operations.
# Pin BOTH helper files to matching versions: the manager uses private helpers.

_wazuh_error() (
    printf '%s\n' "wazuh-credentials: $*" >&2
)

wazuh_base_get_dir() (
    _wazuh_base=${WAZUH_BASE_DIR-/etc/wazuh}
    _wazuh_validate_absolute_path "$_wazuh_base" || return 1
    printf '%s\n' "$_wazuh_base"
)

wazuh_env_get_file() (
    _wazuh_base=$(wazuh_base_get_dir) || return 1
    printf '%s/credentials.env\n' "$_wazuh_base"
)

# Validate from the root down; never traverse an unchecked symlink first.
# Missing components are allowed by this read-only helper.
_wazuh_check_existing_tree() (
    [ "$1" = / ] && { _wazuh_validate_directory_node / ''; return $?; }
    _wazuh_parent=${1%/*}
    [ -n "$_wazuh_parent" ] || _wazuh_parent=/
    _wazuh_check_existing_tree "$_wazuh_parent" || return 1
    if [ -e "$1" ] || [ -L "$1" ]; then
        _wazuh_validate_directory_node "$1" '' || return 1
    fi
)

# Create one component at a time, never chmod/chown an existing directory.
# Parent validation excludes group/world writers, including sticky /tmp.
_wazuh_make_secure_tree() (
    [ "$(id -u)" = 0 ] || { _wazuh_error 'root is required'; return 1; }
    [ "$1" = / ] && { _wazuh_validate_directory_node / ''; return $?; }
    _wazuh_parent=${1%/*}
    [ -n "$_wazuh_parent" ] || _wazuh_parent=/
    _wazuh_make_secure_tree "$_wazuh_parent" || return 1
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then
        # Another cooperating process may create it first; always revalidate.
        (umask 077; mkdir -m 0700 -- "$1") 2>/dev/null || {
            [ -d "$1" ] || { _wazuh_error "cannot create directory: $1"; return 1; }
        }
    fi
    _wazuh_validate_directory_node "$1" ''
)

_wazuh_validate_name() (
    case ${1-} in
        ''|[0-9]*|*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_]*)
            _wazuh_error "invalid environment variable name"
            return 1
            ;;
    esac
)

_wazuh_validate_absolute_path() (
    _wazuh_path=${1-}

    case $_wazuh_path in
        ''|/)
            _wazuh_error "directory must be a non-empty absolute path other than /"
            return 1
            ;;
        /*) ;;
        *)
            _wazuh_error "directory must be an absolute path"
            return 1
            ;;
    esac

    case $_wazuh_path in
        *'//'*)
            _wazuh_error "directory must not contain repeated slashes"
            return 1
            ;;
        */./*|*/.|*/../*|*/..)
            _wazuh_error "directory must not contain . or .. path components"
            return 1
            ;;
        */)
            _wazuh_error "directory must not end with a slash"
            return 1
            ;;
    esac

    case $_wazuh_path in
        *"
"*)
            _wazuh_error "directory must not contain a newline"
            return 1
            ;;
    esac
    _wazuh_cr=$(printf '\r')
    case $_wazuh_path in
        *"$_wazuh_cr"*)
            _wazuh_error "directory must not contain a carriage return"
            return 1
            ;;
    esac
)

_wazuh_validate_directory_node() (
    _wazuh_path=${1-}
    _wazuh_exact_mode=${2-}

    if [ -L "$_wazuh_path" ]; then
        _wazuh_error "refusing symbolic-link directory: $_wazuh_path"
        return 1
    fi
    if [ ! -d "$_wazuh_path" ]; then
        _wazuh_error "not a directory: $_wazuh_path"
        return 1
    fi

    _wazuh_owner=$(stat -c '%u:%g' -- "$_wazuh_path" 2>/dev/null) || {
        _wazuh_error "cannot inspect directory: $_wazuh_path"
        return 1
    }
    if [ "$_wazuh_owner" != '0:0' ]; then
        _wazuh_error "directory must be owned by root:root: $_wazuh_path"
        return 1
    fi

    _wazuh_mode=$(stat -c '%a' -- "$_wazuh_path" 2>/dev/null) || return 1
    if [ -n "$_wazuh_exact_mode" ]; then
        if [ "$_wazuh_mode" != "$_wazuh_exact_mode" ]; then
            _wazuh_error "directory $_wazuh_path must have mode $_wazuh_exact_mode (found $_wazuh_mode)"
            return 1
        fi
        return 0
    fi

    _wazuh_world=${_wazuh_mode#${_wazuh_mode%?}}
    _wazuh_prefix=${_wazuh_mode%?}
    _wazuh_group=${_wazuh_prefix#${_wazuh_prefix%?}}
    case $_wazuh_group$_wazuh_world in
        *[2367]*)
            _wazuh_error "directory must not be group- or world-writable: $_wazuh_path"
            return 1
            ;;
    esac
)

_wazuh_validate_ancestors() (
    _wazuh_parent=${1%/*}
    [ -n "$_wazuh_parent" ] || _wazuh_parent=/
    _wazuh_check_existing_tree "$_wazuh_parent" || return 1
    _wazuh_validate_directory_node "$_wazuh_parent" ''
)
_wazuh_validate_regular_file() (
    _wazuh_path=${1-}
    _wazuh_required_mode=${2-}

    if [ -L "$_wazuh_path" ]; then
        _wazuh_error "refusing symbolic-link file: $_wazuh_path"
        return 1
    fi
    if [ ! -f "$_wazuh_path" ]; then
        _wazuh_error "not a regular file: $_wazuh_path"
        return 1
    fi

    _wazuh_owner=$(stat -c '%u:%g' -- "$_wazuh_path" 2>/dev/null) || {
        _wazuh_error "cannot inspect file: $_wazuh_path"
        return 1
    }
    if [ "$_wazuh_owner" != '0:0' ]; then
        _wazuh_error "file must be owned by root:root: $_wazuh_path"
        return 1
    fi

    _wazuh_mode=$(stat -c '%a' -- "$_wazuh_path" 2>/dev/null) || return 1
    if [ "$_wazuh_mode" != "$_wazuh_required_mode" ]; then
        _wazuh_error "file $_wazuh_path must have mode $_wazuh_required_mode (found $_wazuh_mode)"
        return 1
    fi
)

_wazuh_restorecon() (
    _wazuh_path=${1-}
    if command -v restorecon >/dev/null 2>&1; then
        restorecon "$_wazuh_path" >/dev/null 2>&1 || {
            _wazuh_error "failed to restore the SELinux context of $_wazuh_path"
            return 1
        }
    fi
)

_wazuh_validate_base_dir_if_present() (
    _wazuh_base=$(wazuh_base_get_dir) || return 1
    _wazuh_check_existing_tree "$_wazuh_base" || return 1
    if [ -e "$_wazuh_base" ] || [ -L "$_wazuh_base" ]; then
        _wazuh_validate_directory_node "$_wazuh_base" 700 || return 1
    fi
)

_wazuh_ensure_base_dir() (
    _wazuh_base=$(wazuh_base_get_dir) || return 1
    _wazuh_make_secure_tree "$_wazuh_base" || return 1
    _wazuh_validate_directory_node "$_wazuh_base" 700 || return 1
    _wazuh_restorecon "$_wazuh_base"
)

_wazuh_validate_credentials_file() (
    _wazuh_validate_base_dir_if_present || return 1
    _wazuh_file=$(wazuh_env_get_file) || return 1
    _wazuh_validate_regular_file "$_wazuh_file" 600
)

_wazuh_with_lock() (
    _wazuh_ensure_base_dir || return 1
    _wazuh_base=$(wazuh_base_get_dir) || return 1
    _wazuh_lock=$_wazuh_base/.credentials.lock

    if [ -L "$_wazuh_lock" ]; then
        _wazuh_error "refusing symbolic-link lock file: $_wazuh_lock"
        return 1
    fi
    if [ ! -e "$_wazuh_lock" ]; then
        (umask 077; set -C; : >"$_wazuh_lock") 2>/dev/null || {
            [ -e "$_wazuh_lock" ] || return 1
        }
        _wazuh_restorecon "$_wazuh_lock" || return 1
    fi
    _wazuh_validate_regular_file "$_wazuh_lock" 600 || return 1

    exec 9<>"$_wazuh_lock" || {
        _wazuh_error "cannot open lock file: $_wazuh_lock"
        return 1
    }
    flock -x 9 || {
        _wazuh_error "cannot acquire lock: $_wazuh_lock"
        return 1
    }

    "$@"
)

wazuh_env_get() (
    [ "$#" -eq 1 ] || { _wazuh_error 'usage: wazuh_env_get NAME'; return 2; }
    _wazuh_name=${1-}
    _wazuh_validate_name "$_wazuh_name" || return 2
    _wazuh_file=$(wazuh_env_get_file) || return 2
    if [ ! -e "$_wazuh_file" ] && [ ! -L "$_wazuh_file" ]; then
        _wazuh_validate_base_dir_if_present || return 2
        return 1
    fi
    _wazuh_validate_credentials_file || return 2

    awk -v wanted="$_wazuh_name" '
        function trim_left(s)  { sub(/^[[:space:]]+/, "", s); return s }
        function trim_right(s) { sub(/[[:space:]]+$/, "", s); return s }
        function decode_double(s,    out, i, c, n) {
            out = ""
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1)
                if (c == "\\" && i < length(s)) {
                    n = substr(s, i + 1, 1)
                    if (n == "\\" || n == "\"" || n == "$" || n == "`") {
                        out = out n
                        i++
                        continue
                    }
                }
                out = out c
            }
            return out
        }
        {
            line = trim_left($0)
            if (line == "" || substr(line, 1, 1) == "#")
                next

            equal = index(line, "=")
            if (!equal)
                next

            name = trim_right(substr(line, 1, equal - 1))
            if (name != wanted)
                next

            value = trim_left(substr(line, equal + 1))
            value = trim_right(value)
            if ((substr(value, 1, 1) == "\047" && substr(value, length(value), 1) != "\047") ||
                (substr(value, 1, 1) == "\"" && substr(value, length(value), 1) != "\"")) {
                bad = 1
                next
            }
            if (length(value) >= 2 && substr(value, 1, 1) == "\047" &&
                substr(value, length(value), 1) == "\047") {
                value = substr(value, 2, length(value) - 2)
            } else if (length(value) >= 2 && substr(value, 1, 1) == "\"" &&
                       substr(value, length(value), 1) == "\"") {
                value = decode_double(substr(value, 2, length(value) - 2))
            }
            result = value
            found = 1
        }
        END {
            if (!found)
                exit (bad ? 2 : 1)
            if (bad) exit 2
            print result
        }
    ' "$_wazuh_file"
)

_wazuh_env_mutate_locked() (
    _wazuh_action=${1-}
    _wazuh_name=${2-}
    _wazuh_value_file=${3-}
    _wazuh_file=$(wazuh_env_get_file) || return 1
    _wazuh_base=$(wazuh_base_get_dir) || return 1

    if [ -e "$_wazuh_file" ] || [ -L "$_wazuh_file" ]; then
        _wazuh_validate_credentials_file || return 1
        if [ -s "$_wazuh_file" ] && [ "$(tail -c 1 -- "$_wazuh_file" | od -An -tu1 | tr -d '[:space:]')" != 10 ]; then
            _wazuh_error 'credentials.env must end with a newline; refusing to alter operator bytes'
            return 1
        fi
        _wazuh_source=$_wazuh_file
    else
        if [ "$_wazuh_action" = unset ]; then
            return 0
        fi
        _wazuh_source=/dev/null
    fi

    _wazuh_tmp=$(mktemp "$_wazuh_base/.credentials.env.XXXXXX") || {
        _wazuh_error 'cannot create a temporary credentials file'
        return 1
    }
    trap 'rm -f -- "$_wazuh_tmp"' 0
    trap 'return 130' 1 2 3 15

    if ! awk -v action="$_wazuh_action" -v wanted="$_wazuh_name" \
             -v value_file="$_wazuh_value_file" '
        function lhs_name(line,    equal, lhs) {
            sub(/^[[:space:]]+/, "", line)
            if (substr(line, 1, 1) == "#")
                return ""
            equal = index(line, "=")
            if (!equal)
                return ""
            lhs = substr(line, 1, equal - 1)
            sub(/[[:space:]]+$/, "", lhs)
            return lhs
        }
        function quote_value(s,    out, i, c) {
            out = "\""
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1)
                if (c == "\\" || c == "\"" || c == "$" || c == "`")
                    out = out "\\"
                out = out c
            }
            return out "\""
        }
        BEGIN {
            begin_marker = "# >>> wazuh generated — do not edit <<<"
            end_marker = "# >>> end wazuh generated <<<"
            warning_1 = "# Editing a value here does not change the deployment."
            warning_2 = "# To rotate, use wazuh-passwords-tool.sh."
            value = ""
            if (action == "set") {
                read_status = (getline value < value_file)
                close(value_file)
                if (read_status < 0) {
                    print "wazuh-credentials: cannot read temporary value" > "/dev/stderr"
                    exit 42
                }
                assignment = wanted "=" quote_value(value)
            }
        }
        $0 == begin_marker {
            if (inside || begin_count > 0) {
                bad = 1
                next
            }
            begin_count++
            inside = 1
            print
            next
        }
        $0 == end_marker {
            if (!inside || end_count > 0) {
                bad = 1
                next
            }
            if (action == "set" && !written) {
                print assignment
                written = 1
            }
            end_count++
            inside = 0
            print
            next
        }
        {
            if (inside && lhs_name($0) == wanted) {
                if (action == "set" && !written) {
                    print assignment
                    written = 1
                }
                next
            }
            print
        }
        END {
            if (inside || begin_count != end_count || begin_count > 1 || bad) {
                print "wazuh-credentials: malformed Wazuh-managed block" > "/dev/stderr"
                exit 42
            }
            if (begin_count == 0 && action == "set") {
                if (NR > 0)
                    print ""
                print begin_marker
                print warning_1
                print warning_2
                print assignment
                print end_marker
            }
        }
    ' "$_wazuh_source" >"$_wazuh_tmp"; then
        _wazuh_error 'credentials file was not modified'
        return 1
    fi

    chown root:root "$_wazuh_tmp" || return 1
    chmod 0600 "$_wazuh_tmp" || return 1
    mv -f -- "$_wazuh_tmp" "$_wazuh_file" || {
        _wazuh_error 'cannot replace credentials.env atomically'
        return 1
    }
    trap - 0 1 2 3 15
    _wazuh_restorecon "$_wazuh_file" || return 1
    _wazuh_validate_credentials_file
)

wazuh_env_set() (
    if [ "$#" -ne 2 ]; then
        _wazuh_error 'usage: wazuh_env_set NAME VALUE'
        return 1
    fi
    _wazuh_name=$1
    _wazuh_value=$2
    _wazuh_validate_name "$_wazuh_name" || return 1

    case $_wazuh_value in
        *"
"*)
            _wazuh_error "value for $_wazuh_name must not contain a newline"
            return 1
            ;;
    esac
    _wazuh_cr=$(printf '\r')
    case $_wazuh_value in
        *"$_wazuh_cr"*)
            _wazuh_error "value for $_wazuh_name must not contain a carriage return"
            return 1
            ;;
    esac

    _wazuh_ensure_base_dir || return 1
    _wazuh_base=$(wazuh_base_get_dir) || return 1
    _wazuh_value_file=$(mktemp "$_wazuh_base/.credential-value.XXXXXX") || {
        _wazuh_error 'cannot create a temporary value file'
        return 1
    }
    trap 'rm -f -- "$_wazuh_value_file"' 0
    trap 'return 130' 1 2 3 15
    chmod 0600 "$_wazuh_value_file" || return 1
    printf '%s' "$_wazuh_value" >"$_wazuh_value_file" || return 1

    _wazuh_with_lock _wazuh_env_mutate_locked set "$_wazuh_name" "$_wazuh_value_file"
)

wazuh_env_unset() (
    if [ "$#" -ne 1 ]; then
        _wazuh_error 'usage: wazuh_env_unset NAME'
        return 1
    fi
    _wazuh_validate_name "$1" || return 1
    _wazuh_with_lock _wazuh_env_mutate_locked unset "$1" ''
)

wazuh_ca_get_dir() (
    _wazuh_ca_dir=
    _wazuh_ca_dir_is_set=0

    _wazuh_status=0
    _wazuh_file_value=$(wazuh_env_get WAZUH_CA_DIR) || _wazuh_status=$?
    case $_wazuh_status in
        0)
            _wazuh_ca_dir=$_wazuh_file_value
            _wazuh_ca_dir_is_set=1
            ;;
        1) ;;
        *) return 1 ;;
    esac

    if [ "${WAZUH_CA_DIR+x}" = x ]; then
        _wazuh_ca_dir=${WAZUH_CA_DIR-}
        _wazuh_ca_dir_is_set=1
    fi

    if [ "$_wazuh_ca_dir_is_set" -eq 0 ]; then
        _wazuh_base=$(wazuh_base_get_dir) || return 1
        _wazuh_ca_dir=$_wazuh_base/ca
    fi

    _wazuh_validate_absolute_path "$_wazuh_ca_dir" || return 1
    printf '%s\n' "$_wazuh_ca_dir"
)

_wazuh_validate_ca_files() (
    _wazuh_ca_dir=${1-}
    _wazuh_cert=$_wazuh_ca_dir/root-ca.pem
    _wazuh_key=$_wazuh_ca_dir/root-ca.key

    _wazuh_validate_ancestors "$_wazuh_ca_dir" || return 1
    _wazuh_validate_directory_node "$_wazuh_ca_dir" 700 || return 1

    _wazuh_cert_exists=0
    _wazuh_key_exists=0
    if [ -e "$_wazuh_cert" ] || [ -L "$_wazuh_cert" ]; then
        _wazuh_cert_exists=1
    fi
    if [ -e "$_wazuh_key" ] || [ -L "$_wazuh_key" ]; then
        _wazuh_key_exists=1
    fi

    if [ "$_wazuh_cert_exists" -eq 0 ] && [ "$_wazuh_key_exists" -eq 0 ]; then
        _wazuh_error "CA material is absent from $_wazuh_ca_dir"
        return 1
    fi
    if [ "$_wazuh_cert_exists" -eq 0 ]; then
        _wazuh_error "root-ca.key exists without root-ca.pem in $_wazuh_ca_dir"
        return 1
    fi

    _wazuh_validate_regular_file "$_wazuh_cert" 644 || return 1
    if ! openssl x509 -in "$_wazuh_cert" -noout >/dev/null 2>&1; then
        _wazuh_error "invalid X.509 certificate: $_wazuh_cert"
        return 1
    fi
    if ! openssl x509 -in "$_wazuh_cert" -checkend 0 -noout >/dev/null 2>&1; then
        _wazuh_error "expired X.509 certificate: $_wazuh_cert"
        return 1
    fi
    _wazuh_text=$(LC_ALL=C openssl x509 -in "$_wazuh_cert" -noout -text 2>/dev/null) || return 1
    case $_wazuh_text in
        *'CA:TRUE'*) ;;
        *) _wazuh_error "certificate is not a CA: $_wazuh_cert"; return 1 ;;
    esac
    openssl verify -CAfile "$_wazuh_cert" "$_wazuh_cert" >/dev/null 2>&1 || {
        _wazuh_error "CA certificate is not currently valid: $_wazuh_cert"
        return 1
    }

    # Anchor-only is the expected state for an externally managed CA.
    if [ "$_wazuh_key_exists" -eq 0 ]; then
        return 0
    fi

    _wazuh_validate_regular_file "$_wazuh_key" 400 || return 1
    if ! openssl pkey -in "$_wazuh_key" -passin pass: -check -noout </dev/null >/dev/null 2>&1; then
        _wazuh_error "invalid private key: $_wazuh_key"
        return 1
    fi

    _wazuh_cert_pub=$(mktemp "$_wazuh_ca_dir/.cert-pub.XXXXXX") || return 1
    _wazuh_key_pub=$(mktemp "$_wazuh_ca_dir/.key-pub.XXXXXX") || {
        rm -f -- "$_wazuh_cert_pub"
        return 1
    }
    trap 'rm -f -- "$_wazuh_cert_pub" "$_wazuh_key_pub"' 0
    trap 'return 130' 1 2 3 15
    chmod 0600 "$_wazuh_cert_pub" "$_wazuh_key_pub" || return 1

    openssl x509 -in "$_wazuh_cert" -pubkey -noout >"$_wazuh_cert_pub" 2>/dev/null || return 1
    openssl pkey -in "$_wazuh_key" -passin pass: -pubout </dev/null >"$_wazuh_key_pub" 2>/dev/null || return 1
    if ! cmp -s -- "$_wazuh_cert_pub" "$_wazuh_key_pub"; then
        _wazuh_error 'root-ca.key does not match root-ca.pem'
        return 1
    fi

    rm -f -- "$_wazuh_cert_pub" "$_wazuh_key_pub"
    trap - 0 1 2 3 15
)

_wazuh_ensure_ca_directory() (
    _wazuh_ca_dir=${1-}
    _wazuh_validate_absolute_path "$_wazuh_ca_dir" || return 1

    if [ -L "$_wazuh_ca_dir" ]; then
        _wazuh_error "refusing symbolic-link CA directory: $_wazuh_ca_dir"
        return 1
    fi
    if [ ! -e "$_wazuh_ca_dir" ]; then
        _wazuh_make_secure_tree "$_wazuh_ca_dir" || {
            _wazuh_error "cannot create CA directory: $_wazuh_ca_dir"
            return 1
        }
        _wazuh_restorecon "$_wazuh_ca_dir" || return 1
    fi

    _wazuh_validate_ancestors "$_wazuh_ca_dir" || return 1
    _wazuh_validate_directory_node "$_wazuh_ca_dir" 700
)

_wazuh_ca_validate_locked() (
    _wazuh_ca_dir=$(wazuh_ca_get_dir) || return 1
    _wazuh_validate_ca_files "$_wazuh_ca_dir"
)

wazuh_ca_validate() (
    _wazuh_with_lock _wazuh_ca_validate_locked
)

_wazuh_ca_ensure_locked() (
    _wazuh_ca_dir=$(wazuh_ca_get_dir) || return 1
    _wazuh_ensure_ca_directory "$_wazuh_ca_dir" || return 1

    _wazuh_cert=$_wazuh_ca_dir/root-ca.pem
    _wazuh_key=$_wazuh_ca_dir/root-ca.key

    _wazuh_cert_exists=0
    _wazuh_key_exists=0
    if [ -e "$_wazuh_cert" ] || [ -L "$_wazuh_cert" ]; then
        _wazuh_cert_exists=1
    fi
    if [ -e "$_wazuh_key" ] || [ -L "$_wazuh_key" ]; then
        _wazuh_key_exists=1
    fi

    if [ "$_wazuh_cert_exists" -eq 1 ] || [ "$_wazuh_key_exists" -eq 1 ]; then
        _wazuh_validate_ca_files "$_wazuh_ca_dir"
        return $?
    fi

    command -v openssl >/dev/null 2>&1 || {
        _wazuh_error 'openssl is required to generate the root CA'
        return 1
    }

    _wazuh_tmp_dir=$(mktemp -d "$_wazuh_ca_dir/.root-ca.XXXXXX") || {
        _wazuh_error "cannot create a temporary directory in $_wazuh_ca_dir"
        return 1
    }
    trap 'rm -rf -- "$_wazuh_tmp_dir"' 0
    trap 'return 130' 1 2 3 15
    chmod 0700 "$_wazuh_tmp_dir" || return 1
    _wazuh_config=$_wazuh_tmp_dir/openssl.cnf

    (umask 077; printf '%s\n' \
        '[req]' \
        'distinguished_name = dn' \
        'x509_extensions = v3_ca' \
        'prompt = no' \
        '[dn]' \
        'OU = Wazuh' \
        'O = Wazuh' \
        'L = California' \
        '[v3_ca]' \
        'basicConstraints = critical, CA:TRUE' \
        'keyUsage = critical, keyCertSign, cRLSign' \
        'subjectKeyIdentifier = hash' \
        'authorityKeyIdentifier = keyid:always' \
        >"$_wazuh_config") || return 1

    if ! (umask 077; openssl req -x509 -new -nodes -newkey rsa:2048 \
        -sha256 -days 3650 -batch -config "$_wazuh_config" \
        -keyout "$_wazuh_tmp_dir/root-ca.key" \
        -out "$_wazuh_tmp_dir/root-ca.pem" >/dev/null 2>&1); then
        _wazuh_error 'OpenSSL failed to generate the root CA'
        return 1
    fi

    chown root:root "$_wazuh_tmp_dir/root-ca.key" "$_wazuh_tmp_dir/root-ca.pem" || return 1
    chmod 0400 "$_wazuh_tmp_dir/root-ca.key" || return 1
    chmod 0644 "$_wazuh_tmp_dir/root-ca.pem" || return 1

    # Publishing the key first (hard links refuse existing targets) makes an interrupted installation fail closed as an
    # explicit key-without-certificate state instead of silently looking like
    # an externally managed anchor.
    ln -T -- "$_wazuh_tmp_dir/root-ca.key" "$_wazuh_key" || return 1
    ln -T -- "$_wazuh_tmp_dir/root-ca.pem" "$_wazuh_cert" || return 1
    _wazuh_restorecon "$_wazuh_key" || return 1
    _wazuh_restorecon "$_wazuh_cert" || return 1

    rm -rf -- "$_wazuh_tmp_dir"
    trap - 0 1 2 3 15
    _wazuh_validate_ca_files "$_wazuh_ca_dir"
)

wazuh_ca_ensure() (
    _wazuh_with_lock _wazuh_ca_ensure_locked
)

_wazuh_random_below() (
    _wazuh_limit=${1-}
    case $_wazuh_limit in
        ''|*[!0-9]*|0) return 1 ;;
    esac

    _wazuh_ceiling=$((65536 - (65536 % _wazuh_limit)))
    while :; do
        _wazuh_number=$(od -An -N2 -tu2 /dev/urandom 2>/dev/null) || return 1
        _wazuh_number=$(printf '%s' "$_wazuh_number" | tr -d '[:space:]')
        case $_wazuh_number in
            ''|*[!0-9]*) return 1 ;;
        esac
        if [ "$_wazuh_number" -lt "$_wazuh_ceiling" ]; then
            printf '%s\n' $((_wazuh_number % _wazuh_limit))
            return 0
        fi
    done
)

_wazuh_random_char() (
    _wazuh_alphabet=${1-}
    _wazuh_length=${#_wazuh_alphabet}
    [ "$_wazuh_length" -gt 0 ] || return 1
    _wazuh_index=$(_wazuh_random_below "$_wazuh_length") || return 1
    _wazuh_position=$((_wazuh_index + 1))
    printf '%s' "$_wazuh_alphabet" | cut -c "$_wazuh_position"
)

_wazuh_replace_char() (
    _wazuh_text=${1-}
    _wazuh_position=${2-}
    _wazuh_character=${3-}

    if [ "$_wazuh_position" -le 1 ]; then
        _wazuh_prefix=
    else
        _wazuh_prefix=$(printf '%s' "$_wazuh_text" | cut -c "1-$((_wazuh_position - 1))")
    fi
    _wazuh_suffix=$(printf '%s' "$_wazuh_text" | cut -c "$((_wazuh_position + 1))-" )
    printf '%s%s%s' "$_wazuh_prefix" "$_wazuh_character" "$_wazuh_suffix"
)

wazuh_password_generate() (
    _wazuh_alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,_+:@%^=~-'

    # Finite entropy reads avoid SIGPIPE under a caller's pipefail. Rejection
    # sampling (bytes < 219 for a 73-character alphabet) avoids modulo bias.
    _wazuh_password=
    while [ "${#_wazuh_password}" -lt 32 ]; do
        _wazuh_bytes=$(od -An -v -N128 -tu1 /dev/urandom) || return 1
        [ -n "$_wazuh_bytes" ] || return 1
        _wazuh_chunk=$(printf '%s\n' "$_wazuh_bytes" | awk -v a="$_wazuh_alphabet" '
            { for (i=1; i<=NF; i++) if ($i < 219) printf "%s", substr(a, ($i % 73)+1, 1) }
        ') || return 1
        _wazuh_password=$_wazuh_password$_wazuh_chunk
    done
    _wazuh_password=$(printf '%s' "$_wazuh_password" | cut -c 1-32) || return 1

    _wazuh_index=$(_wazuh_random_below 32) || return 1
    _wazuh_pos_lower=$((_wazuh_index + 1))
    while :; do
        _wazuh_index=$(_wazuh_random_below 32) || return 1
        _wazuh_pos_upper=$((_wazuh_index + 1))
        [ "$_wazuh_pos_upper" -ne "$_wazuh_pos_lower" ] && break
    done
    while :; do
        _wazuh_index=$(_wazuh_random_below 32) || return 1
        _wazuh_pos_digit=$((_wazuh_index + 1))
        if [ "$_wazuh_pos_digit" -ne "$_wazuh_pos_lower" ] &&
           [ "$_wazuh_pos_digit" -ne "$_wazuh_pos_upper" ]; then
            break
        fi
    done

    _wazuh_char=$(_wazuh_random_char 'abcdefghijklmnopqrstuvwxyz') || return 1
    _wazuh_password=$(_wazuh_replace_char "$_wazuh_password" "$_wazuh_pos_lower" "$_wazuh_char") || return 1
    _wazuh_char=$(_wazuh_random_char 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') || return 1
    _wazuh_password=$(_wazuh_replace_char "$_wazuh_password" "$_wazuh_pos_upper" "$_wazuh_char") || return 1
    _wazuh_char=$(_wazuh_random_char '0123456789') || return 1
    _wazuh_password=$(_wazuh_replace_char "$_wazuh_password" "$_wazuh_pos_digit" "$_wazuh_char") || return 1

    wazuh_password_validate "$_wazuh_password" >/dev/null || return 1
    printf '%s\n' "$_wazuh_password"
)

wazuh_password_validate() (
    if [ "$#" -ne 1 ]; then
        _wazuh_error 'usage: wazuh_password_validate VALUE'
        return 1
    fi
    _wazuh_password=$1
    _wazuh_length=${#_wazuh_password}

    if [ "$_wazuh_length" -lt 12 ] || [ "$_wazuh_length" -gt 64 ]; then
        _wazuh_error 'password must contain between 12 and 64 characters'
        return 1
    fi
    case $_wazuh_password in
        *[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz]*) ;;
        *)
            _wazuh_error 'password must contain at least one ASCII letter'
            return 1
            ;;
    esac
    case $_wazuh_password in
        *[0123456789]*) ;;
        *)
            _wazuh_error 'password must contain at least one digit'
            return 1
            ;;
    esac
    case $_wazuh_password in
        *"
"*)
            _wazuh_error 'password must not contain a newline'
            return 1
            ;;
    esac
    _wazuh_cr=$(printf '\r')
    case $_wazuh_password in
        *"$_wazuh_cr"*)
            _wazuh_error 'password must not contain a carriage return'
            return 1
            ;;
    esac
)
