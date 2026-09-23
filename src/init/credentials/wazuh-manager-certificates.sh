#!/bin/sh

# Wazuh manager certificate helpers.
#
# This file is a sourceable POSIX /bin/sh library. It depends on the public and
# locking helpers from wazuh-credentials.sh, which must be sourced first:
#
#   . /usr/share/wazuh-manager/lib/wazuh-credentials.sh
#   . /usr/share/wazuh-manager/lib/wazuh-manager-certificates.sh
#
# Importing this file performs no action and does not change the caller's shell
# options, umask, IFS, working directory, or traps.
#
# Public API
# ----------
#   wazuh_manager_certificates_ensure
#       Idempotently installs the manager's two certificate pairs:
#
#         indexer-connector.pem       clientAuth
#         indexer-connector-key.pem
#         remoted.pem                 serverAuth; leaf followed by root CA
#         remoted-key.pem
#         root-ca.pem                 public trust anchor
#
#       Existing complete pairs are validated and never regenerated. A partial
#       pair is an error. Missing pairs are issued only when root-ca.key exists.
#
#   wazuh_manager_certificates_validate
#       Validates paths, ownership, modes, key/certificate correspondence,
#       validity, CA chain, basic constraints, EKU, and Remoted SAN presence.
#
#   wazuh_manager_remoted_sans
#       Prints the resolved Remoted SANs, one typed entry per line. If no
#       explicit list is configured, every IPv4/IPv6 address assigned to every
#       local interface is included, together with the node hostname/FQDN.
#       Requires successful iproute2 discovery (no loopback-only fallback).
#       Tentative/DAD-failed addresses are skipped; IPs are canonicalized.
#       This helper creates a private temporary workspace below the base.
#
# Configuration
# -------------
#   WAZUH_MANAGER_CERT_SANS
#       Exact comma-separated SAN list for indexer-connector.pem.
#       Example: DNS:manager-1.example.com,IP:10.0.0.10
#
#   WAZUH_MANAGER_REMOTED_CERT_SANS
#       Exact comma-separated SAN list for remoted.pem. When absent, SANs are
#       discovered from all interfaces. An explicitly empty value is invalid.
#
#   WAZUH_MANAGER_NODE_NAME
#       Certificate common name. Defaults to hostname -s.
#
#   WAZUH_MANAGER_HOME
#       Manager installation directory. Defaults to /var/wazuh-manager.
#
#   WAZUH_MANAGER_CERT_DIR
#       Optional absolute certificates-directory override for sandbox installs.
#       Defaults to $WAZUH_MANAGER_HOME/etc/certs.
#
#   WAZUH_MANAGER_USER / WAZUH_MANAGER_GROUP
#       Service identity. Both default to wazuh-manager.
#
# The two SAN settings follow the shared credential precedence: value in
# <wazuh_base_get_dir>/credentials.env, then process environment override, then derived
# default. Values may be typed (DNS:name, IP:address) or untyped; untyped values
# are classified as IP or DNS after validation.

_wmc_error() (
    printf '%s\n' "wazuh-manager-certificates: $*" >&2
)

_wmc_require_shared_helpers() (
    for _wmc_function in \
        wazuh_base_get_dir \
        _wazuh_ensure_base_dir \
        _wazuh_check_existing_tree \
        _wazuh_ca_ensure_locked \
        wazuh_ca_ensure \
        wazuh_ca_validate \
        wazuh_ca_get_dir \
        wazuh_env_get \
        _wazuh_with_lock \
        _wazuh_validate_ca_files
    do
        if ! command -v "$_wmc_function" >/dev/null 2>&1; then
            _wmc_error "missing $_wmc_function; source wazuh-credentials.sh first"
            return 1
        fi
    done
)

_wmc_require_commands() (
    for _wmc_command in awk cat chmod chown cmp cp cut date dirname flock \
        getent grep hostname id install ln mkdir mktemp mv openssl rm sed stat tr
    do
        if ! command -v "$_wmc_command" >/dev/null 2>&1; then
            _wmc_error "required command is unavailable: $_wmc_command"
            return 1
        fi
    done
)

_wmc_validate_path() (
    _wmc_path=${1-}

    case $_wmc_path in
        ''|/)
            _wmc_error 'path must be a non-empty absolute path other than /'
            return 1
            ;;
        /*) ;;
        *)
            _wmc_error "path must be absolute: $_wmc_path"
            return 1
            ;;
    esac
    case $_wmc_path in
        *'//'*)
            _wmc_error "path must not contain repeated slashes: $_wmc_path"
            return 1
            ;;
        */./*|*/.|*/../*|*/..|*/)
            _wmc_error "path contains a forbidden component: $_wmc_path"
            return 1
            ;;
        *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./-]*)
            _wmc_error "path contains unsupported characters: $_wmc_path"
            return 1
            ;;
    esac
)

_wmc_validate_parent_tree() (
    _wmc_parent=${1%/*}
    [ -n "$_wmc_parent" ] || _wmc_parent=/
    _wmc_check_parent "$_wmc_parent"
)

_wmc_check_parent() (
    if [ "$1" != / ]; then
        _wmc_parent=${1%/*}
        [ -n "$_wmc_parent" ] || _wmc_parent=/
        _wmc_check_parent "$_wmc_parent" || return 1
    fi
    [ ! -L "$1" ] && [ -d "$1" ] || {
        _wmc_error "parent must be a real directory: $1"; return 1;
    }
    [ "$(stat -c %u -- "$1")" = 0 ] || {
        _wmc_error "parent must be root-owned: $1"; return 1;
    }
    _wmc_mode=$(stat -c %a -- "$1") || return 1
    [ "$((0$_wmc_mode & 0022))" -eq 0 ] || {
        _wmc_error "parent must not be group/world writable: $1"; return 1;
    }
)

# Missing service-directory parents are root:service-group 0750, so the
# daemon can traverse them. Never change pre-existing owners or permissions.
_wmc_make_parents() (
    [ "$1" = / ] && { _wmc_check_parent /; return $?; }
    _wmc_parent=${1%/*}
    [ -n "$_wmc_parent" ] || _wmc_parent=/
    _wmc_make_parents "$_wmc_parent" "$2" || return 1
    if [ ! -e "$1" ] && [ ! -L "$1" ]; then
        (umask 077; mkdir -m 0700 -- "$1") || return 1
        chown "root:$2" "$1" || return 1
        chmod 0750 "$1" || return 1
        _wazuh_restorecon "$1" || return 1
    fi
    _wmc_check_parent "$1"
)
_wmc_get_identity() (
    _wmc_user=${WAZUH_MANAGER_USER-wazuh-manager}
    _wmc_group=${WAZUH_MANAGER_GROUP-wazuh-manager}

    if [ -z "$_wmc_user" ] || [ -z "$_wmc_group" ]; then
        _wmc_error 'manager user and group must not be empty'
        return 1
    fi
    _wmc_uid=$(id -u "$_wmc_user" 2>/dev/null) || {
        _wmc_error "manager user does not exist: $_wmc_user"
        return 1
    }
    _wmc_gid=$(getent group "$_wmc_group" | awk -F: 'NR == 1 { print $3 }')
    if [ -z "$_wmc_gid" ]; then
        _wmc_error "manager group does not exist: $_wmc_group"
        return 1
    fi
    printf '%s:%s:%s:%s\n' "$_wmc_user" "$_wmc_group" "$_wmc_uid" "$_wmc_gid"
)

_wmc_get_cert_dir() (
    if [ "${WAZUH_MANAGER_HOME+x}" = x ]; then
        _wmc_home=${WAZUH_MANAGER_HOME-}
    else
        _wmc_home=/var/wazuh-manager
    fi
    _wmc_validate_path "$_wmc_home" || return 1

    if [ "${WAZUH_MANAGER_CERT_DIR+x}" = x ]; then
        _wmc_dir=${WAZUH_MANAGER_CERT_DIR-}
        _wmc_validate_path "$_wmc_dir" || return 1
    else
        _wmc_dir=$_wmc_home/etc/certs
    fi
    printf '%s\n' "$_wmc_dir"
)

_wmc_prepare_cert_dir() (
    _wmc_dir=${1-}
    _wmc_group=${2-}
    _wmc_gid=${3-}
    _wmc_create=${4-0}

    _wmc_validate_path "$_wmc_dir" || return 1
    if [ -L "$_wmc_dir" ]; then
        _wmc_error "refusing symbolic-link certificate directory: $_wmc_dir"
        return 1
    fi
    if [ ! -e "$_wmc_dir" ]; then
        if [ "$_wmc_create" -ne 1 ]; then
            _wmc_error "certificate directory does not exist: $_wmc_dir"
            return 1
        fi
        _wmc_make_parents "${_wmc_dir%/*}" "$_wmc_group" || return 1
        _wmc_validate_parent_tree "$_wmc_dir" || return 1
        install -d -m 1770 -o root -g "$_wmc_group" "$_wmc_dir" || {
            _wmc_error "cannot create certificate directory: $_wmc_dir"
            return 1
        }
        if command -v restorecon >/dev/null 2>&1; then
            restorecon "$_wmc_dir" >/dev/null 2>&1 || {
                _wmc_error "failed to restore SELinux context: $_wmc_dir"
                return 1
            }
        fi
    fi

    _wmc_validate_parent_tree "$_wmc_dir" || return 1
    if [ ! -d "$_wmc_dir" ]; then
        _wmc_error "not a directory: $_wmc_dir"
        return 1
    fi
    _wmc_owner=$(stat -c '%u:%g' -- "$_wmc_dir" 2>/dev/null) || return 1
    if [ "$_wmc_owner" != "0:$_wmc_gid" ]; then
        _wmc_error "certificate directory must be root:$_wmc_group: $_wmc_dir"
        return 1
    fi
    _wmc_mode=$(stat -c '%a' -- "$_wmc_dir" 2>/dev/null) || return 1
    if [ "$_wmc_mode" != 1770 ]; then
        _wmc_error "certificate directory $_wmc_dir must have mode 1770 (found $_wmc_mode)"
        return 1
    fi
)

_wmc_validate_file() (
    _wmc_file=${1-}
    _wmc_uid=${2-}
    _wmc_gid=${3-}
    _wmc_mode_required=${4-}

    if [ -L "$_wmc_file" ]; then
        _wmc_error "refusing symbolic-link file: $_wmc_file"
        return 1
    fi
    if [ ! -f "$_wmc_file" ]; then
        _wmc_error "not a regular file: $_wmc_file"
        return 1
    fi
    _wmc_owner=$(stat -c '%u:%g' -- "$_wmc_file" 2>/dev/null) || return 1
    if [ "$_wmc_owner" != "$_wmc_uid:$_wmc_gid" ]; then
        _wmc_error "unexpected owner for $_wmc_file"
        return 1
    fi
    _wmc_mode=$(stat -c '%a' -- "$_wmc_file" 2>/dev/null) || return 1
    if [ "$_wmc_mode" != "$_wmc_mode_required" ]; then
        _wmc_error "file $_wmc_file must have mode $_wmc_mode_required (found $_wmc_mode)"
        return 1
    fi
)

_wmc_validate_dns() (
    _wmc_dns=${1-}
    [ -n "$_wmc_dns" ] || return 1
    [ "${#_wmc_dns}" -le 253 ] || return 1
    case $_wmc_dns in
        *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-]*|.*|*.|*-.*|*.-*|*..*)
            return 1
            ;;
    esac

    _wmc_old_ifs=$IFS
    IFS=.
    set -- $_wmc_dns
    IFS=$_wmc_old_ifs
    for _wmc_label in "$@"; do
        [ -n "$_wmc_label" ] || return 1
        [ "${#_wmc_label}" -le 63 ] || return 1
        case $_wmc_label in
            -*|*-) return 1 ;;
        esac
    done
)

_wmc_validate_ipv4() (
    _wmc_ip=${1-}
    case $_wmc_ip in
        *[!0123456789.]*|.*|*.|*..*) return 1 ;;
    esac
    _wmc_old_ifs=$IFS
    IFS=.
    set -- $_wmc_ip
    IFS=$_wmc_old_ifs
    [ "$#" -eq 4 ] || return 1
    for _wmc_octet in "$@"; do
        case $_wmc_octet in ''|*[!0-9]*) return 1 ;; esac
        [ "${#_wmc_octet}" -le 3 ] || return 1
        if [ "${#_wmc_octet}" -gt 1 ] && [ "${_wmc_octet#?}" != "$_wmc_octet" ] &&
           [ "${_wmc_octet%${_wmc_octet#?}}" = 0 ]; then
            return 1
        fi
        [ "$_wmc_octet" -le 255 ] || return 1
    done
)

_wmc_validate_ipv6() (
    case ${1-} in *:*) ;; *) return 1 ;; esac
    _wmc_normalize_ip "$1" >/dev/null
)

# Canonical IPv4 or expanded IPv6, including IPv4-mapped IPv6.
# Rejects CIDRs, zone IDs, leading-zero IPv4, malformed compression and hex.
_wmc_normalize_ip() (
    printf '%s\n' "${1-}" | LC_ALL=C awk '
        function v4(s, a,n,i) {
            n=split(s,a,".")
            if(n!=4) return 0
            for(i=1;i<=4;i++)
                if(a[i]!~/^[0-9]+$/ || length(a[i])>3 ||
                   (length(a[i])>1 && substr(a[i],1,1)=="0") || a[i]+0>255) return 0
            return 1
        }
        function hex(s, i,v,c) {
            v=0
            for(i=1;i<=length(s);i++) {
                c=index("0123456789abcdef",substr(s,i,1))-1
                if(c<0) return -1
                v=16*v+c
            }
            return v
        }
        {
            s=tolower($0)
            if(index(s,":")==0) {
                if(!v4(s)) exit 1
                print s; next
            }
            if(s~/\./) {
                tail=s
                sub(/^.*:/,"",tail)
                if(!v4(tail)) exit 1
                split(tail,q,".")
                s=substr(s,1,length(s)-length(tail)) sprintf("%x:%x",q[1]*256+q[2],q[3]*256+q[4])
            }
            p=index(s,"::")
            if(p) {
                l=substr(s,1,p-1); r=substr(s,p+2)
                if(index(r,"::")) exit 1
                nl=(l==""?0:split(l,a,":")); nr=(r==""?0:split(r,b,":"))
                if(nl+nr>=8) exit 1
            } else {
                nl=split(s,a,":"); nr=0
                if(nl!=8) exit 1
            }
            out=""
            for(i=1;i<=8;i++) {
                if(i<=nl) h=a[i]
                else if(i>8-nr) h=b[i-(8-nr)]
                else h="0"
                if(h=="" || length(h)>4 || h!~/^[0-9a-f]+$/) exit 1
                out=out (i>1?":":"") sprintf("%x",hex(h))
            }
            print out
        }
    '
)
_wmc_classify_san() (
    _wmc_san=${1-}
    case $_wmc_san in
        DNS:*|dns:*)
            _wmc_value=${_wmc_san#*:}
            _wmc_validate_dns "$_wmc_value" || return 1
            printf 'DNS:%s\n' "$_wmc_value" ;;
        IP:*|ip:*)
            _wmc_value=$(_wmc_normalize_ip "${_wmc_san#*:}") || return 1
            printf 'IP:%s\n' "$_wmc_value" ;;
        *:*)
            _wmc_value=$(_wmc_normalize_ip "$_wmc_san") || return 1
            printf 'IP:%s\n' "$_wmc_value" ;;
        *)
            if _wmc_validate_ipv4 "$_wmc_san"; then
                printf 'IP:%s\n' "$_wmc_san"
            else
                case $_wmc_san in *[!0-9.]* ) ;; *) return 1 ;; esac
                _wmc_validate_dns "$_wmc_san" || return 1
                printf 'DNS:%s\n' "$_wmc_san"
            fi ;;
    esac
)
_wmc_normalize_sans() (
    _wmc_input=${1-}
    _wmc_output=${2-}
    _wmc_raw=$_wmc_output.raw

    case $_wmc_input in
        ''|,*|*,|*,,*) _wmc_error 'empty SAN entry'; return 1 ;;
    esac
    : >"$_wmc_raw" || return 1
    printf '%s' "$_wmc_input" | tr ',' '\n' |
        while IFS= read -r _wmc_item || [ -n "$_wmc_item" ]; do
            _wmc_item=$(printf '%s' "$_wmc_item" |
                sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            [ -n "$_wmc_item" ] || {
                _wmc_error 'SAN list contains an empty entry'
                exit 1
            }
            _wmc_typed=$(_wmc_classify_san "$_wmc_item") || {
                _wmc_error "invalid SAN entry: $_wmc_item"
                exit 1
            }
            printf '%s\n' "$_wmc_typed"
        done >"$_wmc_raw" || return 1

    if [ ! -s "$_wmc_raw" ]; then
        _wmc_error 'SAN list must not be empty'
        return 1
    fi

    awk '
        /^DNS:/ { key = "DNS:" tolower(substr($0, 5)) }
        /^IP:/  { key = $0 }
        !seen[key]++ { print }
    ' "$_wmc_raw" >"$_wmc_output" || return 1
)

_wmc_get_file_setting() (
    _wmc_name=${1-}
    _wmc_status=0
    _wmc_value=$(wazuh_env_get "$_wmc_name") || _wmc_status=$?
    case $_wmc_status in
        0) printf '%s\n' "$_wmc_value" ;;
        1) return 1 ;;
        *) return 2 ;;
    esac
)

_wmc_resolve_manager_san_setting() (
    _wmc_value=
    _wmc_is_set=0
    _wmc_status=0
    _wmc_file_value=$(_wmc_get_file_setting WAZUH_MANAGER_CERT_SANS) || _wmc_status=$?
    case $_wmc_status in
        0) _wmc_value=$_wmc_file_value; _wmc_is_set=1 ;;
        1) ;;
        *) return 2 ;;
    esac
    if [ "${WAZUH_MANAGER_CERT_SANS+x}" = x ]; then
        _wmc_value=${WAZUH_MANAGER_CERT_SANS-}
        _wmc_is_set=1
    fi
    [ "$_wmc_is_set" -eq 1 ] || return 1
    if [ -z "$_wmc_value" ]; then
        _wmc_error 'WAZUH_MANAGER_CERT_SANS is explicitly empty'
        return 2
    fi
    printf '%s\n' "$_wmc_value"
)

_wmc_resolve_remoted_san_setting() (
    _wmc_value=
    _wmc_is_set=0
    _wmc_status=0
    _wmc_file_value=$(_wmc_get_file_setting WAZUH_MANAGER_REMOTED_CERT_SANS) || _wmc_status=$?
    case $_wmc_status in
        0) _wmc_value=$_wmc_file_value; _wmc_is_set=1 ;;
        1) ;;
        *) return 2 ;;
    esac
    if [ "${WAZUH_MANAGER_REMOTED_CERT_SANS+x}" = x ]; then
        _wmc_value=${WAZUH_MANAGER_REMOTED_CERT_SANS-}
        _wmc_is_set=1
    fi
    [ "$_wmc_is_set" -eq 1 ] || return 1
    if [ -z "$_wmc_value" ]; then
        _wmc_error 'WAZUH_MANAGER_REMOTED_CERT_SANS is explicitly empty'
        return 2
    fi
    printf '%s\n' "$_wmc_value"
)

_wmc_node_name() (
    if [ "${WAZUH_MANAGER_NODE_NAME+x}" = x ]; then
        _wmc_node=${WAZUH_MANAGER_NODE_NAME-}
    else
        _wmc_node=$(hostname -s 2>/dev/null) || return 1
    fi
    _wmc_validate_dns "$_wmc_node" || {
        _wmc_error "invalid manager node name: $_wmc_node"
        return 1
    }
    printf '%s\n' "$_wmc_node"
)

_wmc_append_host_names() (
    _wmc_output=${1-}
    _wmc_node=$(_wmc_node_name) || return 1
    printf 'DNS:%s\n' "$_wmc_node" >>"$_wmc_output" || return 1

    _wmc_fqdn=$(hostname -f 2>/dev/null || :)
    if [ -n "$_wmc_fqdn" ] && _wmc_validate_dns "$_wmc_fqdn"; then
        printf 'DNS:%s\n' "$_wmc_fqdn" >>"$_wmc_output" || return 1
    fi
)

_wmc_default_manager_sans() (
    _wmc_output=${1-}
    _wmc_raw=$_wmc_output.raw
    : >"$_wmc_raw" || return 1
    _wmc_append_host_names "$_wmc_raw" || return 1
    printf '%s\n' 'DNS:localhost' 'IP:127.0.0.1' 'IP:::1' >>"$_wmc_raw" || return 1

    if command -v ip >/dev/null 2>&1; then
        {
            ip -o -4 route show default 2>/dev/null || :
            ip -o -6 route show default 2>/dev/null || :
        } | awk '
            { for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }
        ' | awk '!seen[$0]++' |
        while IFS= read -r _wmc_interface; do
            [ -n "$_wmc_interface" ] || continue
            ip -o addr show dev "$_wmc_interface" scope global 2>/dev/null |
                awk '{ sub(/\/.*/, "", $4); print "IP:" $4 }'
        done >>"$_wmc_raw"
    elif command -v hostname >/dev/null 2>&1; then
        hostname -I 2>/dev/null | tr ' ' '\n' |
            awk 'NF { print "IP:" $0 }' >>"$_wmc_raw"
    fi

    awk '
        /^DNS:/ { key = "DNS:" tolower(substr($0, 5)) }
        /^IP:/  { key = $0 }
        !seen[key]++ { print }
    ' "$_wmc_raw" >"$_wmc_output" || return 1
)

_wmc_default_remoted_sans() (
    _wmc_output=$1
    # Require successful enumeration, not just presence of the ip binary.
    # Includes all assigned addresses, also down/virtual/link-local interfaces.
    _wmc_addresses=$(ip -o addr show) || {
        _wmc_error 'cannot enumerate interfaces; supply WAZUH_MANAGER_REMOTED_CERT_SANS'
        return 1
    }
    _wmc_list=$(printf '%s\n' "$_wmc_addresses" | awk '
        ($3=="inet" || $3=="inet6") && $0 !~ / (tentative|dadfailed)( |$)/ {
            sub(/\/.*/, "", $4); print "IP:" $4
        }
    ') || return 1
    [ -n "$_wmc_list" ] || {
        _wmc_error 'no usable interface address; supply WAZUH_MANAGER_REMOTED_CERT_SANS'
        return 1
    }
    _wmc_append_host_names "$_wmc_output.names" || return 1
    _wmc_names=$(cat "$_wmc_output.names") || return 1
    _wmc_normalize_sans "$_wmc_names
$_wmc_list
DNS:localhost
IP:127.0.0.1
IP:::1" "$_wmc_output"
)
_wmc_resolve_manager_sans_to() (
    _wmc_output=${1-}
    _wmc_status=0
    _wmc_setting=$(_wmc_resolve_manager_san_setting) || _wmc_status=$?
    case $_wmc_status in
        0) _wmc_normalize_sans "$_wmc_setting" "$_wmc_output" ;;
        1) _wmc_default_manager_sans "$_wmc_output" ;;
        *) return 1 ;;
    esac
)

_wmc_resolve_remoted_sans_to() (
    _wmc_output=${1-}
    _wmc_status=0
    _wmc_setting=$(_wmc_resolve_remoted_san_setting) || _wmc_status=$?
    case $_wmc_status in
        0) _wmc_normalize_sans "$_wmc_setting" "$_wmc_output" ;;
        1) _wmc_default_remoted_sans "$_wmc_output" ;;
        *) return 1 ;;
    esac
)

wazuh_manager_remoted_sans() (
    _wmc_require_shared_helpers || return 1
    _wazuh_ensure_base_dir || return 1
    _wmc_base=$(wazuh_base_get_dir) || return 1
    _wmc_tmp=$(mktemp -d "$_wmc_base/.sans.XXXXXX") || return 1
    trap 'rm -rf -- "$_wmc_tmp"' 0
    trap 'return 130' 1 2 3 15
    _wmc_resolve_remoted_sans_to "$_wmc_tmp/sans" || return 1
    cat "$_wmc_tmp/sans"
)
_wmc_write_leaf_config() (
    _wmc_config=${1-}
    _wmc_node=${2-}
    _wmc_eku=${3-}
    _wmc_sans=${4-}

    {
        printf '%s\n' '[ req ]'
        printf '%s\n' 'prompt = no'
        printf '%s\n' 'default_bits = 2048'
        printf '%s\n' 'default_md = sha256'
        printf '%s\n' 'distinguished_name = req_dn'
        printf '\n'
        printf '%s\n' '[ req_dn ]'
        printf '%s\n' 'C = US'
        printf '%s\n' 'L = California'
        printf '%s\n' 'O = Wazuh'
        printf '%s\n' 'OU = Wazuh'
        printf 'CN = %s\n' "$_wmc_node"
        printf '\n'
        printf '%s\n' '[ v3_leaf ]'
        printf '%s\n' 'authorityKeyIdentifier = keyid,issuer'
        printf '%s\n' 'subjectKeyIdentifier = hash'
        printf '%s\n' 'basicConstraints = critical,CA:FALSE'
        printf '%s\n' 'keyUsage = critical,digitalSignature,keyEncipherment'
        printf 'extendedKeyUsage = %s\n' "$_wmc_eku"
        printf '%s\n' 'subjectAltName = @alt_names'
        printf '\n'
        printf '%s\n' '[ alt_names ]'
        awk '
            /^IP:/  { ip++;  print "IP." ip " = " substr($0, 4) }
            /^DNS:/ { dns++; print "DNS." dns " = " substr($0, 5) }
        ' "$_wmc_sans"
    } >"$_wmc_config"
)

_wmc_validate_pair() (
    _wmc_cert=${1-}
    _wmc_key=${2-}
    _wmc_ca=${3-}
    _wmc_uid=${4-}
    _wmc_gid=${5-}
    _wmc_eku=${6-}
    _wmc_require_san=${7-0}

    _wmc_validate_file "$_wmc_cert" "$_wmc_uid" "$_wmc_gid" 640 || return 1
    _wmc_validate_file "$_wmc_key" "$_wmc_uid" "$_wmc_gid" 640 || return 1

    openssl x509 -in "$_wmc_cert" -noout >/dev/null 2>&1 || {
        _wmc_error "invalid X.509 certificate: $_wmc_cert"
        return 1
    }
    openssl x509 -in "$_wmc_cert" -checkend 0 -noout >/dev/null 2>&1 || {
        _wmc_error "expired X.509 certificate: $_wmc_cert"
        return 1
    }
    openssl pkey -in "$_wmc_key" -passin pass: -check -noout </dev/null >/dev/null 2>&1 || {
        _wmc_error "invalid private key: $_wmc_key"
        return 1
    }
    case $_wmc_eku in
        clientAuth) _wmc_purpose=sslclient ;;
        serverAuth) _wmc_purpose=sslserver ;;
        *) return 1 ;;
    esac
    openssl verify -purpose "$_wmc_purpose" -CAfile "$_wmc_ca" "$_wmc_cert" >/dev/null 2>&1 || {
        _wmc_error "certificate does not chain to the configured root CA: $_wmc_cert"
        return 1
    }

    _wmc_text=$(LC_ALL=C openssl x509 -in "$_wmc_cert" -noout -text 2>/dev/null) || return 1
    case $_wmc_text in
        *'CA:FALSE'*) ;;
        *)
            _wmc_error "leaf certificate does not declare CA:FALSE: $_wmc_cert"
            return 1
            ;;
    esac
    case $_wmc_eku in
        clientAuth)
            case $_wmc_text in
                *'TLS Web Client Authentication'*) ;;
                *) _wmc_error "certificate lacks clientAuth: $_wmc_cert"; return 1 ;;
            esac
            ;;
        serverAuth)
            case $_wmc_text in
                *'TLS Web Server Authentication'*) ;;
                *) _wmc_error "certificate lacks serverAuth: $_wmc_cert"; return 1 ;;
            esac
            ;;
    esac
    if [ "$_wmc_require_san" -eq 1 ]; then
        case $_wmc_text in
            *'X509v3 Subject Alternative Name'*) ;;
            *) _wmc_error "certificate has no SAN extension: $_wmc_cert"; return 1 ;;
        esac
    fi

    _wmc_cert_pub=$(mktemp "${_wmc_cert%/*}/.cert-pub.XXXXXX") || return 1
    _wmc_key_pub=$(mktemp "${_wmc_cert%/*}/.key-pub.XXXXXX") || {
        rm -f -- "$_wmc_cert_pub"
        return 1
    }
    trap 'rm -f -- "$_wmc_cert_pub" "$_wmc_key_pub"' 0
    trap 'return 130' 1 2 3 15
    chmod 0600 "$_wmc_cert_pub" "$_wmc_key_pub" || return 1
    openssl x509 -in "$_wmc_cert" -pubkey -noout >"$_wmc_cert_pub" 2>/dev/null || return 1
    openssl pkey -in "$_wmc_key" -passin pass: -pubout </dev/null >"$_wmc_key_pub" 2>/dev/null || return 1
    cmp -s -- "$_wmc_cert_pub" "$_wmc_key_pub" || {
        _wmc_error "private key does not match certificate: $_wmc_cert"
        return 1
    }
    rm -f -- "$_wmc_cert_pub" "$_wmc_key_pub"
    trap - 0 1 2 3 15
)

_wmc_pair_state() (
    _wmc_cert=${1-}
    _wmc_key=${2-}
    _wmc_cert_exists=0
    _wmc_key_exists=0
    if [ -e "$_wmc_cert" ] || [ -L "$_wmc_cert" ]; then _wmc_cert_exists=1; fi
    if [ -e "$_wmc_key" ] || [ -L "$_wmc_key" ]; then _wmc_key_exists=1; fi

    if [ "$_wmc_cert_exists" -eq 0 ] && [ "$_wmc_key_exists" -eq 0 ]; then
        printf '%s\n' absent
    elif [ "$_wmc_cert_exists" -eq 1 ] && [ "$_wmc_key_exists" -eq 1 ]; then
        printf '%s\n' complete
    else
        printf '%s\n' partial
    fi
)

_wmc_install_ca_anchor() (
    _wmc_source=${1-}
    _wmc_target=${2-}
    _wmc_group=${3-}
    _wmc_gid=${4-}

    if [ -e "$_wmc_target" ] || [ -L "$_wmc_target" ]; then
        _wmc_validate_file "$_wmc_target" 0 "$_wmc_gid" 640 || return 1
        if ! cmp -s -- "$_wmc_source" "$_wmc_target"; then
            _wmc_error "existing manager root-ca.pem differs from $_wmc_source"
            return 1
        fi
        return 0
    fi

    _wmc_tmp=$(mktemp "${_wmc_target%/*}/.root-ca.XXXXXX") || return 1
    trap 'rm -f -- "$_wmc_tmp"' 0
    trap 'return 130' 1 2 3 15
    cp -- "$_wmc_source" "$_wmc_tmp" || return 1
    chown root:"$_wmc_group" "$_wmc_tmp" || return 1
    chmod 0640 "$_wmc_tmp" || return 1
    ln -T -- "$_wmc_tmp" "$_wmc_target" || return 1
    rm -f -- "$_wmc_tmp"
    trap - 0 1 2 3 15
    if command -v restorecon >/dev/null 2>&1; then
        restorecon "$_wmc_target" >/dev/null 2>&1 || return 1
    fi
    _wmc_validate_file "$_wmc_target" 0 "$_wmc_gid" 640
)

_wmc_generate_indexer_pair() (
    _wmc_dir=${1-}
    _wmc_ca_dir=${2-}
    _wmc_node=${3-}
    _wmc_sans=${4-}
    _wmc_group=${5-}
    _wmc_gid=${6-}
    _wmc_tmp_dir=$(mktemp -d "$_wmc_dir/.indexer-connector.XXXXXX") || return 1
    trap 'rm -rf -- "$_wmc_tmp_dir"' 0
    trap 'return 130' 1 2 3 15
    chmod 0700 "$_wmc_tmp_dir" || return 1

    _wmc_config=$_wmc_tmp_dir/leaf.cnf
    _wmc_write_leaf_config "$_wmc_config" "$_wmc_node" clientAuth "$_wmc_sans" || return 1
    (umask 077; openssl req -new -nodes -newkey rsa:2048 -sha256 \
        -keyout "$_wmc_tmp_dir/indexer-connector-key.pem" \
        -out "$_wmc_tmp_dir/indexer-connector.csr" \
        -config "$_wmc_config" >/dev/null 2>&1) || {
        _wmc_error 'failed to create the Indexer Connector CSR'
        return 1
    }
    _wmc_serial=$(openssl rand -hex 16) || return 1
    openssl x509 -req -sha256 -days 3650 \
        -set_serial "0x$_wmc_serial" \
        -in "$_wmc_tmp_dir/indexer-connector.csr" \
        -CA "$_wmc_ca_dir/root-ca.pem" \
        -CAkey "$_wmc_ca_dir/root-ca.key" -passin pass: \
        -extfile "$_wmc_config" -extensions v3_leaf \
        -out "$_wmc_tmp_dir/indexer-connector.pem" >/dev/null 2>&1 || {
        _wmc_error 'failed to issue the Indexer Connector certificate'
        return 1
    }

    chown root:"$_wmc_group" \
        "$_wmc_tmp_dir/indexer-connector.pem" \
        "$_wmc_tmp_dir/indexer-connector-key.pem" || return 1
    chmod 0640 \
        "$_wmc_tmp_dir/indexer-connector.pem" \
        "$_wmc_tmp_dir/indexer-connector-key.pem" || return 1

    _wmc_validate_pair "$_wmc_tmp_dir/indexer-connector.pem" \
        "$_wmc_tmp_dir/indexer-connector-key.pem" "$_wmc_ca_dir/root-ca.pem" \
        0 "$_wmc_gid" clientAuth 1 || return 1
    ln -T -- "$_wmc_tmp_dir/indexer-connector-key.pem" "$_wmc_dir/indexer-connector-key.pem" || return 1
    ln -T -- "$_wmc_tmp_dir/indexer-connector.pem" "$_wmc_dir/indexer-connector.pem" || return 1
    rm -rf -- "$_wmc_tmp_dir"
    trap - 0 1 2 3 15
)

_wmc_generate_remoted_pair() (
    _wmc_dir=${1-}
    _wmc_ca_dir=${2-}
    _wmc_node=${3-}
    _wmc_sans=${4-}
    _wmc_user=${5-}
    _wmc_group=${6-}
    _wmc_tmp_dir=$(mktemp -d "$_wmc_dir/.remoted.XXXXXX") || return 1
    trap 'rm -rf -- "$_wmc_tmp_dir"' 0
    trap 'return 130' 1 2 3 15
    chmod 0700 "$_wmc_tmp_dir" || return 1

    _wmc_config=$_wmc_tmp_dir/leaf.cnf
    _wmc_write_leaf_config "$_wmc_config" "$_wmc_node" serverAuth "$_wmc_sans" || return 1
    (umask 077; openssl req -new -nodes -newkey rsa:2048 -sha256 \
        -keyout "$_wmc_tmp_dir/remoted-key.pem" \
        -out "$_wmc_tmp_dir/remoted.csr" \
        -config "$_wmc_config" >/dev/null 2>&1) || {
        _wmc_error 'failed to create the Remoted CSR'
        return 1
    }

    _wmc_ca_workspace=$_wmc_tmp_dir/ca
    install -d -m 0700 "$_wmc_ca_workspace/newcerts" || return 1
    : >"$_wmc_ca_workspace/index.txt" || return 1
    printf '%s\n' 'unique_subject = no' >"$_wmc_ca_workspace/index.txt.attr" || return 1
    openssl rand -hex 16 >"$_wmc_ca_workspace/serial" || return 1
    {
        printf '%s\n' '[ ca ]'
        printf '%s\n' 'default_ca = local_ca'
        printf '\n'
        printf '%s\n' '[ local_ca ]'
        printf 'dir = %s\n' "$_wmc_ca_workspace"
        printf 'database = %s/index.txt\n' "$_wmc_ca_workspace"
        printf 'serial = %s/serial\n' "$_wmc_ca_workspace"
        printf 'new_certs_dir = %s/newcerts\n' "$_wmc_ca_workspace"
        printf 'certificate = %s/root-ca.pem\n' "$_wmc_ca_dir"
        printf 'private_key = %s/root-ca.key\n' "$_wmc_ca_dir"
        printf '%s\n' 'default_md = sha256'
        printf '%s\n' 'preserve = yes'
        printf '%s\n' 'email_in_dn = no'
        printf '%s\n' 'policy = leaf_policy'
        printf '\n'
        printf '%s\n' '[ leaf_policy ]'
        printf '%s\n' 'countryName = optional'
        printf '%s\n' 'stateOrProvinceName = optional'
        printf '%s\n' 'localityName = optional'
        printf '%s\n' 'organizationName = optional'
        printf '%s\n' 'organizationalUnitName = optional'
        printf '%s\n' 'commonName = supplied'
    } >"$_wmc_ca_workspace/ca.cnf" || return 1

    _wmc_start=$(date -u -d '-1 day' '+%y%m%d%H%M%SZ' 2>/dev/null) || return 1
    _wmc_end=$(date -u -d '+3650 days' '+%y%m%d%H%M%SZ' 2>/dev/null) || return 1
    openssl ca -batch -notext -md sha256 \
        -config "$_wmc_ca_workspace/ca.cnf" \
        -in "$_wmc_tmp_dir/remoted.csr" \
        -out "$_wmc_tmp_dir/remoted.pem" \
        -extfile "$_wmc_config" -extensions v3_leaf \
        -startdate "$_wmc_start" -enddate "$_wmc_end" \
        -passin pass: >/dev/null 2>&1 || {
        _wmc_error 'failed to issue the Remoted certificate'
        return 1
    }
    printf '\n' >>"$_wmc_tmp_dir/remoted.pem" || return 1
    cat "$_wmc_ca_dir/root-ca.pem" >>"$_wmc_tmp_dir/remoted.pem" || return 1

    chown "$_wmc_user":"$_wmc_group" \
        "$_wmc_tmp_dir/remoted.pem" "$_wmc_tmp_dir/remoted-key.pem" || return 1
    chmod 0640 "$_wmc_tmp_dir/remoted.pem" "$_wmc_tmp_dir/remoted-key.pem" || return 1

    _wmc_validate_pair "$_wmc_tmp_dir/remoted.pem" "$_wmc_tmp_dir/remoted-key.pem" \
        "$_wmc_ca_dir/root-ca.pem" "$(id -u "$_wmc_user")" \
        "$(getent group "$_wmc_group" | cut -d: -f3)" serverAuth 1 || return 1
    ln -T -- "$_wmc_tmp_dir/remoted-key.pem" "$_wmc_dir/remoted-key.pem" || return 1
    ln -T -- "$_wmc_tmp_dir/remoted.pem" "$_wmc_dir/remoted.pem" || return 1
    rm -rf -- "$_wmc_tmp_dir"
    trap - 0 1 2 3 15
)

_wmc_restore_contexts() (
    _wmc_dir=${1-}
    if command -v restorecon >/dev/null 2>&1; then
        restorecon "$_wmc_dir/root-ca.pem" \
            "$_wmc_dir/indexer-connector.pem" \
            "$_wmc_dir/indexer-connector-key.pem" \
            "$_wmc_dir/remoted.pem" \
            "$_wmc_dir/remoted-key.pem" >/dev/null 2>&1 || {
            _wmc_error "failed to restore certificate SELinux contexts in $_wmc_dir"
            return 1
        }
    fi
)

_wmc_validate_locked() (
    _wmc_identity=$(_wmc_get_identity) || return 1
    _wmc_user=${_wmc_identity%%:*}
    _wmc_rest=${_wmc_identity#*:}
    _wmc_group=${_wmc_rest%%:*}
    _wmc_rest=${_wmc_rest#*:}
    _wmc_uid=${_wmc_rest%%:*}
    _wmc_gid=${_wmc_rest#*:}
    _wmc_dir=$(_wmc_get_cert_dir) || return 1
    _wmc_ca_dir=$(wazuh_ca_get_dir) || return 1
    _wmc_validate_path "$_wmc_ca_dir" || return 1

    _wazuh_validate_ca_files "$_wmc_ca_dir" || return 1
    _wmc_prepare_cert_dir "$_wmc_dir" "$_wmc_group" "$_wmc_gid" 0 || return 1
    _wmc_validate_file "$_wmc_dir/root-ca.pem" 0 "$_wmc_gid" 640 || return 1
    cmp -s -- "$_wmc_ca_dir/root-ca.pem" "$_wmc_dir/root-ca.pem" || {
        _wmc_error 'manager root-ca.pem differs from the shared trust anchor'
        return 1
    }

    _wmc_validate_pair \
        "$_wmc_dir/indexer-connector.pem" \
        "$_wmc_dir/indexer-connector-key.pem" \
        "$_wmc_ca_dir/root-ca.pem" 0 "$_wmc_gid" clientAuth 0 || return 1
    _wmc_validate_pair \
        "$_wmc_dir/remoted.pem" \
        "$_wmc_dir/remoted-key.pem" \
        "$_wmc_ca_dir/root-ca.pem" "$_wmc_uid" "$_wmc_gid" serverAuth 1
)

_wmc_ensure_locked() (
    _wmc_identity=$(_wmc_get_identity) || return 1
    _wmc_user=${_wmc_identity%%:*}
    _wmc_rest=${_wmc_identity#*:}
    _wmc_group=${_wmc_rest%%:*}
    _wmc_rest=${_wmc_rest#*:}
    _wmc_uid=${_wmc_rest%%:*}
    _wmc_gid=${_wmc_rest#*:}
    _wmc_dir=$(_wmc_get_cert_dir) || return 1
    _wmc_ca_dir=$(wazuh_ca_get_dir) || return 1

    _wmc_validate_path "$_wmc_ca_dir" || return 1
    if [ ! -e "$_wmc_ca_dir/root-ca.pem" ] && [ ! -L "$_wmc_ca_dir/root-ca.pem" ]; then
        for _wmc_existing in root-ca.pem indexer-connector.pem indexer-connector-key.pem remoted.pem remoted-key.pem; do
            if [ -e "$_wmc_dir/$_wmc_existing" ] || [ -L "$_wmc_dir/$_wmc_existing" ]; then
                _wmc_error 'shared CA missing but manager material exists; refusing to mint another CA'
                return 1
            fi
        done
    fi
    _wazuh_ca_ensure_locked || return 1
    _wazuh_validate_ca_files "$_wmc_ca_dir" || return 1
    _wmc_prepare_cert_dir "$_wmc_dir" "$_wmc_group" "$_wmc_gid" 1 || return 1
    _wmc_install_ca_anchor \
        "$_wmc_ca_dir/root-ca.pem" "$_wmc_dir/root-ca.pem" \
        "$_wmc_group" "$_wmc_gid" || return 1

    _wmc_indexer_state=$(_wmc_pair_state \
        "$_wmc_dir/indexer-connector.pem" \
        "$_wmc_dir/indexer-connector-key.pem") || return 1
    _wmc_remoted_state=$(_wmc_pair_state \
        "$_wmc_dir/remoted.pem" "$_wmc_dir/remoted-key.pem") || return 1

    if [ "$_wmc_indexer_state" = partial ]; then
        _wmc_error 'partial Indexer Connector certificate pair; refusing to modify it'
        return 1
    fi
    if [ "$_wmc_remoted_state" = partial ]; then
        _wmc_error 'partial Remoted certificate pair; refusing to modify it'
        return 1
    fi

    if [ "$_wmc_indexer_state" = complete ]; then
        _wmc_validate_pair \
            "$_wmc_dir/indexer-connector.pem" \
            "$_wmc_dir/indexer-connector-key.pem" \
            "$_wmc_ca_dir/root-ca.pem" 0 "$_wmc_gid" clientAuth 0 || return 1
    fi
    if [ "$_wmc_remoted_state" = complete ]; then
        _wmc_validate_pair \
            "$_wmc_dir/remoted.pem" "$_wmc_dir/remoted-key.pem" \
            "$_wmc_ca_dir/root-ca.pem" "$_wmc_uid" "$_wmc_gid" serverAuth 1 || return 1
    fi

    if [ "$_wmc_indexer_state" = absent ] || [ "$_wmc_remoted_state" = absent ]; then
        if [ ! -e "$_wmc_ca_dir/root-ca.key" ] && [ ! -L "$_wmc_ca_dir/root-ca.key" ]; then
            _wmc_error 'a manager certificate is missing and the shared CA has no private key; stage a pre-issued pair'
            return 1
        fi
        _wmc_node=$(_wmc_node_name) || return 1
    fi

    if [ "$_wmc_indexer_state" = absent ] || [ "$_wmc_remoted_state" = absent ]; then
        _wmc_base=$(wazuh_base_get_dir) || return 1
        _wmc_stage=$(mktemp -d "$_wmc_base/.manager-sans.XXXXXX") || return 1
        trap 'rm -rf -- "$_wmc_stage"' 0
        trap 'return 130' 1 2 3 15
        # Resolve BOTH requested inputs before issuing either leaf.
        if [ "$_wmc_indexer_state" = absent ]; then
            _wmc_resolve_manager_sans_to "$_wmc_stage/indexer" || return 1
        fi
        if [ "$_wmc_remoted_state" = absent ]; then
            _wmc_resolve_remoted_sans_to "$_wmc_stage/remoted" || return 1
        fi
        if [ "$_wmc_indexer_state" = absent ]; then
            _wmc_generate_indexer_pair "$_wmc_dir" "$_wmc_ca_dir" "$_wmc_node" \
                "$_wmc_stage/indexer" "$_wmc_group" "$_wmc_gid" || return 1
        fi
        if [ "$_wmc_remoted_state" = absent ]; then
            _wmc_generate_remoted_pair "$_wmc_dir" "$_wmc_ca_dir" "$_wmc_node" \
                "$_wmc_stage/remoted" "$_wmc_user" "$_wmc_group" || return 1
        fi
    fi

    _wmc_restore_contexts "$_wmc_dir" || return 1
    _wmc_validate_locked
)

wazuh_manager_certificates_ensure() (
    if [ "$#" -ne 0 ]; then
        _wmc_error 'usage: wazuh_manager_certificates_ensure'
        return 1
    fi
    _wmc_require_shared_helpers || return 1
    _wmc_require_commands || return 1

    # This creates the bootstrap CA only when both root-ca.pem and root-ca.key
    # are absent. An anchor-only external CA remains anchor-only.
    _wazuh_with_lock _wmc_ensure_locked
)

wazuh_manager_certificates_validate() (
    if [ "$#" -ne 0 ]; then
        _wmc_error 'usage: wazuh_manager_certificates_validate'
        return 1
    fi
    _wmc_require_shared_helpers || return 1
    _wmc_require_commands || return 1
    _wazuh_with_lock _wmc_validate_locked
)
