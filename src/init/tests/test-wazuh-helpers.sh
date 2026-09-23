#!/bin/sh
# Place this script next to both helpers. Run as root:
#   sudo sh ./test-wazuh-helpers.sh
#   sudo env TEST_SHELL=/bin/bash TEST_PIPEFAIL=1 sh ./test-wazuh-helpers.sh
# Optional: WAZUH_TEST_PARENT=/root (must be root-owned, no writable ancestors).
# Tests never use the production base or manager paths. Each case gets its own
# base. Artifacts and test.log are retained in the printed mktemp directory.
# Interface discovery uses a deterministic shell stub: no network needed.
# This is helper regression testing, NOT a running Wazuh/SELinux integration test.
set -eu
umask 077

TEST_SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
export TEST_SCRIPT_DIR

# Local deviation from upstream, which expects the two helpers beside this file. In this repo the
# suite lives with the other src/init shell tests and the helpers live in src/init/credentials/,
# so they are resolved once here and exported -- the per-case sub-shells, and the one case that
# sources a helper through "$TEST_SHELL -c", all read it from the environment. Falls back to this
# file's own directory, which is the upstream layout, so a verbatim upstream copy still runs.
WAZUH_HELPER_DIR=$TEST_SCRIPT_DIR/../credentials
[ -f "$WAZUH_HELPER_DIR/wazuh-credentials.sh" ] || WAZUH_HELPER_DIR=$TEST_SCRIPT_DIR
WAZUH_HELPER_DIR=$(CDPATH= cd -- "$WAZUH_HELPER_DIR" && pwd -P)
export WAZUH_HELPER_DIR

TEST_SHELL=${TEST_SHELL-/bin/sh}
export TEST_SHELL

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
eq() { [ "$1" = "$2" ] || fail "assertion failed: $3"; }
reject() { if "$@"; then fail 'expected a non-zero status'; fi; }
fixture() {
    wazuh_manager_certificates_ensure
    wazuh_manager_certificates_validate
}

if [ "${1-}" = --case ]; then
    # Unset inherited production selectors. These assignments are test-only.
    unset WAZUH_CA_DIR WAZUH_MANAGER_CERT_SANS WAZUH_MANAGER_REMOTED_CERT_SANS
    export WAZUH_BASE_DIR="$WAZUH_TEST_ROOT/$2/nested/base"
    export WAZUH_MANAGER_HOME="$WAZUH_TEST_ROOT/$2/manager"
    unset WAZUH_MANAGER_CERT_DIR
    export WAZUH_MANAGER_USER=root WAZUH_MANAGER_GROUP=root
    export WAZUH_MANAGER_NODE_NAME=test-manager
    export WAZUH_MANAGER_CERT_SANS='DNS:connector.test,IP:192.0.2.10'
    export WAZUH_MANAGER_REMOTED_CERT_SANS='DNS:agents.test,IP:192.0.2.11,IP:2001:db8::11'
    if [ "${TEST_PIPEFAIL-0}" = 1 ]; then set -o pipefail; fi
    . "$WAZUH_HELPER_DIR/wazuh-credentials.sh"
    . "$WAZUH_HELPER_DIR/wazuh-manager-certificates.sh"
    case $2 in
        import)
            before=$(umask)
            before_pwd=$PWD
            before_opts=$-
            . "$WAZUH_HELPER_DIR/wazuh-credentials.sh"
            . "$WAZUH_HELPER_DIR/wazuh-manager-certificates.sh"
            eq "$(umask)" "$before" umask
            eq "$PWD" "$before_pwd" cwd
            eq "$-" "$before_opts" options
            [ ! -e "$WAZUH_BASE_DIR" ] || fail 'source has side effects'
            ;;
        defaults)
            eq "$(wazuh_base_get_dir)" "$WAZUH_BASE_DIR" base
            eq "$(wazuh_env_get_file)" "$WAZUH_BASE_DIR/credentials.env" env
            eq "$(wazuh_ca_get_dir)" "$WAZUH_BASE_DIR/ca" ca
            eq "$(unset WAZUH_BASE_DIR; wazuh_base_get_dir)" /etc/wazuh default-base
            [ ! -e "$WAZUH_BASE_DIR" ] || fail 'getter created base'
            ;;
        env)
            wazuh_env_set TEST 'value1'
            eq "$(wazuh_env_get TEST)" value1 set
            wazuh_env_set TEST 'value2'
            eq "$(wazuh_env_get TEST)" value2 replace
            wazuh_env_set EMPTY ''
            eq "$(wazuh_env_get EMPTY)" '' empty
            special='  literal $() `cmd` "quotes" \ slash #hash  '
            wazuh_env_set SPECIAL "$special"
            eq "$(wazuh_env_get SPECIAL)" "$special" special
            wazuh_env_unset TEST
            rc=0; wazuh_env_get TEST || rc=$?
            eq "$rc" 1 absent
            eq "$(stat -c %a "$WAZUH_BASE_DIR")" 700 base-mode
            eq "$(stat -c %a "$(wazuh_env_get_file)")" 600 env-mode
            ;;
        operator)
            _wazuh_ensure_base_dir
            file=$(wazuh_env_get_file)
            printf '%s\n' '# operator comment' "KEY='operator'" >"$file"
            chmod 0600 "$file"
            cp "$file" "$WAZUH_BASE_DIR/operator.original"
            wazuh_env_set KEY managed
            eq "$(wazuh_env_get KEY)" managed precedence
            wazuh_env_set KEY replaced
            wazuh_env_unset KEY
            eq "$(wazuh_env_get KEY)" operator preserve
            head -n 2 "$file" >"$WAZUH_BASE_DIR/operator.after"
            cmp "$WAZUH_BASE_DIR/operator.original" "$WAZUH_BASE_DIR/operator.after"
            ;;
        malformed)
            wazuh_env_set VALID value
            file=$(wazuh_env_get_file)
            printf '%s\n' '# >>> wazuh generated — do not edit <<<' >>"$file"
            old=$(sha256sum "$file")
            reject wazuh_env_set VALID replacement
            eq "$(sha256sum "$file")" "$old" malformed-preserved
            ;;
        no_newline)
            _wazuh_ensure_base_dir
            file=$(wazuh_env_get_file)
            printf 'OPERATOR=value' >"$file"
            old=$(sha256sum "$file")
            reject wazuh_env_set TEST value
            eq "$(sha256sum "$file")" "$old" operator-bytes
            ;;
        precedence)
            file_ca="$WAZUH_TEST_ROOT/$2/file-ca/deep"
            process_ca="$WAZUH_TEST_ROOT/$2/process-ca/deep"
            wazuh_env_set WAZUH_CA_DIR "$file_ca"
            eq "$(wazuh_ca_get_dir)" "$file_ca" file-ca
            export WAZUH_CA_DIR="$process_ca"
            eq "$(wazuh_ca_get_dir)" "$process_ca" process-ca
            wazuh_ca_ensure
            [ -f "$process_ca/root-ca.pem" ]
            [ ! -e "$file_ca" ]
            [ ! -e "$WAZUH_BASE_DIR/ca" ]
            export WAZUH_CA_DIR=
            reject wazuh_ca_get_dir
            ;;
        invalid_paths)
            for path in '' relative / /root/../tmp /root//bad /root/./bad; do
                reject env WAZUH_BASE_DIR="$path" "$TEST_SHELL" -eu -c '. "$WAZUH_HELPER_DIR/wazuh-credentials.sh"; wazuh_env_set TEST value'
            done
            ;;
        permissions)
            wazuh_env_set TEST value
            file=$(wazuh_env_get_file)
            chmod 0644 "$file"
            reject wazuh_env_get TEST
            reject wazuh_env_set TEST new
            eq "$(stat -c %a "$file")" 644 not-repaired
            chmod 0600 "$file"
            chmod 0755 "$WAZUH_BASE_DIR"
            reject wazuh_env_set TEST new
            ;;
        symlinks)
            _wazuh_ensure_base_dir
            mkdir "$WAZUH_BASE_DIR/real"
            ln -s "$WAZUH_BASE_DIR/real" "$WAZUH_BASE_DIR/link"
            export WAZUH_CA_DIR="$WAZUH_BASE_DIR/link/deep"
            reject wazuh_ca_ensure
            [ ! -e "$WAZUH_BASE_DIR/real/deep" ]
            ln -s "$WAZUH_BASE_DIR/real/untouched" "$(wazuh_env_get_file)"
            reject wazuh_env_set TEST value
            [ ! -e "$WAZUH_BASE_DIR/real/untouched" ]
            ;;
        concurrent_env)
            pids=
            i=1
            while [ "$i" -le 12 ]; do
                wazuh_env_set "KEY_$i" "value-$i" &
                pids="$pids $!"
                i=$((i+1))
            done
            for pid in $pids; do wait "$pid"; done
            i=1
            while [ "$i" -le 12 ]; do
                eq "$(wazuh_env_get "KEY_$i")" "value-$i" concurrency
                i=$((i+1))
            done
            ;;
        passwords)
            i=0
            while [ "$i" -lt 30 ]; do
                p=$(wazuh_password_generate)
                eq "${#p}" 32 password-length
                case $p in *[a-z]*) ;; *) fail lowercase ;; esac
                case $p in *[A-Z]*) ;; *) fail uppercase ;; esac
                case $p in *[0-9]*) ;; *) fail digit ;; esac
                case $p in *[!A-Za-z0-9.,_+:@%^=~-]*) fail alphabet ;; esac
                wazuh_password_validate "$p"
                i=$((i+1))
            done
            reject wazuh_password_validate short1
            reject wazuh_password_validate NoDigitsHere
            ;;
        ca)
            wazuh_ca_ensure & p1=$!
            wazuh_ca_ensure & p2=$!
            wait "$p1"; wait "$p2"
            ca=$(wazuh_ca_get_dir)
            wazuh_ca_validate
            before=$(sha256sum "$ca/root-ca.pem" "$ca/root-ca.key")
            wazuh_ca_ensure
            eq "$(sha256sum "$ca/root-ca.pem" "$ca/root-ca.key")" "$before" ca-idempotence
            eq "$(stat -c %a "$ca/root-ca.key")" 400 key-mode
            eq "$(stat -c %a "$ca/root-ca.pem")" 644 cert-mode
            mv "$ca/root-ca.pem" "$ca/saved.pem"
            reject wazuh_ca_ensure
            mv "$ca/saved.pem" "$ca/root-ca.pem"
            mv "$ca/root-ca.key" "$ca/saved.key"
            wazuh_ca_ensure
            [ ! -e "$ca/root-ca.key" ]
            ;;
        manager)
            fixture
            dir="$WAZUH_MANAGER_HOME/etc/certs"
            ca=$(wazuh_ca_get_dir)
            [ ! -e "$dir/root-ca.key" ]
            eq "$(stat -c %a "$dir")" 1770 directory-mode
            eq "$(stat -c %a "$WAZUH_MANAGER_HOME")" 750 parent-mode
            for f in root-ca.pem indexer-connector.pem indexer-connector-key.pem remoted.pem remoted-key.pem; do
                eq "$(stat -c %a "$dir/$f")" 640 mode
            done
            eq "$(grep -c 'BEGIN CERTIFICATE' "$dir/remoted.pem")" 2 chain
            openssl verify -purpose sslclient -CAfile "$dir/root-ca.pem" "$dir/indexer-connector.pem"
            openssl verify -purpose sslserver -verify_hostname agents.test -CAfile "$dir/root-ca.pem" "$dir/remoted.pem"
            before=$(sha256sum "$dir"/*.pem)
            WAZUH_MANAGER_REMOTED_CERT_SANS='' wazuh_manager_certificates_ensure
            eq "$(sha256sum "$dir"/*.pem)" "$before" manager-idempotence
            mv "$ca/root-ca.key" "$ca/key.saved"
            wazuh_manager_certificates_ensure
            [ ! -e "$ca/root-ca.key" ]
            mv "$dir/remoted-key.pem" "$dir/key.saved"
            reject wazuh_manager_certificates_ensure
            [ ! -e "$dir/remoted-key.pem" ]
            ;;
        external_missing)
            wazuh_ca_ensure
            ca=$(wazuh_ca_get_dir)
            mv "$ca/root-ca.key" "$ca/key.saved"
            reject wazuh_manager_certificates_ensure
            [ ! -e "$WAZUH_MANAGER_HOME/etc/certs/remoted-key.pem" ]
            [ ! -e "$ca/root-ca.key" ]
            ;;
        invalid_sans)
            for san in '' 'IP:999.1.1.1' 'IP:2001:::1' 'IP:fe80::1%eth0' 'IP:010.1.1.1' 'DNS:*.test' 'DNS:foo,' 'DNS:foo,,DNS:bar'; do
                WAZUH_MANAGER_REMOTED_CERT_SANS=$san
                export WAZUH_MANAGER_REMOTED_CERT_SANS
                reject wazuh_manager_certificates_ensure
                [ ! -e "$WAZUH_MANAGER_HOME/etc/certs/indexer-connector.pem" ]
                [ ! -e "$WAZUH_MANAGER_HOME/etc/certs/remoted.pem" ]
            done
            ;;
        san_precedence)
            unset WAZUH_MANAGER_REMOTED_CERT_SANS
            wazuh_env_set WAZUH_MANAGER_REMOTED_CERT_SANS 'DNS:file.test,IP:2001:db8::1,IP:2001:db8:0:0:0:0:0:1'
            sans=$(wazuh_manager_remoted_sans)
            eq "$(printf '%s\n' "$sans" | wc -l | tr -d ' ')" 2 deduplication
            export WAZUH_MANAGER_REMOTED_CERT_SANS=DNS:process.test
            eq "$(wazuh_manager_remoted_sans)" DNS:process.test san-environment
            ;;
        interfaces)
            unset WAZUH_MANAGER_REMOTED_CERT_SANS
            # Include physical, secondary/non-default, virtual, loopback,
            # link-local and IPv6. The helper must not filter by default route.
            ip() {
                printf '%s\n' \
                    '1: lo inet 127.0.0.1/8 scope host lo' \
                    '2: eth0 inet 192.0.2.10/24 scope global eth0' \
                    '3: eth1 inet 198.51.100.12/24 scope global eth1' \
                    '4: docker0 inet 172.17.0.1/16 scope global docker0' \
                    '5: eth1 inet6 fe80::12/64 scope link' \
                    '5: eth1 inet6 2001:db8::12/64 scope global' \
                    '5: eth1 inet6 2001:db8::99/64 scope global tentative'
            }
            sans=$(wazuh_manager_remoted_sans)
            for expected in IP:127.0.0.1 IP:192.0.2.10 IP:198.51.100.12 IP:172.17.0.1 IP:fe80:0:0:0:0:0:0:12 IP:2001:db8:0:0:0:0:0:12; do
                printf '%s\n' "$sans" | grep -Fx "$expected"
            done
            fixture
            openssl verify -purpose sslserver -verify_ip 198.51.100.12 -CAfile "$(wazuh_ca_get_dir)/root-ca.pem" "$WAZUH_MANAGER_HOME/etc/certs/remoted.pem"
            ;;
        discovery_failure)
            unset WAZUH_MANAGER_REMOTED_CERT_SANS
            ip() { return 1; }
            reject wazuh_manager_remoted_sans
            reject wazuh_manager_certificates_ensure
            [ ! -e "$WAZUH_MANAGER_HOME/etc/certs/remoted.pem" ]
            ;;
        concurrent_manager)
            wazuh_manager_certificates_ensure & p1=$!
            wazuh_manager_certificates_ensure & p2=$!
            wait "$p1"; wait "$p2"
            wazuh_manager_certificates_validate
            ;;
        ca_missing_existing)
            fixture
            ca=$(wazuh_ca_get_dir)
            mv "$ca/root-ca.pem" "$ca/cert.saved"
            mv "$ca/root-ca.key" "$ca/key.saved"
            reject wazuh_manager_certificates_ensure
            [ ! -e "$ca/root-ca.pem" ]
            [ ! -e "$ca/root-ca.key" ]
            ;;
        key_mismatch)
            fixture
            dir="$WAZUH_MANAGER_HOME/etc/certs"
            mv "$dir/remoted-key.pem" "$dir/key.original"
            openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/remoted-key.pem" >/dev/null 2>&1
            chmod 0640 "$dir/remoted-key.pem"
            before=$(sha256sum "$dir/remoted-key.pem")
            reject wazuh_manager_certificates_validate
            reject wazuh_manager_certificates_ensure
            eq "$(sha256sum "$dir/remoted-key.pem")" "$before" no-regeneration
            ;;
        cert_symlink)
            fixture
            dir="$WAZUH_MANAGER_HOME/etc/certs"
            mv "$dir/remoted.pem" "$dir/cert.original"
            ln -s "$dir/cert.original" "$dir/remoted.pem"
            reject wazuh_manager_certificates_ensure
            [ -L "$dir/remoted.pem" ]
            ;;
        *) fail 'unknown case' ;;
    esac
    exit 0
fi

[ "$(id -u)" = 0 ] || fail 'run with sudo/root (ownership tests)'
[ "$#" -eq 0 ] || fail 'usage: test-wazuh-helpers.sh'
for tool in openssl flock ip getent stat awk od sha256sum; do
    command -v "$tool" >/dev/null || fail "missing dependency: $tool"
done
. "$WAZUH_HELPER_DIR/wazuh-credentials.sh"
test_parent=${WAZUH_TEST_PARENT-/root}
_wazuh_validate_absolute_path "$test_parent"
_wazuh_check_existing_tree "$test_parent"
[ -d "$test_parent" ] || fail 'test parent must exist'
WAZUH_TEST_ROOT=$(mktemp -d "$test_parent/wazuh-helper-tests.XXXXXX")
export WAZUH_TEST_ROOT
test_log="$WAZUH_TEST_ROOT/test.log"
test_fail=0
test_count=0
printf 'Test workspace: %s\n' "$WAZUH_TEST_ROOT"
for test_case in import defaults env operator malformed no_newline precedence invalid_paths permissions symlinks concurrent_env passwords ca manager external_missing invalid_sans san_precedence interfaces discovery_failure concurrent_manager ca_missing_existing key_mismatch cert_symlink; do
    test_count=$((test_count+1))
    printf '\nCASE %s\n' "$test_case" >>"$test_log"
    if "$TEST_SHELL" -eu "$TEST_SCRIPT_DIR/test-wazuh-helpers.sh" --case "$test_case" >>"$test_log" 2>&1; then
        printf 'PASS %s\n' "$test_case"
        printf 'PASS %s\n' "$test_case" >>"$test_log"
    else
        printf 'FAIL %s (see log)\n' "$test_case"
        printf 'FAIL %s\n' "$test_case" >>"$test_log"
        test_fail=$((test_fail+1))
    fi
done
printf '%s cases, %s failures. Log: %s\n' "$test_count" "$test_fail" "$test_log"
printf '%s cases, %s failures\n' "$test_count" "$test_fail" >>"$test_log"
printf 'Disposable test keys retained; remove this exact workspace when finished.\n'
[ "$test_fail" -eq 0 ]
