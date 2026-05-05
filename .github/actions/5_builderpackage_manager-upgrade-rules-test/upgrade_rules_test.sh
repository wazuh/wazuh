#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-}"
SYSTEM="${2:-}"
PACKAGE_PATH="${3:-}"
COMPONENT="${4:-manager}"
OLD_PACKAGE_URL="${5:-}"
EXTRACT_DIR=""
INSTALL_DIR=""
MARKER=""
MARKED_FILES_LIST=""
DELETED_ETC_REL=""
DELETED_DATA_REL=""
BINARY_REL=""

COMMENT_MARKERS=()
CUSTOM_ETC_MARKERS=()
DATA_MARKERS=()

log() {
    echo "[upgrade-rules] $*"
}

fail() {
    echo "[upgrade-rules] ERROR: $*" >&2
    exit 1
}

configure_component() {
    case "$COMPONENT" in
        manager)
            INSTALL_DIR="/var/wazuh-manager"
            MARKER="WAZUH_UPGRADE_RULES_MARKER"
            MARKED_FILES_LIST="/tmp/wazuh-manager-upgrade-rules-marked-files.list"
            DELETED_ETC_REL="etc/outputs/default/indexer.yml"
            DELETED_DATA_REL="data/store/schema/engine-schema/0"
            BINARY_REL="bin/wazuh-manager-analysisd"
            COMMENT_MARKERS=(
                "etc/wazuh-manager.conf|wazuh-manager.conf|<!-- | -->"
                "etc/shared/agent-template.conf|agent-template|<!-- | -->"
                "etc/shared/default/agent.conf|shared-default-agent|<!-- | -->"
                "etc/wazuh-manager-internal-options.conf|internal-options|# |"
                "etc/client.keys|client-keys|# |"
            )
            CUSTOM_ETC_MARKERS=(
                "etc/custom-upgrade-rules-marker|custom-etc"
            )
            DATA_MARKERS=(
                "data/mmdb/GeoLite2-ASN.mmdb|mmdb-asn"
                "data/mmdb/GeoLite2-City.mmdb|mmdb-city"
                "data/store/enrichment/geo/0|store-enrichment-geo"
                "data/store/enrichment/ioc/0|store-enrichment-ioc"
                "data/store/geo/mmdb/0|store-geo-mmdb"
                "data/store/schema/allowed-fields/0|store-allowed-fields"
                "data/store/schema/wazuh-logpar-overrides/0|store-logpar-overrides"
                "data/custom-upgrade-rules-marker|custom-data"
            )
            ;;
        agent)
            INSTALL_DIR="/var/ossec"
            MARKER="WAZUH_AGENT_UPGRADE_RULES_MARKER"
            DELETED_ETC_REL="etc/internal_options.conf"
            DELETED_DATA_REL=""
            BINARY_REL="bin/wazuh-agentd"
            COMMENT_MARKERS=(
                "etc/ossec.conf|ossec-conf|<!-- | -->"
                "etc/local_internal_options.conf|local-internal-options|# |"
                "etc/client.keys|client-keys|# |"
            )
            CUSTOM_ETC_MARKERS=(
                "etc/custom-upgrade-rules-marker|custom-etc"
                "etc/shared/custom-upgrade-rules-marker|custom-shared"
            )
            ;;
        *)
            fail "Unsupported component: $COMPONENT"
            ;;
    esac
}

cleanup_extract() {
    if [ -n "$EXTRACT_DIR" ] && [ -d "$EXTRACT_DIR" ]; then
        rm -rf "$EXTRACT_DIR"
        EXTRACT_DIR=""
    fi
}

require_file() {
    local path="$1"
    [ -f "$path" ] || fail "Missing file: $path"
}

path_for() {
    local relative_path="$1"
    printf '%s/%s' "$INSTALL_DIR" "$relative_path"
}

stop_component_if_running() {
    case "$COMPONENT" in
        manager)
            command -v systemctl >/dev/null 2>&1 && systemctl stop wazuh-manager >/dev/null 2>&1 || true
            command -v service >/dev/null 2>&1 && service wazuh-manager stop >/dev/null 2>&1 || true
            [ -x "${INSTALL_DIR}/bin/wazuh-manager-control" ] && "${INSTALL_DIR}/bin/wazuh-manager-control" stop >/dev/null 2>&1 || true
            ;;
        agent)
            command -v systemctl >/dev/null 2>&1 && systemctl stop wazuh-agent >/dev/null 2>&1 || true
            command -v service >/dev/null 2>&1 && service wazuh-agent stop >/dev/null 2>&1 || true
            [ -x "${INSTALL_DIR}/bin/wazuh-control" ] && "${INSTALL_DIR}/bin/wazuh-control" stop >/dev/null 2>&1 || true
            ;;
    esac
}

write_marker() {
    local path="$1"
    local label="$2"

    mkdir -p "$(dirname "$path")"
    printf '%s:%s\n' "$MARKER" "$label" > "$path"
}

write_marker_rel() {
    local relative_path="$1"
    local label="$2"

    write_marker "$(path_for "$relative_path")" "$label"
}

# Append the marker as a syntactically valid comment for the file's format,
# so config parsers do not error out if services are started around the test.
append_marker_commented() {
    local path="$1"
    local label="$2"
    local prefix="$3"
    local suffix="$4"

    require_file "$path"
    printf '\n%s%s:%s%s\n' "$prefix" "$MARKER" "$label" "$suffix" >> "$path"
}

assert_contains_marker() {
    local path="$1"

    require_file "$path"
    grep -q "$MARKER" "$path" || fail "Marker was not preserved in $path"
}

assert_not_contains_marker() {
    local path="$1"

    require_file "$path"
    if grep -q "$MARKER" "$path"; then
        fail "Marker unexpectedly preserved in $path"
    fi
}

package_root_path() {
    local relative_path="$1"

    printf '%s%s/%s' "$EXTRACT_DIR" "$INSTALL_DIR" "$relative_path"
}

assert_matches_package() {
    local relative_path="$1"
    local installed_path
    local packaged_path

    installed_path="$(path_for "$relative_path")"
    packaged_path="$(package_root_path "$relative_path")"
    require_file "$installed_path"
    require_file "$packaged_path"

    cmp -s "$installed_path" "$packaged_path" || fail "$installed_path does not match target package"
}

ensure_cpio() {
    command -v cpio >/dev/null 2>&1 && return 0

    if command -v yum >/dev/null 2>&1; then
        yum install -y cpio
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y cpio
    elif command -v microdnf >/dev/null 2>&1; then
        microdnf install -y cpio
    else
        fail "cpio is required"
    fi
}

extract_package() {
    cleanup_extract
    [ -n "$PACKAGE_PATH" ] || fail "Missing package path"
    require_file "$PACKAGE_PATH"

    EXTRACT_DIR="$(mktemp -d)"

    case "$SYSTEM" in
        deb)
            command -v dpkg-deb >/dev/null 2>&1 || fail "dpkg-deb is required"
            dpkg-deb -x "$PACKAGE_PATH" "$EXTRACT_DIR"
            ;;
        rpm)
            command -v rpm2cpio >/dev/null 2>&1 || fail "rpm2cpio is required"
            ensure_cpio
            (cd "$EXTRACT_DIR" && rpm2cpio "$PACKAGE_PATH" | cpio -idm --quiet)
            ;;
        *)
            fail "Unsupported package system: $SYSTEM"
            ;;
    esac
}

assert_target_package_contains() {
    local relative_path="$1"

    extract_package
    require_file "$(package_root_path "$relative_path")"
    cleanup_extract
}

download_old_package() {
    [ -n "$OLD_PACKAGE_URL" ] || fail "Missing old package URL"
    mkdir -p /old_package
    curl -fL -o "/old_package/$(basename "$OLD_PACKAGE_URL")" "$OLD_PACKAGE_URL"
}

package_operation() {
    local package_path="$1"
    local operation="$2"

    require_file "$package_path"

    case "$SYSTEM:$operation" in
        deb:install)
            dpkg --install "$package_path"
            ;;
        deb:upgrade)
            dpkg --install --force-confnew "$package_path"
            ;;
        rpm:install)
            rpm -ivh --ignorearch "$package_path"
            ;;
        rpm:upgrade)
            rpm -Uvh --ignorearch "$package_path"
            ;;
        *)
            fail "Unsupported package operation: $SYSTEM $operation"
            ;;
    esac
}

prepare_common_markers() {
    local marker_entry
    local relative_path
    local label
    local prefix
    local suffix

    for marker_entry in "${COMMENT_MARKERS[@]}"; do
        IFS='|' read -r relative_path label prefix suffix <<< "$marker_entry"
        append_marker_commented "$(path_for "$relative_path")" "$label" "$prefix" "$suffix"
    done

    for marker_entry in "${CUSTOM_ETC_MARKERS[@]}"; do
        IFS='|' read -r relative_path label <<< "$marker_entry"
        write_marker_rel "$relative_path" "$label"
    done

    for marker_entry in "${DATA_MARKERS[@]+"${DATA_MARKERS[@]}"}"; do
        IFS='|' read -r relative_path label <<< "$marker_entry"
        write_marker_rel "$relative_path" "$label"
    done
}

prepare_manager_outputs() {
    local output_file
    local outputs_found="no"
    local deleted_etc_file

    deleted_etc_file="$(path_for "$DELETED_ETC_REL")"
    : > "$MARKED_FILES_LIST"

    if [ -d "${INSTALL_DIR}/etc/outputs/default" ]; then
        while IFS= read -r output_file; do
            [ "$output_file" = "$deleted_etc_file" ] && continue
            append_marker_commented "$output_file" "outputs" "# " ""
            printf '%s\n' "$output_file" >> "$MARKED_FILES_LIST"
            outputs_found="yes"
        done < <(find "${INSTALL_DIR}/etc/outputs/default" -maxdepth 1 -type f -name '*.yml' | sort)
    fi

    [ "$outputs_found" = "yes" ] || fail "No output .yml files found to mark"

    assert_target_package_contains "data/tzdb/iana/version"
    write_marker_rel "data/tzdb/iana/version" "tzdb"
}

prepare() {
    [ -d "$INSTALL_DIR" ] || fail "$INSTALL_DIR is not installed"

    stop_component_if_running

    prepare_common_markers

    if [ "$COMPONENT" = "manager" ]; then
        prepare_manager_outputs
    fi

    if [ -n "$DELETED_ETC_REL" ]; then
        require_file "$(path_for "$DELETED_ETC_REL")"
        rm -f "$(path_for "$DELETED_ETC_REL")"
    fi

    if [ -n "$DELETED_DATA_REL" ]; then
        require_file "$(path_for "$DELETED_DATA_REL")"
        rm -f "$(path_for "$DELETED_DATA_REL")"
    fi

    write_marker_rel "$BINARY_REL" "binary"
    chmod 0750 "$(path_for "$BINARY_REL")"

    log "Prepared $COMPONENT upgrade rule markers"
    log "Marker locations before upgrade:"
    if [ "$COMPONENT" = "manager" ]; then
        grep -RHn "$MARKER" "${INSTALL_DIR}/etc" "${INSTALL_DIR}/data" 2>/dev/null || true
    else
        grep -RHn "$MARKER" "${INSTALL_DIR}/etc" 2>/dev/null || true
    fi
    log "Files staged as 'should be reinstalled by package':"
    [ -n "$DELETED_ETC_REL" ] && printf '  %s\n' "$(path_for "$DELETED_ETC_REL")"
    [ -n "$DELETED_DATA_REL" ] && printf '  %s\n' "$(path_for "$DELETED_DATA_REL")"

    return 0
}

validate_common_markers() {
    local marker_entry
    local relative_path
    local label

    for marker_entry in "${COMMENT_MARKERS[@]}"; do
        IFS='|' read -r relative_path label _ <<< "$marker_entry"
        assert_contains_marker "$(path_for "$relative_path")"
    done

    for marker_entry in "${CUSTOM_ETC_MARKERS[@]}"; do
        IFS='|' read -r relative_path label <<< "$marker_entry"
        assert_contains_marker "$(path_for "$relative_path")"
    done

    for marker_entry in "${DATA_MARKERS[@]+"${DATA_MARKERS[@]}"}"; do
        IFS='|' read -r relative_path label <<< "$marker_entry"
        assert_contains_marker "$(path_for "$relative_path")"
    done
}

validate_manager_outputs() {
    local output_file

    [ -s "$MARKED_FILES_LIST" ] || fail "Marked files list missing or empty: $MARKED_FILES_LIST"
    while IFS= read -r output_file; do
        [ -n "$output_file" ] || continue
        assert_contains_marker "$output_file"
    done < "$MARKED_FILES_LIST"

    assert_not_contains_marker "$(path_for "data/tzdb/iana/version")"
    assert_matches_package "data/tzdb/iana/version"
}

validate() {
    extract_package
    trap 'cleanup_extract' EXIT

    log "Post-upgrade etc/ contents:"
    ls -laR "${INSTALL_DIR}/etc" 2>/dev/null | head -120 || true
    if [ "$COMPONENT" = "manager" ]; then
        log "Post-upgrade data/ top-level contents:"
        ls -la "${INSTALL_DIR}/data" 2>/dev/null || true
        log "Post-upgrade marker matches under etc/ and data/:"
        grep -RHn "$MARKER" "${INSTALL_DIR}/etc" "${INSTALL_DIR}/data" 2>/dev/null || true
    else
        log "Post-upgrade marker matches under etc/:"
        grep -RHn "$MARKER" "${INSTALL_DIR}/etc" 2>/dev/null || true
    fi

    validate_common_markers

    if [ "$COMPONENT" = "manager" ]; then
        validate_manager_outputs
    fi

    if [ -n "$DELETED_ETC_REL" ]; then
        assert_not_contains_marker "$(path_for "$DELETED_ETC_REL")"
        assert_matches_package "$DELETED_ETC_REL"
    fi

    if [ -n "$DELETED_DATA_REL" ]; then
        assert_not_contains_marker "$(path_for "$DELETED_DATA_REL")"
        assert_matches_package "$DELETED_DATA_REL"
    fi

    assert_not_contains_marker "$(path_for "$BINARY_REL")"
    assert_matches_package "$BINARY_REL"

    log "All assertions passed."
    log "Validated $COMPONENT upgrade rule markers"
}

run_full_upgrade() {
    local old_package_path

    download_old_package
    old_package_path="/old_package/$(basename "$OLD_PACKAGE_URL")"
    package_operation "$old_package_path" "install"

    if [ "$COMPONENT" = "agent" ] && [ -f "${INSTALL_DIR}/etc/ossec.conf" ]; then
        sed -i 's/MANAGER_IP/1.1.1.1/g' "${INSTALL_DIR}/etc/ossec.conf"
    fi

    prepare
    package_operation "$PACKAGE_PATH" "upgrade"
    validate
}

configure_component

case "$MODE" in
    prepare)
        prepare
        ;;
    validate)
        validate
        ;;
    run)
        run_full_upgrade
        ;;
    *)
        fail "Unsupported mode: $MODE"
        ;;
esac
