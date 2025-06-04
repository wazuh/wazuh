#!/bin/bash

set -e

DIR_ROOT=$(dirname "$(realpath "$0")")/..
DIR_SRC="$DIR_ROOT/src"
DIR_FRAMEWORK="$DIR_ROOT/framework"
DIR_API="$DIR_ROOT/api"
DIR_PACKAGE="$DIR_ROOT/packages"
FILE_VERSION="$DIR_ROOT/VERSION.json"
PATTERN_STAGES=('alpha' 'beta' 'rc')
PATTERN_VERSION='^[0-9]+\.[0-9]+\.[0-9]+$'
PATTERN_STAGE='^(alpha|beta|rc)[0-9]{1,2}$'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
date_time=$(date '+%Y-%m-%d_%H-%M-%S')
LOG_FILE="${SCRIPT_DIR}/repository_bumper_${date_time}.log"

log_action() {
    local message="$1"
    local log_file="$LOG_FILE"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$log_file"
}

declare -a COMMAND_FILES
declare -a COMMAND_BACKUPS
declare -a COMMAND_NEWS

add_command() {
    COMMAND_FILES+=("$1")
    COMMAND_BACKUPS+=("$2")
    COMMAND_NEWS+=("$3")
}

do_command() {
    local idx="$1"
    if echo "${COMMAND_NEWS[$idx]}" > "${COMMAND_FILES[$idx]}"; then
        echo "Updated ${COMMAND_FILES[$idx]}" >> "$LOG_FILE"
    else
        echo "Failed to update ${COMMAND_FILES[$idx]}" >> "$LOG_FILE"
    fi
}

undo_command() {
    local idx="$1"
    if echo "${COMMAND_BACKUPS[$idx]}" > "${COMMAND_FILES[$idx]}"; then
        echo "Reverted ${COMMAND_FILES[$idx]}" >> "$LOG_FILE"
    else
        echo "Failed to revert ${COMMAND_FILES[$idx]}" >> "$LOG_FILE"
    fi
}

diff_command() {
    local idx="$1"
    diff <(echo "${COMMAND_BACKUPS[$idx]}") <(echo "${COMMAND_NEWS[$idx]}") | sed "s/^/${COMMAND_FILES[$idx]}: /"
}

execute_commands() {
    local do_errors=()
    local undo_errors=()

    for i in "${!COMMAND_FILES[@]}"; do
        if ! do_command "$i"; then
            do_errors+=("Error on ${COMMAND_FILES[$i]}")
            for ((j=i; j>=0; j--)); do
                if ! undo_command "$j"; then
                    undo_errors+=("Undo error on ${COMMAND_FILES[$j]}")
                fi
            done
            break
        fi
    done
}

validate_version() {
    local version="$1"

    if [[ ! "$version" =~ $PATTERN_VERSION ]]; then
        echo "Error: Invalid version value '$version'" >&2
        exit 1
    fi
}

validate_stage() {
    local stage="$1"

    if [[ ! "$stage" =~ $PATTERN_STAGE ]]; then
        echo "Error: Invalid stage value '$stage'" >&2
        exit 1
    fi
}

validate_date() {
    local date="$1"

    if ! date -d "$date" "+%Y-%m-%d" >/dev/null 2>&1 || [[ "$date" != "$(date -d "$date" "+%Y-%m-%d")" ]]; then
        echo "Error: Invalid date value '$date'" >&2
        exit 1
    fi
}

update_file() {
    local file_path="$1"
    local patterns=("$@")
    unset patterns[0]

    for pattern in "${patterns[@]}"; do
        local pattern_match="${pattern%%=*}"
        local replacement="${pattern#*=}"
        if [[ -n "$replacement" ]]; then
            sed -i -E "s/$pattern_match/$replacement/g" "$file_path"
        fi
    done
}

load_version() {
    local version_file_path="$1"

    if [[ ! -f "$version_file_path" ]]; then
        echo "Error: $version_file_path not found"
        exit 1
    fi

    version=$(jq -r '.version' "$version_file_path")
    stage=$(jq -r '.stage' "$version_file_path")

    if [[ -z "$version" || -z "$stage" ]]; then
        echo "Error: Missing 'version' or 'stage' in $version_file_path"
        exit 1
    fi

    validate_version "$version"
    validate_stage "$stage"

    echo "$version" "$stage"
}

update_file_version() {
    local new_version="$1"
    local new_stage="$2"

    if [[ -z "$new_version" && -z "$new_stage" ]]; then
        return
    fi

    local current
    current=$(<"$FILE_VERSION")

    local updated
    updated=$(echo "$current" | jq --arg ver "$new_version" --arg stage "$new_stage" '
        . as $orig |
        (if $ver != "" then .version = $ver else . end) |
        (if $stage != "" then .stage = $stage else . end)
    ')

    local to_write
    to_write="$(echo "$updated" | jq --indent 4 '.')"

    if [[ "$current" != "$to_write" ]]; then
        add_command "$FILE_VERSION" "$current" "$to_write"
        log_action "Modified $FILE_VERSION with new version: $new_version and stage: $new_stage"
    fi
}

update_file_sources() {
    local new_version="$1"
    local new_stage="$2"

    if [[ -z "$new_version" && -z "$new_stage" ]]; then
        return
    fi

    # Update defs.h
    if [[ -n "$new_version" ]]; then
        local defs_file="$DIR_SRC/headers/defs.h"
        local current_defs_version
        current_defs_version=$(grep -E '^#define __ossec_version' "$defs_file" \
            | sed -E 's/^#define __ossec_version\s+"v([0-9]+\.[0-9]+\.[0-9]+)".*/\1/')

        if [[ "$current_defs_version" != "$new_version" ]]; then
            sed -i -E "s|(^#define __ossec_version\s+\"v)[0-9]+\.[0-9]+\.[0-9]+(\")|\1${new_version}\2|" "$defs_file"
            log_action "Modified $defs_file with new version: $new_version"
        fi
    fi

    # Update wazuh-*.sh scripts
    for script in \
        "$DIR_SRC/init/wazuh-server.sh" \
        "$DIR_SRC/init/wazuh-client.sh" \
        "$DIR_SRC/init/wazuh-local.sh"
    do
        if [[ -n "$new_version" ]]; then
            local current_script_version
            current_script_version=$(
                grep -E '^VERSION="' "$script" \
                | sed -E 's/^VERSION="v([0-9]+\.[0-9]+\.[0-9]+)".*/\1/'
            )

            if [[ "$current_script_version" != "$new_version" ]]; then
                sed -i -E "s|(^VERSION=\")v[0-9]+\.[0-9]+\.[0-9]+(\")|\1v${new_version}\2|" "$script"
                log_action "Modified $script with new version: $new_version"
            fi
        fi

        if [[ -n "$new_stage" ]]; then
            local current_script_stage
            current_script_stage=$(
                grep -E '^REVISION="' "$script" \
                | sed -E 's/^REVISION="([^"]+)".*/\1/'
            )

            if [[ "$current_script_stage" != "$new_stage" ]]; then
                sed -i -E "s|(^REVISION=\")[^\"]+(\")|\1${new_stage}\2|" "$script"
                log_action "Modified $script with new stage: $new_stage"
            fi
        fi
    done

    # Update wazuh-installer.nsi
    local nsi_file="$DIR_SRC/win32/wazuh-installer.nsi"
    if [[ -n "$new_version" ]]; then
        local current_nsi_version
        current_nsi_version=$(grep -E '^!define VERSION' "$nsi_file" \
            | sed -E 's/^!define VERSION\s+"([0-9]+\.[0-9]+\.[0-9]+)".*/\1/')

        if [[ "$current_nsi_version" != "$new_version" ]]; then
            sed -i -E "s|(^!define VERSION\s+\")[0-9]+\.[0-9]+\.[0-9]+(\")|\1${new_version}\2|" "$nsi_file"
            sed -i -E "s|(^VIProductVersion\s+\")[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\")|\1${new_version}.0\2|" "$nsi_file"
            log_action "Modified $nsi_file with new version: $new_version"
        fi
    fi
    if [[ -n "$new_stage" ]]; then
        local current_nsi_stage
        current_nsi_stage=$(grep -E '^!define REVISION' "$nsi_file" \
            | sed -E 's/^!define REVISION\s+"([^"]+)".*/\1/')

        if [[ "$current_nsi_stage" != "$new_stage" ]]; then
            sed -i -E "s|(^!define REVISION\s+\")[^\"]+(\")|\1${new_stage}\2|" "$nsi_file"
            log_action "Modified $nsi_file with new stage: $new_stage"
        fi
    fi

    # Update wazuh-installer.wxs
    if [[ -n "$new_version" ]]; then
        local wxs_file="$DIR_SRC/win32/wazuh-installer.wxs"
        local current_wxs_version
        current_wxs_version=$(grep -E '<Product ' "$wxs_file" \
            | sed -E 's/.*Version="([^"]+)".*/\1/')

        if [[ "$current_wxs_version" != "$new_version" ]]; then
            sed -i -E "s|(<Product Id=\"\*\" Name=\"Wazuh Agent\" Language=\"1033\" Version=\")[^\"]+(\" Manufacturer=)|\1${new_version}\2|" "$wxs_file"
            log_action "Modified $wxs_file with new version: $new_version"
        fi
    fi

    # Update Doxyfile
    local doxy_file="$DIR_SRC/Doxyfile"
    if [[ -n "$new_version" ]]; then
        local current_doxy_proj
        current_doxy_proj=$(grep -E '^PROJECT_NUMBER\s+=' "$doxy_file" \
            | sed -E 's/^PROJECT_NUMBER\s+=\s+"v([0-9]+\.[0-9]+\.[0-9]+)(-[^"]*)?"$/\1/')

        if [[ "$current_doxy_proj" != "$new_version" ]]; then
            sed -i -E "s|(PROJECT_NUMBER\s+=\s+\"v)[0-9]+\.[0-9]+\.[0-9]+(-[^\"]+\"$)|\1${new_version}\2|" "$doxy_file"
            log_action "Modified $doxy_file with new version: $new_version"
        fi
    fi
    if [[ -n "$new_stage" ]]; then
        local current_doxy_stage
        current_doxy_stage=$(grep -E '^PROJECT_NUMBER\s+=' "$doxy_file" \
            | sed -E 's/^PROJECT_NUMBER\s+=\s+"v[0-9]+\.[0-9]+\.[0-9]+-([^"]+)".*$/\1/')

        if [[ "$current_doxy_stage" != "$new_stage" ]]; then
            sed -i -E "s|(PROJECT_NUMBER\s+=\s+\"v[0-9]+\.[0-9]+\.[0-9]+-)[^\"]+(\"$)|\1${new_stage}\2|" "$doxy_file"
            log_action "Modified $doxy_file with new stage: $new_stage"
        fi
    fi

    # Update version.rc
    if [[ -n "$new_version" ]]; then
        local rc_file="$DIR_SRC/win32/version.rc"
        local current_rc_str
        current_rc_str=$(grep -E '^#define VER_PRODUCTVERSION_STR' "$rc_file" \
            | sed -E 's/^#define VER_PRODUCTVERSION_STR v([0-9]+\.[0-9]+\.[0-9]+)$/\1/')

        local current_rc_num
        current_rc_num=$(grep -E '^#define VER_PRODUCTVERSION\s+' "$rc_file" \
            | sed -E 's/^#define VER_PRODUCTVERSION\s+([0-9]+,[0-9]+,[0-9]+),?.*$/\1/')

        if [[ "$current_rc_str" != "$new_version" ]]; then
            sed -i -E "s|(^#define VER_PRODUCTVERSION_STR v)[0-9]+\.[0-9]+\.[0-9]+$|\1${new_version}|" "$rc_file"
            log_action "Modified $rc_file with new VER_PRODUCTVERSION_STR: $new_version"
        fi

        local new_version_comma="${new_version//./,}"
        if [[ "$current_rc_num" != "$new_version_comma" ]]; then
            sed -i -E "s|(^#define VER_PRODUCTVERSION\s+)[0-9]+,[0-9]+,[0-9]+(,[0-9]+$)|\1${new_version_comma}\2|" "$rc_file"
            log_action "Modified $rc_file with new VER_PRODUCTVERSION: $new_version_comma"
        fi
    fi
}

update_file_framework() {
    local new_version="$1"
    local new_stage="$2"

    [[ -z "$new_version" && -z "$new_stage" ]] && return

    local init_file="$DIR_FRAMEWORK/wazuh/__init__.py"
    local cluster_file="$DIR_FRAMEWORK/wazuh/core/cluster/__init__.py"

    if [[ -n "$new_version" ]]; then
        local current_version_init
        current_version_init=$(grep -E "^__version__" "$init_file" | sed -E "s/^__version__\s*=\s*'([^']+)'.*/\1/")
        local current_version_cluster
        current_version_cluster=$(grep -E "^__version__" "$cluster_file" | sed -E "s/^__version__\s*=\s*'([^']+)'.*/\1/")

        if [[ "$current_version_init" != "$new_version" || "$current_version_cluster" != "$new_version" ]]; then
            sed -i -E "s|^(__version__\s*=\s*')[^']+(')|\1${new_version}\2|" "$init_file"
            sed -i -E "s|^(__version__\s*=\s*')[^']+(')|\1${new_version}\2|" "$cluster_file"
            log_action "Updated version to '${new_version}' in: $init_file and $cluster_file"
        fi
    fi

    if [[ -n "$new_stage" ]]; then
        local current_stage
        current_stage=$(grep -E "^__revision__" "$cluster_file" | sed -E "s/^__revision__\s*=\s*'([^']+)'.*/\1/")

        if [[ "$current_stage" != "$new_stage" ]]; then
            sed -i -E "s|^(__revision__\s*=\s*')[^']+(')|\1${new_stage}\2|" "$cluster_file"
            log_action "Updated revision to '${new_stage}' in: $cluster_file"
        fi
    fi
}

update_file_api() {
    local new_version="$1"
    local new_stage="$2"
    local setup_file="${DIR_API}/setup.py"
    local spec_file="${DIR_API}/api/spec/spec.yaml"

    [[ -z "$new_version" && -z "$new_stage" ]] && return

    if [[ -n "$new_version" ]]; then
        local current_setup_version
        current_setup_version=$(
            grep -E "^[[:space:]]*version='" "$setup_file" \
            | sed -E "s/^[[:space:]]*version='([^']+)'.*/\1/"
        )

        local current_spec_version
        current_spec_version=$(
            grep -E "^[[:space:]]*version:[[:space:]]*'" "$spec_file" \
            | sed -E "s/^[[:space:]]*version:[[:space:]]*'([0-9]+\.[0-9]+\.[0-9]+)'.*/\1/"
        )

        # Only if the version in setup.py does NOT match new_version, we apply changes
        if [[ "$current_setup_version" != "$new_version" ]]; then
            sed -i -E \
                "s|^([[:space:]]*version=')[^']+(',)|\1${new_version}\2|" \
                "$setup_file"

            sed -i -E \
                "s|^([[:space:]]*version:[[:space:]]*')[0-9]+\.[0-9]+\.[0-9]+(')|\1${new_version}\2|" \
                "$spec_file"

            sed -i -E \
                "s|(\/v)[0-9]+\.[0-9]+\.[0-9]+(/)|\1${new_version}\2|g" \
                "$spec_file"

            local version_short
            version_short=$(echo "$new_version" | awk -F. '{print $1 "." $2}')
            sed -i -E \
                "s|(com/)[0-9]+\.[0-9]+(/)|\1${version_short}\2|g" \
                "$spec_file"

            log_action "Updated version to '${new_version}' in: $setup_file and $spec_file"
        fi
    fi

    if [[ -n "$new_stage" ]]; then
        local current_spec_stage
        current_spec_stage=$(
            grep -E "^[[:space:]]*x-revision:[[:space:]]*'" "$spec_file" \
            | sed -E "s/^[[:space:]]*x-revision:[[:space:]]*'([^']+)'.*/\1/"
        )

        # Only if the current stage does NOT match new_stage, we apply the change
        if [[ "$current_spec_stage" != "$new_stage" ]]; then
            sed -i -E \
                "s|^([[:space:]]*x-revision:[[:space:]]*')[^']+(')|\1${new_stage}\2|" \
                "$spec_file"

            log_action "Updated revision to '${new_stage}' in: $spec_file"
        fi
    fi
}

update_file_packages() {
    local final_version="$1"
    local final_stage="$2"
    local new_date="$3"

    if [[ -z "$final_version" && -z "$new_date" ]]; then
        log_action "No version or date provided: changelog and .spec updates omitted."
        return 0
    fi

    IFS='.' read -r major minor patch <<< "$final_version"
    formatted_date=$(date -d "$new_date" +"%a, %d %b %Y 00:00:00 +0000")
    spec_date=$(date -d "$new_date" +"%a %b %d %Y")

    # ----------------------------------------------------
    # Update .spec files
    # ----------------------------------------------------
    for spec_file in $(find "$DIR_PACKAGE" -type f -name "*.spec"); do
        local existing_line
        existing_line=$(grep -E "^\\* .+ - ${final_version}$" "$spec_file" || true)

        if [[ -n "$existing_line" ]]; then
            sed -i -E \
                "s|^\* .+ - ${final_version}$|* ${spec_date} support <info@wazuh.com> - ${final_version}|" \
                "$spec_file"
            log_action "Updated changelog date for version ${final_version} in: $spec_file"
        else
            sed -i -E \
                "/^%changelog\s*$/a * ${spec_date} support <info@wazuh.com> - ${final_version}\n- More info: https://documentation.wazuh.com/current/release-notes/release-${final_version//./-}.html" \
                "$spec_file"
            log_action "Prepended changelog entry for version ${final_version} in: $spec_file"
        fi
    done

    # ----------------------------------------------------
    # Update Debian/Ubuntu changelog files (in each package)
    # ----------------------------------------------------
    for changelog_file in $(find "$DIR_PACKAGE" -type f -name "changelog"); do
        local INSTALL_TYPE
        INSTALL_TYPE=$(basename "$(dirname "$(dirname "$changelog_file")")")
        local changelog_entry
        changelog_entry="$(
cat <<EOF
${INSTALL_TYPE} (${final_version}-RELEASE) stable; urgency=low

  * More info: https://documentation.wazuh.com/current/release-notes/release-${final_version//./-}.html

 -- Wazuh, Inc <info@wazuh.com>  ${formatted_date}

EOF
)"
        local version_pattern_grep
        local version_pattern_awk
        version_pattern_grep="^${INSTALL_TYPE} \(${final_version//./\\.}-RELEASE\) stable; urgency=low"
        version_pattern_awk="^${INSTALL_TYPE} [(]${final_version//./.}-RELEASE[)] stable; urgency=low"

        if grep -qE "$version_pattern_grep" "$changelog_file"; then
            awk -v version_regex="$version_pattern_awk" -v new_date="$formatted_date" '
            BEGIN { inside_match = 0 }
            {
                if ($0 ~ version_regex) {
                    inside_match = 1s
                    print
                    next
                }
                if (inside_match && $0 ~ /^ -- Wazuh, Inc <info@wazuh.com>  /) {
                    print " -- Wazuh, Inc <info@wazuh.com>  " new_date
                    inside_match = 0
                    next
                }
                print
            }' "$changelog_file" > "${changelog_file}.tmp" && mv "${changelog_file}.tmp" "$changelog_file"

            log_action "Updated changelog date for version ${final_version} in: $changelog_file"
        else
            local tmp_file
            tmp_file=$(mktemp)
            {
                printf "%s\n" "$changelog_entry"
                cat "$changelog_file"
            } > "$tmp_file" && mv "$tmp_file" "$changelog_file"

            log_action "Prepended changelog entry for version ${final_version} in: $changelog_file"
        fi
    done

    # ----------------------------------------------------
    # Update “copyright” files
    # ----------------------------------------------------
    for copyright_file in $(find "$DIR_PACKAGE" -type f -name "copyright"); do
        sed -i -E \
            "s|(^    Wazuh, Inc <info@wazuh.com> on )[^$]+(\$)|\1${formatted_date}\2|" \
            "$copyright_file"
        log_action "Updated copyright date in: $copyright_file"
    done

    # ----------------------------------------------------
    # 6) Update “pkginfo” files
    # ----------------------------------------------------
    local pkginfo_date
    pkginfo_date=$(date -d "$new_date" +"%d%b%Y")
    for pkginfo_file in $(find "$DIR_PACKAGE" -type f -name "pkginfo"); do
        sed -i -E "s|(^VERSION=\")([0-9]+\.[0-9]+\.[0-9]+)(\"$)|\1${final_version}\3|" "$pkginfo_file"
        sed -i -E "s|(^PSTAMP=\")[^\"]+(\"$)|\1${pkginfo_date}\2|" "$pkginfo_file"

        log_action "Updated VERSION and PSTAMP in: $pkginfo_file"
    done
}

update_root_changelog() {
    local new_version="$1"
    local changelog_file="$DIR_ROOT/CHANGELOG.md"

    if [[ -z "$new_version" ]]; then
        return
    fi

    if [[ ! -f "$changelog_file" ]]; then
        echo -e "# Change Log\nAll notable changes to this project will be documented in this file.\n" > "$changelog_file"
    fi

    if grep -q "\[$new_version\]" "$changelog_file"; then
        log_action "Version $new_version already exists in changelog."
        return
    fi

    local inserted=0
    local temp_file
    temp_file=$(mktemp)

    while IFS= read -r line; do
        if [[ "$line" =~ ^##\ \[v?([0-9]+\.[0-9]+\.[0-9]+)\] ]]; then
            existing_version="${BASH_REMATCH[1]}"
            if [[ "$existing_version" == "$new_version" ]]; then
                log_action "Duplicate version $new_version found, skipping."
                return
            fi
            if [[ $inserted -eq 0 ]] && [[ "$(printf "%s\n%s" "$new_version" "$existing_version" | sort -Vr | head -n1)" == "$new_version" ]]; then
                echo -e "## [v$new_version]\n\n" >> "$temp_file"
                inserted=1
            fi
        fi
        echo "$line" >> "$temp_file"
    done < "$changelog_file"

    if [[ $inserted -eq 0 ]]; then
        echo -e "## [v$new_version]\n" >> "$temp_file"
    fi

    mv "$temp_file" "$changelog_file"
    log_action "Modified $changelog_file with new version: $new_version"
}

update_version() {
    local current_version="$1"
    local current_stage="$2"
    local new_version="$3"
    local new_stage="$4"
    local new_date="$5"

    [[ -n "$new_version" ]] && validate_version "$new_version"
    [[ -n "$new_stage" ]] && validate_stage "$new_stage"
    [[ -n "$new_date" ]] && validate_date "$new_date"

    # Create commands
    update_file_version "$new_version" "$new_stage"
    update_file_sources "$new_version" "$new_stage"
    update_file_framework "$new_version" "$new_stage"
    update_file_api "$new_version" "$new_stage"
    update_root_changelog "$new_version"

    local final_version="${new_version:-$current_version}"
    local final_stage="${new_stage:-$current_stage}"
    local final_date="${new_date:-$(date +%F)}"

    # Add package entries
    update_file_packages "$final_version" "$final_stage" "$final_date"

    # Execute commands
    execute_commands
}

usage() {
    echo "Usage: $0 --version VERSION --stage STAGE --date DATE"
    echo "  --version VERSION   Version number (e.g., 4.9.1)"
    echo "  --stage STAGE       Stage name (e.g., alpha, beta, rc)"
    echo "  --date DATE         Release date in format YYYY-MM-DD (e.g., 2025-04-14)"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
        --version)
            new_version="$2"
            shift 2
            ;;
        --stage)
            new_stage="$2"
            shift 2
            ;;
        --date)
            new_date="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
        esac
    done

    if [[ -z "$new_version" && -z "$new_stage" && -z "$new_date" ]]; then
        echo "Error: at least one of the parameters (version, stage or date) must be set"
        usage
        exit 1
    fi
}

parse_args "$@"

result=$(load_version "$FILE_VERSION")
current_version=$(echo "$result" | cut -d' ' -f1)
current_stage=$(echo "$result" | cut -d' ' -f2)

if [[ -z "$current_version" || -z "$current_stage" ]]; then
    echo "Error loading current version"
    exit 1
fi

if ! update_version "$current_version" "$current_stage" "$new_version" "$new_stage" "$new_date"; then
    echo "Error updating version"
    exit 1
fi
