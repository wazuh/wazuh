#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Move to the directory of the script
# ------------------------------------------------------------------------------
OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
trap 'cd "$OLD_DIR"' EXIT
cd "$SCRIPT_DIR"

# ------------------------------------------------------------------------------
# Logging: mirror all stdout and stderr to a timestamped log file
# ------------------------------------------------------------------------------
LOG_FILE="${SCRIPT_DIR}/init.log"
: > "$LOG_FILE"  # Truncate log file on each run
exec > >(tee "$LOG_FILE") 2>&1

echo "==========================================================="
echo "  init.sh started at $(date '+%Y-%m-%d %H:%M:%S')"
echo "==========================================================="
echo ""

# ------------------------------------------------------------------------------
# CLI args
# ------------------------------------------------------------------------------
FROM_WORKFLOWS=0
for arg in "$@"; do
  case "$arg" in
    --from-wf|--from-workflow|--from-workflows)
      FROM_WORKFLOWS=1
      ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--from-wf]

Initializes the E2E environment.

By default, the Wazuh Indexer and Dashboard packages are downloaded from the
staging nightly artifact URL manifests. If a package is missing from the primary
manifest, the script tries the nightly backup manifest.

Options:
  --from-wf, --from-workflow, --from-workflows
                 Download packages from the latest successful GitHub Actions
                 workflows instead of the staging manifests.
  --help, -h     Show this help.

Required tools:
  default mode:  curl
  --from-wf:     curl, gh, unzip
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      echo "Use --help to see supported options." >&2
      exit 1
      ;;
  esac
done

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
WAZUH_5X_PRIMARY_MANIFEST_URL="${WAZUH_5X_PRIMARY_MANIFEST_URL:-https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/artifact-urls/artifact_urls_5.0.0-latest.yaml}"
WAZUH_5X_FALLBACK_MANIFEST_URL="${WAZUH_5X_FALLBACK_MANIFEST_URL:-https://packages-staging.xdrsiem.wazuh.info/nightly-backup/artifact_urls_5.0.0-latest.yaml}"

INDEXER_PACKAGE_KEY="wazuh_indexer_amd64_deb"
INDEXER_PACKAGE_FILE="wazuh-indexer_5.0.0-latest_amd64.deb"
DASHBOARD_PACKAGE_KEY="wazuh_dashboard_amd64_deb"
DASHBOARD_PACKAGE_FILE="wazuh-dashboard_5.0.0-latest_amd64.deb"

WAZUH_MANAGER_HOME="${WAZUH_MANAGER_HOME:-/var/wazuh-manager}"


# ==============================================================================
#                      Manager listener bind addresses
# ==============================================================================
# The manager ships remoted bound to loopback on purpose -- see
# docs/ref/modules/remoted/configuration.md (legacy.local_ip, https.bind_addr):
# an operator who wants remote agents is expected to open it after install.
# Containerised agents reach the devContainer host over the docker bridge, so
# loopback-only listeners refuse them with "Transport endpoint is not connected".
function open_manager_listeners() {
    local conf="${WAZUH_MANAGER_HOME}/etc/wazuh-manager.conf"

    echo "==> Opening manager listeners for containerised agents..."

    if [ ! -f "$conf" ]; then
        echo "==> Manager not installed at ${WAZUH_MANAGER_HOME}, skipping."
        echo "    Re-run this script after installing it, or set WAZUH_MANAGER_HOME."
        return 0
    fi

    # Scoped to <remote>: <cluster> carries its own <bind_addr>127.0.0.1</bind_addr>
    # that must stay loopback for a single-node dev environment.
    sed -i "/<remote>/,/<\/remote>/ {
        s|<local_ip>127\.0\.0\.1</local_ip>|<local_ip>0.0.0.0</local_ip>|
        s|<bind_addr>127\.0\.0\.1</bind_addr>|<bind_addr>0.0.0.0</bind_addr>|
    }" "$conf"

    # Editors and package upgrades reset the group; remoted runs as wazuh-manager
    # and reports a permission failure as "Error reading XML file (line 0)".
    chown root:wazuh-manager "$conf"
    chmod 660 "$conf"

    grep -nE "<local_ip>|<bind_addr>" "$conf" | sed 's/^/    /'
    echo "==> Restart the manager to apply: ${WAZUH_MANAGER_HOME}/bin/wazuh-manager-control restart"
}

# ==============================================================================
#                          Certificates
# ==============================================================================
function upsert_certs() {
    echo "==> Creating certificates..."

    # Check if certs directory already exists
    if [ -d certs ]; then
        echo "==> Certificates directory already exists."
        read -p "Do you want to regenerate the certificates? This will delete the existing certs directory. (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "==> Skipping certificate generation."
            return 0
        fi
        echo "==> Removing existing certificates directory..."
        rm -rf certs
    fi

    local wazuh_install_script="wazuh-install.sh"
    local wazuh_install_url="https://packages.wazuh.com/4.14/wazuh-install.sh"
    local config_file="config.yml"

    # Download wazuh-install.sh
    echo "==> Downloading wazuh-install.sh..."
    curl -sO "${wazuh_install_url}"
    chmod +x "${wazuh_install_script}"

    # Create config.yml
    echo "==> Creating config.yml..."
    cat > "${config_file}" << 'EOF'
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: node-1
      ip: "127.0.0.1"

  # Wazuh server nodes
  server:
    - name: wazuh-1
      ip: "127.0.0.1"

  # Wazuh dashboard nodes
  dashboard:
    - name: dashboard
      ip: "127.0.0.1"
EOF

    # Generate config files
    echo "==> Generating configuration files..."
    bash "${wazuh_install_script}" --generate-config-files

    # Extract the tar file
    echo "==> Extracting wazuh-install-files.tar..."
    tar -xf wazuh-install-files.tar

    # Rename wazuh-install-files to certs
    echo "==> Renaming wazuh-install-files to certs..."
    mv wazuh-install-files certs

    # Clean up temporary files
    echo "==> Cleaning up temporary files..."
    rm -f "${wazuh_install_script}" "${config_file}" wazuh-install-files.tar

    echo "==> Certificates created successfully."
}

# ==============================================================================
#                          GitHub Token
# ==============================================================================
function gh_token() {
  GH_TOKEN="$(gh auth token 2>/dev/null || true)"
  if [[ -z "$GH_TOKEN" ]]; then
    echo "Cannot find a GitHub token. Please run 'gh auth login' to authenticate."
    exit 1
  fi
}


# ==============================================================================
#                           Helpers
# ==============================================================================
function need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "ERROR: required command not found: $1" >&2; exit 1; }
}

function yaml_value() {
  local yaml_file=$1
  local key=$2

  sed -nE "s|^${key}:[[:space:]]*\"?([^\"]+)\"?[[:space:]]*$|\1|p" "$yaml_file" | head -n 1
}

function fetch_manifest() {
  local manifest_url=$1
  local output_file=$2

  echo "==> Fetching package manifest..."
  echo "    Manifest: $manifest_url"
  curl -fsSL "$manifest_url" -o "$output_file"
}

function resolve_package_url_from_manifest() {
  local package_name=$1
  local package_key=$2
  local manifest=$3
  local manifest_url=$4
  local manifest_name=$5

  RESOLVED_PACKAGE_URL="$(yaml_value "$manifest" "$package_key")"
  RESOLVED_PACKAGE_MANIFEST="$manifest_url"

  if [[ -n "$RESOLVED_PACKAGE_URL" ]]; then
    echo "==> Found $package_name package in $manifest_name manifest."
    return 0
  fi

  return 1
}

function download_package_from_url() {
  local package_name=$1
  local package_url=$2
  local output_dir=$3
  local final_filename=$4

  mkdir -p "$output_dir"

  local tmp_file="${output_dir}/${final_filename}.tmp"
  local final_path="${output_dir}/${final_filename}"

  echo "==> Downloading $package_name package..."
  echo "    => URL:       $package_url"
  echo "    => Saving to: $final_path"

  rm -f "$tmp_file"
  curl -fsSL "$package_url" -o "$tmp_file"
  mv "$tmp_file" "$final_path"

  echo "    => OK ($(du -h "$final_path" | awk '{print $1}'))"
  echo "    ---------------------------------------------------"
  echo "    [Download Summary]"
  echo "      Source manifest:   $RESOLVED_PACKAGE_MANIFEST"
  echo "      Package URL:       $package_url"
  echo "      Saved as:          $final_path"
  echo "    ---------------------------------------------------"
  echo ""
}

#
# Function to find the first successful run of a GitHub Actions workflow
#   args:
#     $1 => repo (e.g. "wazuh/wazuh-indexer")
#     $2 => workflow file (e.g. "build.yml")
#     $3 => run name prefix (e.g. "Build [ \"deb\" ] Wazuh Indexer on [ \"x64\" ] | main")
#
function find_first_successful_run() {
  local repo=$1
  local workflow_file=$2
  local run_name_prefix=$3

  local run_id
  run_id=$(
    gh api \
      "repos/$repo/actions/workflows/$workflow_file/runs" \
      --paginate \
      -q '.workflow_runs[]
          | select(
              .conclusion == "success"
              and .head_branch == "main"
              and (.name | startswith("'"$run_name_prefix"'"))
            )
          | .id' \
    | head -n 1 || true
  )

  # If no successful build is found, exit
  echo "$run_id"
}

#
# Function to list the artifacts of a GitHub Actions run
#   args:
#     $1 => repo (e.g. "wazuh/wazuh-indexer")
#     $2 => run_id (e.g. "123456789")
function list_run_artifacts() {
  local repo=$1
  local run_id=$2

  gh api "repos/$repo/actions/runs/$run_id/artifacts" \
    -q '.artifacts[] | "- \(.name) => \(.archive_download_url)"' \
    | cat
}

#
# This function downloads a GitHub Actions artifact, unzips it, and renames the unzipped file.
# Assuming the artifact is a zip file with a single file inside, this is the file we want.
#
#   args:
#     $1 => repo (e.g. "wazuh/wazuh-indexer")
#     $2 => run_id (e.g. "123456789")
#     $3 => artifact_url
#     $4 => output_dir (e.g. "wazuh-indexer")
#     $5 => final_filename (The final name of the unzipped file)
#
function download_and_unzip_artifact() {
  local repo=$1
  local run_id=$2
  local artifact_url=$3
  local output_dir=$4
  local final_filename=$5

  # Create the output directory if it doesn't exist (This never happens on devContainer context)
  # but we keep it for future use
  mkdir -p "$output_dir"

  local tmp_file="${output_dir}/tmp_artifact.zip"

  echo "==> Downloading artifact for run_id: $run_id"
  echo "    => Saving to: $tmp_file"

  curl -sSL \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "$artifact_url" \
    -o "$tmp_file"

  echo "    => Download finished."
  echo "    => Unzipping..."
  local unzipped_file
  unzipped_file=$(unzip -l "$tmp_file" | awk 'NR==4 {print $4}')
  unzip -oq "$tmp_file" -d "$output_dir"
  echo "    => Unzip finished."

  echo "    => Unzipped file: $unzipped_file"
  echo "       Renaming to: $final_filename"

  # If unzipped_file == final_filename, we don't need to rename it
  if [[ "$unzipped_file" == "$final_filename" ]]; then
    echo "    => No need to rename."
  else
    # If the unzipped file is not the same as the final filename, we need to rename it
    mv "${output_dir}/${unzipped_file}" "${output_dir}/${final_filename}" || {
      echo "    => Warning: Could not move/unzipped file not found."
    }
  fi

  rm "$tmp_file"

  # ---- Record download summary in the log ----
  echo "    ---------------------------------------------------"
  echo "    [Download Summary]"
  echo "      Repo:              $repo"
  echo "      Run ID:            $run_id"
  echo "      Run URL:           https://github.com/$repo/actions/runs/$run_id"
  echo "      Artifact URL:      $artifact_url"
  echo "      Original file:     $unzipped_file"
  echo "      Saved as:          ${output_dir}/${final_filename}"
  echo "    ---------------------------------------------------"
  echo ""
}

#
# Find and filter artifacts by regex, and for each artifact define a destination
# file according to the first matching pattern.
#   args:
#     $1 => repo (e.g. "wazuh/wazuh-indexer")
#     $2 => run_id (e.g. "123456789")
#     $3 => output_dir (e.g. "wazuh-indexer")
#     from $4 => list of regex::filename pairs (e.g.
#                "^prefix1-[[:alnum:]]+\\.zip$::file1.zip"
#                "^wazuh-indexer_5\\.0\\.0-[[:alnum:]]+_amd64\\.deb$::wazuh-indexer_5.0.0-latest_amd64.deb"
#
function fetch_artifacts_with_patterns() {
  local repo=$1
  local run_id=$2
  local output_dir=$3
  shift 3

  # Build the jq filter to select artifacts by regex and create the regex map.
  local jq_filter=""
  local -a pattern_map=()

  for pair in "$@"; do
    local pattern="${pair%%::*}"
    local jq_pattern="${pattern//\\/\\\\}"
    jq_pattern="${jq_pattern//\"/\\\"}"
    local final_filename="${pair##*::}"
    pattern_map+=("$pattern|$final_filename")

    if [[ -z "$jq_filter" ]]; then
      jq_filter="(.name | test(\"$jq_pattern\"))"
    else
      jq_filter="$jq_filter or (.name | test(\"$jq_pattern\"))"
    fi
  done

  # List the artifacts - piping to 'cat' to avoid paging
  local raw_kv_art
  raw_kv_art=$(
    gh api "repos/$repo/actions/runs/$run_id/artifacts" \
      -q ".artifacts[]
          | select($jq_filter and (.name | test(\"\\\\.(sha512|sha256|md5)$\") | not))
          | [ .name, .archive_download_url ]
          | @tsv" \
    | cat
  )

  if [[ -z "$raw_kv_art" ]]; then
    echo "==> Cannot find any artifacts matching the given patterns in $repo / run_id $run_id. See http://github.com/$repo/actions/runs/$run_id"
    return 0
  fi

  echo ""
  echo "==> Downloading artifacts of interest..."

  while IFS=$'\t' read -r artifact_name artifact_url; do
    [[ -z "$artifact_name" || -z "$artifact_url" ]] && continue

    # Determine the destination file
    for pm in "${pattern_map[@]}"; do
      local pattern="${pm%%|*}"
      local final_f="${pm##*|}"

      if [[ "$artifact_name" =~ $pattern ]]; then
        download_and_unzip_artifact "$repo" "$run_id" "$artifact_url" "$output_dir" "$final_f"
        break
      fi
    done

  done <<< "$raw_kv_art"
}


# ==============================================================================
#                   Staging manifests
# ==============================================================================
function get_packages_from_manifests() {
  local primary_manifest
  local fallback_manifest
  local fallback_manifest_loaded=0
  primary_manifest="$(mktemp)"
  fallback_manifest="$(mktemp)"
  trap 'rm -f "$primary_manifest" "$fallback_manifest"' RETURN

  fetch_manifest "$WAZUH_5X_PRIMARY_MANIFEST_URL" "$primary_manifest"

  if ! resolve_package_url_from_manifest "Wazuh Indexer" "$INDEXER_PACKAGE_KEY" "$primary_manifest" "$WAZUH_5X_PRIMARY_MANIFEST_URL" "primary"; then
    echo "==> Wazuh Indexer package key '$INDEXER_PACKAGE_KEY' not found in primary manifest."
    echo "    Trying fallback manifest..."
    fetch_manifest "$WAZUH_5X_FALLBACK_MANIFEST_URL" "$fallback_manifest"
    fallback_manifest_loaded=1
    resolve_package_url_from_manifest "Wazuh Indexer" "$INDEXER_PACKAGE_KEY" "$fallback_manifest" "$WAZUH_5X_FALLBACK_MANIFEST_URL" "fallback" || {
      echo "ERROR: package key '$INDEXER_PACKAGE_KEY' not found in primary or fallback manifests." >&2
      return 1
    }
  fi
  download_package_from_url "Wazuh Indexer" "$RESOLVED_PACKAGE_URL" "wazuh-indexer" "$INDEXER_PACKAGE_FILE"

  if ! resolve_package_url_from_manifest "Wazuh Dashboard" "$DASHBOARD_PACKAGE_KEY" "$primary_manifest" "$WAZUH_5X_PRIMARY_MANIFEST_URL" "primary"; then
    echo "==> Wazuh Dashboard package key '$DASHBOARD_PACKAGE_KEY' not found in primary manifest."
    echo "    Trying fallback manifest..."
    if [[ "$fallback_manifest_loaded" -ne 1 ]]; then
      fetch_manifest "$WAZUH_5X_FALLBACK_MANIFEST_URL" "$fallback_manifest"
      fallback_manifest_loaded=1
    fi
    resolve_package_url_from_manifest "Wazuh Dashboard" "$DASHBOARD_PACKAGE_KEY" "$fallback_manifest" "$WAZUH_5X_FALLBACK_MANIFEST_URL" "fallback" || {
      echo "ERROR: package key '$DASHBOARD_PACKAGE_KEY' not found in primary or fallback manifests." >&2
      return 1
    }
  fi
  download_package_from_url "Wazuh Dashboard" "$RESOLVED_PACKAGE_URL" "wazuh-dashboard" "$DASHBOARD_PACKAGE_FILE"

  rm -f "$primary_manifest" "$fallback_manifest"
  trap - RETURN
}


# ==============================================================================
#                   Indexer
# ==============================================================================
function get_indexer_artifact() {
  local repo="wazuh/wazuh-indexer"
  local workflow_file="5_builderpackage_indexer.yml"
  local run_name_prefix='Build [ \"deb\" ] Wazuh Indexer on [ \"x64\" ] | main_'

  echo "==> Searching for the first successful build for the Wazuh Indexer 5.x..."
  local run_id
  run_id="$( find_first_successful_run "$repo" "$workflow_file" "$run_name_prefix" )"

  if [[ -z "$run_id" ]]; then
    echo "==> Cannot find a successful build for the Wazuh Indexer"
    exit 1
  fi

  echo "==> Found successful build for the Wazuh Indexer"
  echo "    run_id: $run_id (https://github.com/$repo/actions/runs/$run_id)"

  echo ""
  echo "==> Artifacts:"
  list_run_artifacts "$repo" "$run_id"

  # Download:
  #  - If artifact_name matches wazuh-indexer_5.0.0-${VAR}_amd64.deb,
  #    save it as "wazuh-indexer_5.0.0-latest_amd64.deb"
  fetch_artifacts_with_patterns \
    "$repo" "$run_id" "wazuh-indexer" \
    '^wazuh-indexer_5\.0\.0-[[:alnum:]]+_amd64\.deb$::wazuh-indexer_5.0.0-latest_amd64.deb'
}


# ==============================================================================
#                   Dashboard
# ==============================================================================
function get_dashboard_artifact() {
  local repo="wazuh/wazuh-dashboard"
  local workflow_file="5_builderpackage_dashboard.yml"
  local run_name_prefix='Build deb wazuh-dashboard on amd64 - is stage - checksum main_'

  echo "==> Searching for the first successful build for the Wazuh Dashboard..."
  local run_id
  run_id="$( find_first_successful_run "$repo" "$workflow_file" "$run_name_prefix" )"

  if [[ -z "$run_id" ]]; then
    echo "==> Cannot find a successful build for the Wazuh Dashboard"
    exit 1
  fi

  echo "==> Found successful build for the Wazuh Dashboard"
  echo "    run_id: $run_id (https://github.com/$repo/actions/runs/$run_id)"

  echo ""
  echo "==> Artifacts:"
  list_run_artifacts "$repo" "$run_id"

  # Download:
  #  - If artifact_name matches wazuh-dashboard_5.0.0-${VAR}_amd64.deb,
  #    save it as "wazuh-dashboard_5.0.0-latest_amd64.deb"
  fetch_artifacts_with_patterns \
    "$repo" "$run_id" "wazuh-dashboard" \
    '^wazuh-dashboard_5\.0\.0-[[:alnum:]]+_amd64\.deb$::wazuh-dashboard_5.0.0-latest_amd64.deb'
}

####################################################
#                   MAIN
####################################################

need_cmd curl

# Download the last version of the Wazuh Indexer and Dashboard
if [[ "$FROM_WORKFLOWS" -eq 1 ]]; then
  need_cmd gh
  need_cmd unzip

  # Make sure we have a GitHub token
  gh_token

  get_indexer_artifact
  get_dashboard_artifact
else
  get_packages_from_manifests
fi

# Init certs
upsert_certs

# Let containerised agents reach remoted
open_manager_listeners

echo ""
echo "==========================================================="
echo "  init.sh finished at $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Log: $LOG_FILE"
echo "==========================================================="

exit 0
