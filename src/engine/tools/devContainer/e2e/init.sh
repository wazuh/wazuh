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
CERTS_ONLY=0
REGEN_CERTS=0
ROTATE_CA=0
for arg in "$@"; do
  case "$arg" in
    --from-wf|--from-workflow|--from-workflows)
      FROM_WORKFLOWS=1
      ;;
    --certs-only)
      CERTS_ONLY=1
      ;;
    --regen-certs)
      REGEN_CERTS=1
      ;;
    --rotate-ca)
      ROTATE_CA=1
      ;;
    -h|--help)
      cat <<EOF
Usage: $0 [--from-wf] [--certs-only] [--regen-certs] [--rotate-ca]

Initializes the E2E environment: downloads the Wazuh Indexer and Dashboard
packages and generates the TLS certificates into certs/ with
scripts/wazuh-certs-tool.sh, driven by scripts/wazuh-certs-tool.yml.

By default, the packages are downloaded from the staging nightly artifact URL
manifests. If a package is missing from the primary manifest, the script tries
the nightly backup manifest.

Options:
  --from-wf, --from-workflow, --from-workflows
                 Download packages from the latest successful GitHub Actions
                 workflows instead of the staging manifests.
  --certs-only   Skip the package download; only (re)generate the certificates.
  --regen-certs  Regenerate the certificates without asking when certs/ exists.
  --rotate-ca    Issue a new root CA instead of reusing certs/root-ca.{pem,key}.
                 Everything that trusts the current CA must be redeployed after
                 that (docker compose down -v && up -d, sudo ./wazuh_copy_certs.sh).
  --help, -h     Show this help.

Required tools:
  default mode:  curl, openssl
  --from-wf:     curl, gh, unzip, openssl
  --certs-only:  openssl
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

# Certificates: issued by the devcontainer copy of the installation assistant's
# certificate tool, driven by the YAML next to it (its node names are load-bearing,
# see the comments in that file). WAZUH_DEV_SCRIPTS is exported by the devcontainer.
WAZUH_DEV_SCRIPTS="${WAZUH_DEV_SCRIPTS:-${SCRIPT_DIR}/../scripts}"
WAZUH_DEV_SCRIPTS="${WAZUH_DEV_SCRIPTS%/}"
CERTS_TOOL="${WAZUH_DEV_SCRIPTS}/wazuh-certs-tool.sh"
CERTS_CONFIG="${CERTS_CONFIG:-${WAZUH_DEV_SCRIPTS}/wazuh-certs-tool.yml}"
CERTS_DIR="${SCRIPT_DIR}/certs"


# ==============================================================================
#                      Manager listener bind addresses
# ==============================================================================
# Both remoted listeners (https.bind_addr, legacy.local_ip) ship bound to
# 0.0.0.0 -- see docs/ref/modules/remoted/configuration.md -- but an installation
# predating that default change may still carry the old 127.0.0.1 values.
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
# First "- name:" under "manager:" in the certs YAML. awk rather than yq so the same
# helper works under sudo in wazuh_copy_certs.sh; comments and blank lines skipped.
function manager_node_name() {
  awk '
    function indent(s) { match(s, /^[ \t]*/); return RLENGTH }
    /^[ \t]*#/ || /^[ \t]*$/ { next }
    /^[ \t]*manager:[ \t]*$/ { in_mgr = 1; mgr_indent = indent($0); next }
    in_mgr && /^[ \t]*[A-Za-z0-9_]+:[ \t]*$/ && indent($0) <= mgr_indent { in_mgr = 0 }
    in_mgr && /^[ \t]*-[ \t]*name:[ \t]*/ {
      sub(/^[ \t]*-[ \t]*name:[ \t]*/, ""); gsub(/["'"'"']/, ""); sub(/[ \t]+$/, "")
      print; exit
    }
  ' "$CERTS_CONFIG"
}

function upsert_certs() {
  echo "==> Certificates (${CERTS_DIR})..."
  need_cmd openssl

  if [ ! -f "$CERTS_TOOL" ]; then
    echo "ERROR: certificate tool not found: $CERTS_TOOL (set WAZUH_DEV_SCRIPTS)" >&2
    return 1
  fi
  if [ ! -f "$CERTS_CONFIG" ]; then
    echo "ERROR: certificate configuration not found: $CERTS_CONFIG" >&2
    return 1
  fi

  local manager_name
  manager_name="$(manager_node_name)"
  if [ -z "$manager_name" ]; then
    echo "ERROR: no manager node ('- name:' under 'manager:') in $CERTS_CONFIG" >&2
    return 1
  fi

  # Existing certificates: ask before replacing them unless --regen-certs
  if [ -d "$CERTS_DIR" ] && [ -n "$(ls -A "$CERTS_DIR")" ]; then
    echo "==> Certificates directory already exists."
    if (( REGEN_CERTS == 0 )); then
      read -p "Do you want to regenerate the certificates? This will delete the existing certs directory. (y/N): " -n 1 -r
      echo
      if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "==> Skipping certificate generation."
        return 0
      fi
    fi
  fi

  # Root CA: reuse the current one (the indexer/dashboard containers and the
  # installed manager trust it) unless --rotate-ca. Copied aside first because
  # certs/ is wiped below; the RETURN trap removes the copy on every exit path.
  local -a ca_args=()
  local ca_tmp=""
  if (( ROTATE_CA == 0 )) && [ -f "$CERTS_DIR/root-ca.pem" ] && [ -f "$CERTS_DIR/root-ca.key" ]; then
    ca_tmp="$(mktemp -d)"
    trap "rm -rf '${ca_tmp}'; trap - RETURN" RETURN
    cp "$CERTS_DIR/root-ca.pem" "$CERTS_DIR/root-ca.key" "$ca_tmp/"
    ca_args=("$ca_tmp/root-ca.pem" "$ca_tmp/root-ca.key")
    echo "==> Reusing the existing root CA (${CERTS_DIR}/root-ca.pem); pass --rotate-ca to issue a new one."
  elif (( ROTATE_CA == 1 )); then
    echo "==> Rotating the root CA: a new root-ca.pem / root-ca.key will be issued."
  else
    echo "==> No reusable root CA in ${CERTS_DIR}; a new one will be issued."
  fi

  echo "==> Removing existing certificates directory..."
  rm -rf "$CERTS_DIR"

  echo "==> Generating certificates with ${CERTS_TOOL}..."
  echo "    config: ${CERTS_CONFIG}"
  if ! bash "$CERTS_TOOL" -A "${ca_args[@]}" -v -c "$CERTS_CONFIG" -o "$CERTS_DIR"; then
    echo "ERROR: certificate generation failed (see ${CERTS_DIR}/wazuh-certificates-tool.log)" >&2
    return 1
  fi

  # Post-checks: the files the docker entrypoints (node-1*, admin*, dashboard*,
  # root-ca.pem) and wazuh_copy_certs.sh (<manager>*) copy by name.
  local -a required=(
    root-ca.pem root-ca.key
    admin.pem admin-key.pem
    node-1.pem node-1-key.pem
    dashboard.pem dashboard-key.pem
    "${manager_name}.pem" "${manager_name}-key.pem"
    "${manager_name}-remoted.pem" "${manager_name}-remoted-key.pem"
  )
  local f
  for f in "${required[@]}"; do
    if [ ! -s "$CERTS_DIR/$f" ]; then
      echo "ERROR: expected certificate file missing: $CERTS_DIR/$f" >&2
      return 1
    fi
  done

  echo "==> Verifying the certificates against ${CERTS_DIR}/root-ca.pem..."
  for f in admin.pem node-1.pem dashboard.pem "${manager_name}.pem" "${manager_name}-remoted.pem"; do
    if ! openssl verify -CAfile "$CERTS_DIR/root-ca.pem" "$CERTS_DIR/$f" | sed 's/^/    /'; then
      echo "ERROR: $CERTS_DIR/$f does not verify against root-ca.pem" >&2
      return 1
    fi
  done

  echo "==> Agent listener certificate (${manager_name}-remoted.pem, leaf followed by the CA):"
  openssl x509 -in "$CERTS_DIR/${manager_name}-remoted.pem" -noout -subject -issuer -enddate \
    -ext subjectAltName,extendedKeyUsage,keyUsage,basicConstraints | sed 's/^/    /'

  echo "==> Certificates created successfully in ${CERTS_DIR}."
  echo "    Next steps:"
  echo "      sudo ./wazuh_copy_certs.sh              # deploy into ${WAZUH_MANAGER_HOME}/etc/certs"
  echo "      ${WAZUH_MANAGER_HOME}/bin/wazuh-manager-control restart"
  echo "      docker compose -f ${SCRIPT_DIR}/docker-compose.yml down && docker compose -f ${SCRIPT_DIR}/docker-compose.yml up -d"
  echo "        (the containers copy the certificates at start; not required while the CA is unchanged)"
  if (( ROTATE_CA == 1 )); then
    echo "    The root CA was rotated: everything that trusted the old CA must be redeployed:"
    echo "      docker compose -f ${SCRIPT_DIR}/docker-compose.yml down -v && docker compose -f ${SCRIPT_DIR}/docker-compose.yml up -d"
    echo "        (-v drops the indexer volumes so its security index is re-initialised with the new admin certificate)"
  fi
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

if (( CERTS_ONLY == 0 )); then
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
else
  echo "==> --certs-only: skipping the package download."
  echo ""
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
