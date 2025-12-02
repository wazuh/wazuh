#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------------------------
# Move to the directory of the script
# ------------------------------------------------------------------------------
OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
trap 'cd "$OLD_DIR"' EXIT
cd "$SCRIPT_DIR"
# ==============================================================================
#                          Certificates
# ==============================================================================
function upsert_certs() {
    echo "==> Creating certificates..."

    # Ensure certs/ directory exists and is cleaned (may need sudo)
    sudo mkdir -p certs || mkdir -p certs
    sudo touch ./certs/root-ca.pem || touch ./certs/root-ca.pem
    sudo touch ./certs/server.pem || touch ./certs/server.pem
    sudo touch ./certs/server-key.pem || touch ./certs/server-key.pem
}
# ==============================================================================
#                          GitHub Token
# ==============================================================================
function gh_token() {
  if [[ -z "${GH_TOKEN:-}" ]]; then
    echo "ERROR: GH_TOKEN env var not provided"
    echo "Tip: set it in your .env file as GH_TOKEN=xxxxx"
    exit 1
  fi
}
# ==============================================================================
#                           Helpers
# ==============================================================================
function validate_gh_token() {
  if [ -z "${GH_TOKEN}" ] && [ -z "${GITHUB_TOKEN}" ]; then
    echo "Error: No authentication environment variable is defined" >&2
    echo "       You must define GH_TOKEN or GITHUB_TOKEN" >&2
    return 1
  fi

  local token="${GH_TOKEN:-${GITHUB_TOKEN}}"
  echo "$token"
}

function find_first_successful_run() {
  local repo=$1
  local workflow_file=$2
  local run_name_prefix=$3

  local token=""

  token=$(validate_gh_token)
  local endpoint="repos/$repo/actions/workflows/$workflow_file/runs"
  local run_id
  run_id=$(
    gh api "$endpoint" \
      --paginate \
      --header "Authorization: Bearer $token" \
      -q "
        .workflow_runs[]
        | select(
            .conclusion == \"success\"
            and (.name | startswith(\"$run_name_prefix\"))
          )
        | .id
      " | head -n 1 || true
  )

  echo "$run_id"
}


function list_run_artifacts() {
  local repo=$1
  local run_id=$2
  token=$(validate_gh_token)

  GH_TOKEN="${token}" gh api "repos/$repo/actions/runs/$run_id/artifacts" \
    -q '.artifacts[] | "- \(.name) => \(.archive_download_url)"'
}

function download_and_unzip_artifact() {
  local repo="$1"
  local run_id="$2"
  local artifact_url="$3"
  local output_dir="$4"
  local final_filename="$5"

  mkdir -p "$output_dir"

  local tmp_file="${output_dir}/tmp_artifact.zip"

  echo "==> Downloading artifact for run_id: $run_id"
  token=$(validate_gh_token)
  # Use curl to download artifact while capturing HTTP status. Some GitHub artifact URLs
  # return 401 or 404 when token is missing/invalid or lacks permissions.
  http_status=$(curl -sSL -w "%{http_code}" -H "Authorization: Bearer $token" -H "Accept: application/vnd.github+json" "$artifact_url" -o "$tmp_file" -L)
  if [[ "$http_status" != "200" ]]; then
    echo "ERROR: Failed downloading artifact (HTTP $http_status)."
    if [[ "$http_status" == "401" ]]; then
      echo "    -> Unauthorized (401). The GH_TOKEN appears to be invalid or lacks permissions."
      echo "    Tip: create a token with appropriate scopes (repo, workflow) and set GH_TOKEN in your .env or env var."
    elif [[ "$http_status" == "404" ]]; then
      echo "    -> Not Found (404). The artifact URL may be incorrect or not accessible. Check repository, workflow, and run id."
    fi
    # Remove any partial file
    rm -f "$tmp_file" || true
    return 1
  fi

  echo "    => Unzipping..."

  local unzipped_file
  unzipped_file=$(unzip -l "$tmp_file" | awk 'NR==4 {print $4}')

  if [[ -z "$unzipped_file" ]]; then
    echo "ERROR: Unable to detect file inside ZIP"
    exit 1
  fi

  unzip -oq "$tmp_file" -d "$output_dir"

  if [[ "$unzipped_file" != "$final_filename" ]]; then
    mv "${output_dir}/${unzipped_file}" "${output_dir}/${final_filename}" || true
  fi

  rm -f "$tmp_file"
  echo ""
}


function fetch_artifacts_with_prefixes() {
  local repo=$1
  local run_id=$2
  local output_dir=$3
  shift 3 # Shift the first three arguments to get the prefixes

  # Build the jq filter to select artifacts by prefix and create the prefix map "NAME URL"
  local jq_filter=""
  local -a prefix_map=()

  for pair in "$@"; do
    # pair is in the format "prefix::filename", we split it into prefix and final_filename
    # prefix is the prefix to match, final_filename is the name of the file to save the artifact as
    local prefix="${pair%%::*}"
    local final_filename="${pair##*::}"
    prefix_map+=("$prefix|$final_filename")

    # Add to jq filter
    if [[ -z "$jq_filter" ]]; then
      jq_filter="(.name | startswith(\"$prefix\"))"
    else
      jq_filter="$jq_filter or (.name | startswith(\"$prefix\"))"
    fi
  done
  token=$(validate_gh_token)
  # List the artifacts - piping to 'cat' to avoid paging
  local raw_kv_art
  raw_kv_art=$(
    GH_TOKEN="${token}" gh api "repos/$repo/actions/runs/$run_id/artifacts" \
      -q ".artifacts[]
          | select($jq_filter)
          | \"\(.name) \(.archive_download_url)\"" \
    | cat
  )

  if [[ -z "$raw_kv_art" ]]; then
    echo "==> Cannot find any artifacts matching given prefixes in $repo / run_id $run_id. See http://github.com/$repo/actions/runs/$run_id"
    return 0
  fi

  echo ""
  echo "==> Downloading artifacts of interest..."

  while read -r artifact_line; do
    local artifact_name artifact_url
    artifact_name="$(echo "$artifact_line" | awk '{print $1}')"
    artifact_url="$(echo "$artifact_line"  | awk '{print $2}')"

    # Determine the destination file
    for pm in "${prefix_map[@]}"; do
      local pre="${pm%%|*}"
      local final_f="${pm##*|}"

      if [[ "$artifact_name" == "$pre"* ]]; then
        download_and_unzip_artifact "$repo" "$run_id" "$artifact_url" "$output_dir" "$final_f"
        break
      fi
    done

  done <<< "$raw_kv_art"
}
# ==============================================================================
#                   Indexer
# ==============================================================================
function get_indexer_artifact() {
  local repo="wazuh/wazuh-indexer"
  local workflow_file="build.yml"
  local run_name_prefix='Build [ \"rpm\" ] Wazuh Indexer on [ \"x64\" ] '
  echo "==> Searching for successful Wazuh Indexer build..."
  local run_id
  run_id="$( find_first_successful_run "$repo" "$workflow_file" "$run_name_prefix" )"

  if [[ -z "$run_id" ]]; then
    echo "==> No successful builds found for Indexer"
    exit 1
  fi

  echo "==> Found successful build: https://github.com/$repo/actions/runs/$run_id"
  echo ""
  echo "==> Artifacts:"
  list_run_artifacts "$repo" "$run_id"

  fetch_artifacts_with_prefixes \
    "$repo" "$run_id" "wazuh-indexer" \
    "wazuh-indexer-command-manager-5.0::wazuh-indexer-command-manager-5.0.0.0.zip" \
    "wazuh-indexer-setup-5.0::wazuh-indexer-setup-5.0.0.0.zip"
}


####################################################
#                   MAIN
####################################################
if [[ -f .env ]]; then
  echo "==> Loading .env..."
  export $(grep -v '^#' .env | xargs -d '\n' || true)
fi
gh_token
get_indexer_artifact
upsert_certs

exit 0
