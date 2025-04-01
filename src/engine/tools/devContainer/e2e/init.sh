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

    local tmp_crt_gen="tmp_gen_certs.sh"
    local url_crt_gen="https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/main/apis/tools/env/certs/gen_certs.sh"

    # if exists, remove the certs directory
    if [ -d certs ]; then
        rm -rf certs/*
    elif [ ! -d certs ]; then
        mkdir certs
    fi
    curl -s -L -o "${tmp_crt_gen}" "${url_crt_gen}"
    chmod +x "${tmp_crt_gen}"
    bash "${tmp_crt_gen}"
    rm "${tmp_crt_gen}"

    echo "==> Certificates created."

    chmod 644 ./certs/root-ca.pem
    chmod 644 ./certs/wazuh-indexer*

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
  echo ""
}

#
# Find and filter artifacts by prefix, and for each artifact define a "dest_file" # according to the prefix.
#   args:
#     $1 => repo (e.g. "wazuh/wazuh-indexer")
#     $2 => run_id (e.g. "123456789")
#     $3 => output_dir (e.g. "wazuh-indexer")
#     from $4 => list of prefix::filename pairs (e.g.
#                "prefix1::file1.zip" "wazuh-indexer-setup-5.0::wazuh-indexer-setup-5.0.0.0.zip"
#
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

  # List the artifacts - piping to 'cat' to avoid paging
  local raw_kv_art
  raw_kv_art=$(
    gh api "repos/$repo/actions/runs/$run_id/artifacts" \
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
  local run_name_prefix='Build [ \"deb\" ] Wazuh Indexer on [ \"x64\" ] | main'

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

  # Descargamos:
  #  - Si artifact_name empieza con "wazuh-indexer-command-manager-5.0", lo guardamos como "wazuh-indexer-command-manager-5.0.0.0.zip"
  #  - Si artifact_name empieza con "wazuh-indexer-setup-5.0", lo guardamos como "wazuh-indexer-setup-5.0.0.0.zip"
  fetch_artifacts_with_prefixes \
    "$repo" "$run_id" "wazuh-indexer" \
    "wazuh-indexer-command-manager-5.0::wazuh-indexer-command-manager-5.0.0.0.zip" \
    "wazuh-indexer-setup-5.0::wazuh-indexer-setup-5.0.0.0.zip"
}


# ==============================================================================
#                   Dashboard
# ==============================================================================
function get_dashboard_artifact() {
  local repo="wazuh/wazuh-dashboard"
  local workflow_file="5_builderpackage_dashboard.yml"
  local run_name_prefix='Build deb wazuh-dashboard on amd64'

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

  # Descargamos:
  #  - Si artifact_name empieza con "wazuh-dashboard_5.0.0-latest_amd64.deb", 
  #    lo guardamos como "wazuh-dashboard_5.0.0-latest_amd64.deb"
  fetch_artifacts_with_prefixes \
    "$repo" "$run_id" "wazuh-dashboard" \
    "wazuh-dashboard_5.0.0-latest_amd64.deb::wazuh-dashboard_5.0.0-latest_amd64.deb"
}

####################################################
#                   MAIN
####################################################

# Make sure we have a GitHub token
gh_token

# Download the last version of the Wazuh Indexer and Dashboard
get_indexer_artifact
get_dashboard_artifact

# Init certs
upsert_certs

exit 0
