#!/usr/bin/env bash
set -euo pipefail

# Move to the directory of the script
OLD_DIR=$(pwd)
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
trap 'cd "$OLD_DIR"' EXIT

####################################################
#              Recreate certs
####################################################

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


####################################################
#                    GH
####################################################

# Get the GitHub token.
function gh_token() {
  GH_TOKEN="$(gh auth token 2>/dev/null || true)"
  if [[ -z "$GH_TOKEN" ]]; then
    echo "Cannot find a GitHub token. Please run 'gh auth login' to authenticate."
    exit 1
  fi
}


####################################################
#                 Indexer
####################################################

function get_indexer_artifact() {
  local repo="wazuh/wazuh-indexer"
  local workflow_file="build.yml"
  local run_name_prefix='Build [ \"deb\" ] Wazuh Indexer on [ \"x64\" ] | main'

  # Search for the first successful build
  echo "==> Searching for the first successful build for the Wazuh Indexer 5.x..."
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
  if [[ -z "$run_id" ]]; then
    echo "==> Cannot find a successful build for the Wazuh Indexer"
    exit 1
  fi

  echo "==> Found successful build for the Wazuh Indexer"
  echo "    run_id: $run_id (https://github.com/$repo/actions/runs/$run_id)"

  # List the artifacts - piping to 'cat' to avoid paging
  echo ""
  echo "==> Artifacts:"
  gh api "repos/$repo/actions/runs/$run_id/artifacts" \
    -q '.artifacts[] | "- \(.name) => \(.archive_download_url)"' \
    | cat

  # Get the artifact(s) of interest
  local raw_kv_art
  raw_kv_art=$(
    gh api "repos/$repo/actions/runs/$run_id/artifacts" \
      -q '.artifacts[]
          | select(
              (.name | startswith("wazuh-indexer-command-manager-5.0"))
              or
              (.name | startswith("wazuh-indexer-setup-5.0"))
            )
          | "\(.name) \(.archive_download_url)"'
  )

  if [[ -z "$raw_kv_art" ]]; then
    echo "==> Cannot find the desired artifacts for the Wazuh Indexer"
    exit 1
  fi

  echo ""
  echo "==> Downloading artifacts of interest..."

  # Read line by line to parse artifact_name and artifact_url
  while read -r artifact_line; do
    local artifact_name
    local artifact_url
    artifact_name="$(echo "$artifact_line" | awk '{print $1}')"
    artifact_url="$(echo "$artifact_line"  | awk '{print $2}')"

    # Determine the destination file
    local dest_file=""
    local tmp_file="tmp_artifact.zip"
    if [[ "$artifact_name" == wazuh-indexer-command-manager-5.0* ]]; then
      dest_file="wazuh-indexer-command-manager-5.0.0.0.zip"
    elif [[ "$artifact_name" == wazuh-indexer-setup-5.0* ]]; then
      dest_file="wazuh-indexer-setup-5.0.0.0.zip"
    else
      # Skip unknown artifacts
      continue
    fi

    # Download the artifact
    echo "==> Downloading: $artifact_name"

    curl -sSL \
      -H "Authorization: Bearer $GH_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      "$artifact_url" \
      -o "wazuh-indexer/${tmp_file}"
    echo "    => Download finished."

    # The artifact is a zip file with a zip file inside, this is the file we want
    echo "    => Unzipping..."
    unziped_file=$(unzip -l "wazuh-indexer/${tmp_file}" | awk 'NR==4 {print $4}')
    unzip -oq "wazuh-indexer/${tmp_file}" -d "wazuh-indexer"
    echo "    => Unzip finished."

    # Get the name of the unzipped file
    echo "    => Unzipped file: $unziped_file, moving the content to $dest_file"
    mv "wazuh-indexer/${unziped_file}" "wazuh-indexer/${dest_file}"
    rm "wazuh-indexer/${tmp_file}"

    echo ""
  done <<< "$raw_kv_art"

  echo "==> Done."
}


####################################################
#                 Dashboard
####################################################

function get_dashboard_artifact() {
  local repo="wazuh/wazuh-dashboard"
  local workflow_file="5_builderpackage_dashboard.yml"
  local run_name_prefix='Build deb wazuh-dashboard on amd64'

  # Search for the first successful build
  echo "==> Searching for the first successful build for the Wazuh Dashboard..."
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

  echo "==> run_id: $run_id"

  # If no successful build is found, exit
  if [[ -z "$run_id" ]]; then
    echo "==> Cannot find a successful build for the Wazuh Dashboard"
    exit 1
  fi

  echo "==> Found successful build for the Wazuh Dashboard"
  echo "    run_id: $run_id (https://github.com/$repo/actions/runs/$run_id)"

  # List the artifacts - piping to 'cat' to avoid paging
  echo ""
  echo "==> Artifacts:"
  gh api "repos/$repo/actions/runs/$run_id/artifacts" \
    -q '.artifacts[] | "- \(.name) => \(.archive_download_url)"' \
    | cat

  # Get the artifact(s) of interest
  local raw_kv_art
  raw_kv_art=$(
    gh api "repos/$repo/actions/runs/$run_id/artifacts" \
      -q '.artifacts[]
          | select(
              (.name | startswith("wazuh-dashboard_5.0.0-latest_amd64.deb"))
            )
          | "\(.name) \(.archive_download_url)"'
  )

  if [[ -z "$raw_kv_art" ]]; then
    echo "==> Cannot find the desired artifacts for the Wazuh Dashboard"
    exit 1
  fi

  echo ""
  echo "==> Downloading artifacts of interest..."

  # Read line by line to parse artifact_name and artifact_url
  while read -r artifact_line; do
    local artifact_name
    local artifact_url
    artifact_name="$(echo "$artifact_line" | awk '{print $1}')"
    artifact_url="$(echo "$artifact_line"  | awk '{print $2}')"

    # Determine the destination file
    local dest_file=""
    local tmp_file="tmp_artifact.zip"
    if [[ "$artifact_name" == wazuh-dashboard_5.0.0-latest_amd64* ]]; then
      dest_file="wazuh-dashboard_5.0.0-latest_amd64.deb"
    else
      # Skip unknown artifacts
      continue
    fi

    # Download the artifact
    echo "==> Downloading: $artifact_name"

    curl -sSL \
      -H "Authorization: Bearer $GH_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      "$artifact_url" \
      -o "wazuh-dashboard/${tmp_file}"
    echo "    => Download finished."

    # The artifact is a zip file with a zip file inside, this is the file we want
    echo "    => Unzipping..."
    unziped_file=$(unzip -l "wazuh-dashboard/${tmp_file}" | awk 'NR==4 {print $4}')
    unzip -oq "wazuh-dashboard/${tmp_file}" -d "wazuh-dashboard"
    echo "    => Unzip finished."

    # Get the name of the unzipped file
    echo "    => Unzipped file: $unziped_file, moving the content to $dest_file"
    mv "wazuh-dashboard/${unziped_file}" "wazuh-dashboard/${dest_file}" || echo "    => File already exists, skipping."
    rm "wazuh-dashboard/${tmp_file}"

    echo ""
  done <<< "$raw_kv_art"

  echo "==> Done."
}

####################################################
#                   MAIN
####################################################

# Make sure we have a GitHub token
gh_token

# Get the desired artifacts
get_indexer_artifact
get_dashboard_artifact

# Init certs
upsert_certs



exit 0
