#!/bin/bash
#
# Publish the refs of a pool tree built by 5_builderpackage_externals.yml to
# s3://<bucket>/deps/pool/, the bucket behind packages.wazuh.com/deps/pool/.
#
#   publish_pool.sh <pool_dir> <bucket>
#
# <pool_dir> holds <name>/<version>-<key>/ directories, each with the
# manifest.json consolidate.sh wrote. AWS credentials come from the
# environment; AWS_REGION defaults to us-west-1.
#
# A published ref is never modified, and publishing is idempotent:
#   - a ref whose manifest.json is already published with the same inputs is
#     skipped, and with other inputs is an error;
#   - every file is written with --if-none-match '*'; a key left by an earlier
#     run is kept, and when its bytes differ (builds are not byte-reproducible)
#     its sha256 replaces this run's in the manifest that is uploaded;
#   - manifest.json goes last, so a ref without it is incomplete and the next
#     run completes it.
#
# Needs bash >= 4.4 (inherit_errexit), python3 and an AWS CLI with
# put-object --if-none-match; the role needs s3:ListBucket on the bucket, limited
# to the deps/pool/ prefix.

set -euo pipefail
# put() runs inside $(...): without this its failures would not stop the script.
shopt -s inherit_errexit
# File lists are compared as sorted text; the order must not depend on the locale.
export LC_ALL=C

log() { echo "[publish] $*"; }
err() { echo "[publish][ERROR] $*" >&2; }

if [ $# -ne 2 ]; then
    err "usage: $0 <pool_dir> <bucket>"
    exit 2
fi
POOL_DIR="$1" BUCKET="$2"
if [ ! -d "${POOL_DIR}" ]; then
    err "${POOL_DIR} is not a directory"
    exit 2
fi
export AWS_REGION="${AWS_REGION:-us-west-1}" AWS_DEFAULT_REGION="${AWS_REGION:-us-west-1}"

if ! aws s3api put-object help 2>/dev/null | grep -q -- '--if-none-match'; then
    err "this AWS CLI does not support put-object --if-none-match"
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
json_get() { python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$1" "$2"; }

# Write $1 to key $2. On a key that exists, print the sha256 of what is there.
put() {
    local file="$1" key="$2" out
    if out="$(aws s3api put-object --bucket "${BUCKET}" --key "${key}" --body "${file}" --if-none-match '*' 2>&1)"; then
        return 0
    fi
    if ! grep -q 'PreconditionFailed' <<< "${out}"; then
        err "upload of ${key} failed: ${out}"
        return 1
    fi
    rm -f "${WORK}/existing"
    aws s3api get-object --bucket "${BUCKET}" --key "${key}" "${WORK}/existing" >/dev/null || return 1
    sha256_of "${WORK}/existing"
}

published=0 skipped=0
refs="$(find "${POOL_DIR}" -mindepth 2 -maxdepth 2 -type d | sort)"
if [ -z "${refs}" ]; then
    err "no <name>/<version>-<key>/ refs under ${POOL_DIR}"
    exit 1
fi
while IFS= read -r dir; do
    ref="${dir#"${POOL_DIR%/}/"}"
    manifest="${dir}/manifest.json"
    if [ ! -f "${manifest}" ]; then
        err "${ref} has no manifest.json"
        exit 1
    fi
    prefix="deps/pool/${ref}"
    inputs="$(json_get "${manifest}" inputs_hash)"

    if aws s3api get-object --bucket "${BUCKET}" --key "${prefix}/manifest.json" "${WORK}/remote.json" >/dev/null 2>&1; then
        if [ "$(json_get "${WORK}/remote.json" inputs_hash)" != "${inputs}" ]; then
            err "${ref} is published with other inputs"
            exit 1
        fi
        log "${ref} is already published"
        skipped=$((skipped + 1))
        continue
    fi

    # Every file the manifest lists must be here, and nothing else may sit under the ref:
    # make deps would take a stray object for a precompiled tarball.
    listed="$(python3 -c 'import json, sys; print("\n".join(sorted(json.load(open(sys.argv[1]))["files"])))' "${manifest}")"
    present="$(cd "${dir}" && find . -type f ! -name manifest.json | sed 's|^\./||' | sort)"
    if [ "${listed}" != "${present}" ]; then
        err "${ref}: the files do not match its manifest.json"
        exit 1
    fi
    remote="$(aws s3api list-objects-v2 --bucket "${BUCKET}" --prefix "${prefix}/" --query 'Contents[].Key' --output text)"
    for key in ${remote}; do
        # Its own manifest.json is handled below, as a race with another run.
        [ "${key}" = "None" ] || [ "${key}" = "${prefix}/manifest.json" ] && continue
        if ! grep -qxF -- "${key#"${prefix}/"}" <<< "${listed}"; then
            err "${ref}: ${key} is in the pool but not in this run's manifest"
            exit 1
        fi
    done

    # The manifest is uploaded from a copy that records the bytes the pool really has.
    cp "${manifest}" "${WORK}/manifest.json"
    while IFS= read -r -d '' file; do
        rel="${file#"${dir}/"}"
        [ "${rel}" = "manifest.json" ] && continue
        want="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["files"].get(sys.argv[2], ""))' "${manifest}" "${rel}")"
        if [ "${want}" != "$(sha256_of "${file}")" ]; then
            err "${ref}/${rel} does not match its manifest"
            exit 1
        fi
        existing="$(put "${file}" "${prefix}/${rel}")"
        if [ -n "${existing}" ] && [ "${existing}" != "${want}" ]; then
            log "${ref}/${rel} was uploaded by an earlier run with other bytes; keeping it"
            python3 - "${WORK}/manifest.json" "${rel}" "${existing}" <<'EOF'
import json, sys
path, rel, digest = sys.argv[1:]
manifest = json.load(open(path))
manifest["files"][rel] = digest
open(path, "w").write(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
EOF
        fi
    done < <(find "${dir}" -type f -print0 | sort -z)

    existing="$(put "${WORK}/manifest.json" "${prefix}/manifest.json")"
    if [ -n "${existing}" ]; then
        aws s3api get-object --bucket "${BUCKET}" --key "${prefix}/manifest.json" "${WORK}/remote.json" >/dev/null
        if [ "$(json_get "${WORK}/remote.json" inputs_hash)" != "${inputs}" ]; then
            err "${ref} was published meanwhile with other inputs"
            exit 1
        fi
        log "${ref} was published meanwhile by another run"
    fi
    published=$((published + 1))
done <<< "${refs}"

log "published ${published} refs, ${skipped} already in the pool"
