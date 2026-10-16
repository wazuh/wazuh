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
#     run with the same bytes is kept, and one with other bytes (builds are not
#     byte-reproducible, and the pool allows deletes) stops the run: this run did
#     not test those bytes, so an admin deletes the incomplete ref first;
#   - manifest.json goes last, so a ref without it is incomplete and the next
#     run completes it.
#
# In a workflow run (GITHUB_RUN_ID set) it then writes the record
# deps/pool/_published/<run id>-<attempt>.json: every ref of the tree, the pull
# request (PUBLISH_PULL_REQUEST) and the commit (PUBLISH_COMMIT, default
# GITHUB_SHA). deps.py orphans reads the records to see the refs published from a
# pull request whose commits no branch keeps.
#
# Needs bash >= 4.4 (inherit_errexit), python3 and an AWS CLI with
# put-object --if-none-match: an older one rejects the option on the first upload,
# which then fails before writing anything. The role needs s3:ListBucket on the
# bucket, limited to the deps/pool/ prefix.

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

    if aws s3api get-object --bucket "${BUCKET}" --key "${prefix}/manifest.json" "${WORK}/remote.json" >/dev/null 2>"${WORK}/get.err"; then
        if [ "$(json_get "${WORK}/remote.json" inputs_hash)" != "${inputs}" ]; then
            err "${ref} is published with other inputs"
            exit 1
        fi
        log "${ref} is already published"
        skipped=$((skipped + 1))
        continue
    fi
    # Only a missing key means unpublished; any other error (a transient 403, a cut connection) stops the run
    # before it uploads over a ref that may be complete.
    if ! grep -q 'NoSuchKey' "${WORK}/get.err"; then
        err "cannot read ${prefix}/manifest.json: $(cat "${WORK}/get.err")"
        exit 1
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
            err "${ref}/${rel} is already in the pool with other bytes (sha256 ${existing}, this run ${want})."
            err "This run did not test them: delete the incomplete ref (aws s3 rm s3://${BUCKET}/${prefix}/ --recursive) and run again."
            exit 1
        fi
    done < <(find "${dir}" -type f -print0 | sort -z)

    existing="$(put "${manifest}" "${prefix}/manifest.json")"
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

if [ -z "${GITHUB_RUN_ID:-}" ]; then
    log "no GITHUB_RUN_ID: no record under deps/pool/_published/ (deps.py orphans will not see these refs unless a branch keeps them)"
    exit 0
fi
record="deps/pool/_published/${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT:-1}.json"
printf '%s\n' "${refs}" > "${WORK}/refs.txt"
python3 - "${WORK}/record.json" "${POOL_DIR%/}" "${WORK}/refs.txt" <<'PY'
import json, os, sys, time
out, pool, refs = sys.argv[1], sys.argv[2] + "/", open(sys.argv[3]).read().splitlines()
pull = os.environ.get("PUBLISH_PULL_REQUEST", "")
json.dump({
    "workflow_run": f'{os.environ.get("GITHUB_SERVER_URL", "https://github.com")}/{os.environ.get("GITHUB_REPOSITORY", "")}'
                    f'/actions/runs/{os.environ["GITHUB_RUN_ID"]}',
    "run_id": int(os.environ["GITHUB_RUN_ID"]),
    "run_attempt": int(os.environ.get("GITHUB_RUN_ATTEMPT", "1")),
    "event": os.environ.get("GITHUB_EVENT_NAME", ""),
    "pull_request": int(pull) if pull else None,
    "commit": os.environ.get("PUBLISH_COMMIT") or os.environ.get("GITHUB_SHA", ""),
    "published_at": int(time.time()),
    "refs": sorted(ref.removeprefix(pool) for ref in refs),
}, open(out, "w"), indent=2)
PY
existing="$(put "${WORK}/record.json" "${record}")"
if [ -n "${existing}" ]; then
    err "${record} already exists: an attempt of a run publishes once"
    exit 1
fi
log "recorded the refs of this run in ${record}"
