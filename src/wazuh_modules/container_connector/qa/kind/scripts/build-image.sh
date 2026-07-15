#!/bin/bash
# Build the agent from the *currently checked-out branch* inside the
# wazuh-testenv agent container (incremental), install it to /var/ossec there,
# tar the installed tree, bake the thin runtime image and load it into kind.
#
# Differences vs the testenv's build-agent.sh (intentional):
#   - no clean-internals/clean-deps (incremental dev loop)
#   - rsync excludes the HOST's src/build and src/external (macOS artifacts
#     poison the Linux build volume; tracked files in src/external are copied
#     back explicitly)
#   - the agent service in the container is stopped, never started
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
QA_DIR="$REPO_ROOT/src/wazuh_modules/container_connector/qa/kind"
IMAGE_TAG=${IMAGE_TAG:-wazuh-agent-k8s:dev}
KIND_CLUSTER=${KIND_CLUSTER:-wazuh-spike}
NPROC=${NPROC:-4}

echo "==> [1/5] incremental agent build in wazuh-agent container"
docker exec wazuh-agent bash -c "
  set -e
  rsync -a --exclude=/src/build --exclude=/src/external /wazuh-repo/ /wazuh-build/
  cp /wazuh-repo/src/external/CMakeLists.txt /wazuh-repo/src/external/.gitignore /wazuh-build/src/external/ 2>/dev/null || true
  # procps compiles from source when no prebuilt libproc.a ships; wcwidth()
  # needs the feature-test macros under the 22.04 toolchain.
  if [ -f /wazuh-build/src/external/procps/escape.c ] \
     && ! grep -q _GNU_SOURCE /wazuh-build/src/external/procps/escape.c; then
      sed -i '1s/^/#define _GNU_SOURCE 1\n#define _XOPEN_SOURCE 700\n/' /wazuh-build/src/external/procps/escape.c
  fi
  make -C /wazuh-build/src TARGET=agent -j$NPROC > /tmp/build-agent.log 2>&1 \
    || { echo BUILD_FAIL; tail -30 /tmp/build-agent.log; exit 1; }
"

echo "==> [2/5] binary-install into the container's /var/ossec"
docker exec wazuh-agent bash -c "
  set -e
  systemctl stop wazuh-agent 2>/dev/null || true
  cd /wazuh-build
  USER_INSTALL_TYPE=agent USER_UPDATE=y USER_AGENT_MANAGER_IP=127.0.0.1 \
  USER_AUTO_START=n USER_ENABLE_ACTIVE_RESPONSE=n \
  bash ./install.sh binary-install > /tmp/install-agent.log 2>&1 \
    || { echo INSTALL_FAIL; tail -30 /tmp/install-agent.log; exit 1; }
"

echo "==> [3/5] tar installed tree (state and identity excluded)"
docker exec wazuh-agent bash -c "
  tar -C / \
      --exclude='var/ossec/etc/client.keys' \
      --exclude='var/ossec/logs/*' \
      --exclude='var/ossec/queue/k8s-logs' \
      --exclude='var/ossec/queue/logcollector/file_status.json' \
      --exclude='var/ossec/queue/rids/*' \
      --exclude='var/ossec/var/run/*' \
      -czf /tmp/agent-root.tgz var/ossec
"
docker cp wazuh-agent:/tmp/agent-root.tgz "$QA_DIR/agent-root.tgz"

echo "==> [4/5] docker build $IMAGE_TAG"
docker build -q -t "$IMAGE_TAG" -f "$QA_DIR/Dockerfile.runtime" "$QA_DIR"

echo "==> [5/5] kind load into cluster $KIND_CLUSTER"
kind load docker-image "$IMAGE_TAG" --name "$KIND_CLUSTER"

echo "==> done. Roll it out with:"
echo "    kubectl -n wazuh rollout restart ds/wazuh-agent && kubectl -n wazuh rollout status ds/wazuh-agent"
