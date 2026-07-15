#!/bin/bash
# Create the kind cluster for the #36101 spike, join the wazuh-testenv manager
# container to its docker network, and deploy the agent DaemonSet stack.
# Idempotent: safe to re-run.
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
QA_DIR="$REPO_ROOT/src/wazuh_modules/container_connector/qa/kind"
KIND_CLUSTER=${KIND_CLUSTER:-wazuh-spike}

if ! kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER"; then
    echo "==> creating kind cluster $KIND_CLUSTER"
    kind create cluster --config "$QA_DIR/kind-config.yaml"
else
    echo "==> kind cluster $KIND_CLUSTER already exists"
fi

echo "==> verifying kubelet rotation settings on the worker"
docker exec "$KIND_CLUSTER-worker" grep -E "containerLogMaxSize|containerLogMaxFiles|maxPods" /var/lib/kubelet/config.yaml || {
    echo "!! kubelet config patch missing — applying manually"
    docker exec "$KIND_CLUSTER-worker" bash -c '
      sed -i "/^containerLogMaxSize/d;/^containerLogMaxFiles/d;/^maxPods/d" /var/lib/kubelet/config.yaml
      printf "containerLogMaxSize: \"1Mi\"\ncontainerLogMaxFiles: 3\nmaxPods: 150\n" >> /var/lib/kubelet/config.yaml
      systemctl restart kubelet'
}

echo "==> joining wazuh-server to the kind docker network"
docker network connect kind wazuh-server 2>/dev/null || true
MANAGER_IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' wazuh-server)
echo "==> manager IP on kind network: $MANAGER_IP"

echo "==> ensuring the engine file output channel is enabled on the manager"
docker exec wazuh-server bash -c '
  f=/var/wazuh-manager/etc/outputs/default/file-output-integrations.yml
  if grep -q "^enabled: false" "$f"; then
      sed -i "s/^enabled: false/enabled: true/" "$f"
      systemctl restart wazuh-manager
      echo "   (file output enabled; manager restarted)"
  else
      echo "   (already enabled)"
  fi'

echo "==> applying manifests"
kubectl apply -f "$QA_DIR/manifests/00-namespace.yaml"
kubectl apply -f "$QA_DIR/manifests/01-rbac.yaml"
kubectl apply -f "$QA_DIR/manifests/02-agent-config.yaml"
sed "s/__MANAGER_IP__/$MANAGER_IP/" "$QA_DIR/manifests/03-daemonset.yaml" | kubectl apply -f -

echo "==> waiting for the agent DaemonSet"
kubectl -n wazuh rollout status ds/wazuh-agent --timeout=180s || true
kubectl -n wazuh get pods -o wide
