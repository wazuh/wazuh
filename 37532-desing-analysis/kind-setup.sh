#!/bin/bash
# Reproduce the Kubernetes topology used by the #37532 container-security spike.
#
# Topology is SIDE-BY-SIDE (D4): a KinD node running under the host's dockerd,
# with the Wazuh agent installed on the host -- not in a pod. Nothing is
# auto-mounted or injected, so the agent needs an explicit kubeconfig on disk
# (D5), and <node_name> must match the real node name or the pod list, which is
# node-scoped, returns nothing.
#
# The names below are not arbitrary: they match the capture in
# 37532-desing-analysis/15-spike-resume.md 15.10, which the test plan diffs
# against as golden output.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-demo}"          # node becomes <name>-control-plane
NODE_NAME="${CLUSTER_NAME}-control-plane"
NAMESPACE="${NAMESPACE:-default}"
DEPLOYMENT="${DEPLOYMENT:-cfim-k8s-demo}"
CONTAINER="${CONTAINER:-writer}"
KUBECONFIG_DEST="${KUBECONFIG_DEST:-/etc/wazuh-agent/container_instances/kubeconfig}"

log() { printf '[kind-setup] %s\n' "$*"; }

if ! kind get clusters 2>/dev/null | grep -qx "${CLUSTER_NAME}"; then
    log "creating cluster ${CLUSTER_NAME}"
    kind create cluster --name "${CLUSTER_NAME}" --wait 120s
else
    log "cluster ${CLUSTER_NAME} already exists"
fi

log "node name is ${NODE_NAME} -- this must match <node_name> in ossec.conf"
kubectl get nodes -o name

# A two-container pod. The second container is what makes 4.5 testable: the
# module must emit one INDEPENDENT record per container, each carrying its own
# copy of the same kubernetes object. A single-container pod cannot show that.
log "applying deployment ${DEPLOYMENT} (containers: ${CONTAINER}, sidecar)"
kubectl apply -f - <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${DEPLOYMENT}
  namespace: ${NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels: {app: ${DEPLOYMENT}}
  template:
    metadata:
      labels: {app: ${DEPLOYMENT}}
      annotations:
        wazuh.com/spike: "37532"
    spec:
      containers:
        - name: ${CONTAINER}
          image: busybox:latest
          command: ["sh","-c","mkdir -p /data && echo seed > /data/seed.txt && while :; do sleep 5; done"]
        - name: sidecar
          image: busybox:latest
          command: ["sh","-c","mkdir -p /data && echo side > /data/side.txt && while :; do sleep 5; done"]
YAML

kubectl -n "${NAMESPACE}" rollout status "deployment/${DEPLOYMENT}" --timeout=180s

# The agent reads a kubeconfig from disk. `kind export kubeconfig` writes
# client-cert credentials, which ARE supported; an exec credential plugin is
# rejected outright by yaml_kubeconfig_loader.cpp, so never hand this an
# ambient cloud kubeconfig.
log "exporting kubeconfig to ${KUBECONFIG_DEST}"
sudo install -d -m 0750 "$(dirname "${KUBECONFIG_DEST}")"
kind export kubeconfig --name "${CLUSTER_NAME}" --kubeconfig /tmp/kind-kubeconfig
# The exported server URL points at 127.0.0.1:<port>, which is correct here
# because the agent runs on the same host as the KinD node.
sudo install -m 0640 -o root -g wazuh /tmp/kind-kubeconfig "${KUBECONFIG_DEST}" 2>/dev/null \
    || sudo install -m 0640 /tmp/kind-kubeconfig "${KUBECONFIG_DEST}"
rm -f /tmp/kind-kubeconfig

if grep -q "exec:" "${KUBECONFIG_DEST}" 2>/dev/null || sudo grep -q "exec:" "${KUBECONFIG_DEST}" 2>/dev/null; then
    log "FATAL: kubeconfig uses an exec credential plugin; the agent will reject it"
    exit 1
fi
log "kubeconfig has no exec plugin -- accepted credential type"

log "done. Pod containers and their cgroups:"
for p in $(kubectl -n "${NAMESPACE}" get pods -l "app=${DEPLOYMENT}" -o name); do
    kubectl -n "${NAMESPACE}" get "${p}" -o jsonpath='{.metadata.name}{"\n"}'
done
log "set <node_name>${NODE_NAME}</node_name> in <container_security>"
