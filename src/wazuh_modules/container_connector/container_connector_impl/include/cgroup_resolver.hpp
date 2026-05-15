#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace wazuh::container_connector {

/// @brief Build a snapshot map from CRI container id (no runtime prefix) to the
/// kernel cgroup_id (st_ino of the cgroup directory under /sys/fs/cgroup) for
/// every running container visible from the agent's PID namespace.
///
/// Implementation: one pass over /proc/[0-9]+/cgroup. For each task we read
/// the cgroup v2 unified entry ("0::<path>"), extract the CRI container id
/// from the leaf basename (handles cri-containerd-*.scope, crio-*.scope,
/// docker-*.scope, and the 64-hex leaf used by the cgroupfs driver), and
/// stat() the cgroupfs path to obtain its inode. That inode is exactly what
/// bpf_get_current_cgroup_id() reports from the kernel for any task in the
/// same cgroup, which is the join key used by the FIM eBPF pipeline.
///
/// Properties:
///   - Agnostic to kubelet cgroup driver (systemd or cgroupfs).
///   - Agnostic to --kubelet-cgroups override and to --cgroup-root.
///   - Agnostic to outer-Docker wraps (kind / k3d / minikube docker driver).
///   - Works for static pods and custom cgroup parents.
///   - Single pass per reconcile cycle (O(N_processes) ≈ tens of ms on a
///     typical node), instead of N stat-with-glob calls per container.
///
/// Requirements:
///   - The agent must be able to read /proc/<pid>/cgroup of other tasks.
///     Root has this by default; as a DaemonSet, hostPID:true is required.
///   - The agent must run in the host's cgroup namespace (DaemonSet manifests
///     must NOT request a private cgroup namespace). Otherwise /proc/<pid>/cgroup
///     reports namespace-relative paths and stat() against /sys/fs/cgroup
///     fails to find them.
///
/// Failure mode: containers whose cgroup_id cannot be resolved are reported
/// with cgroup_id=0 (best-effort, no exceptions thrown). The watcher proceeds
/// and the FIM pipeline simply cannot do cgroup_id-keyed lookups for those
/// containers; lookups by container_id continue to work.
std::unordered_map<std::string, uint64_t> BuildCgroupIdMap();

/// @brief Compatibility wrapper that resolves a single container's cgroup_id.
///
/// Implemented in terms of BuildCgroupIdMap() and therefore costs the same
/// single /proc scan per call. PodWatcher uses BuildCgroupIdMap() directly
/// to amortize the scan across all containers in a reconcile cycle; this
/// wrapper exists for legacy call sites and tests.
///
/// @param pod_uid Unused (kept for backward compatibility).
/// @param container_id CRI container id without runtime prefix.
/// @return The cgroup_id (st_ino) of the container, or 0 if not resolvable.
uint64_t ResolveCgroupId(const std::string& pod_uid, const std::string& container_id);

} // namespace wazuh::container_connector
