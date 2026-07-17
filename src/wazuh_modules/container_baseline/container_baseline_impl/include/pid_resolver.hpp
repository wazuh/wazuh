#pragma once

#include <sys/types.h>

#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief Resolve the set of live PIDs (in the agent's own PID namespace) that
/// belong to a given container.
///
/// This is the reverse of container_instances' cgroup resolution path
/// (which maps container_id -> cgroup_id but discards the PID along the way).
/// The baseline module needs an actual PID to address the container's mount
/// namespace via /proc/<pid>/root/<path>, so it re-walks /proc and keeps every
/// PID whose /proc/<pid>/cgroup leaf matches the target container_id.
///
/// One /proc scan per call — the caller is expected to call this once per
/// container per baseline run, not per file.
///
/// @param container_id CRI container id without runtime prefix (as returned by
///                      ContainerInstancesClient::listContainers()/resolveByCgroupId()).
/// @return Every live PID found in that container's cgroup, in no particular
///         order. Empty if the container has no live processes (e.g. already
///         exited) or the id is empty.
std::vector<pid_t> ResolvePidsForContainer(const std::string& container_id);

/// @brief Extract the CRI container id from a cgroup v2 unified path.
///
/// Exposed for unit testing; mirrors container_instances cgroup-id extraction
/// extraction rules (cri-containerd-*.scope, crio-*.scope, docker-*.scope,
/// and bare-hex cgroupfs-driver leaves), always reading from the path LEAF so
/// outer-Docker wraps (kind/k3d) don't get masked.
std::string ExtractContainerIdFromCgroupPath(const std::string& cgroup_path);

} // namespace wazuh::container_baseline
