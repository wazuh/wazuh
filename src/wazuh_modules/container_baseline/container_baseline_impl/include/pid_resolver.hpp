#pragma once

#include <sys/types.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace wazuh::container_baseline {

/// @brief cgroup-leaf -> live PIDs index, built with a SINGLE /proc sweep and
/// shared by every container and every scanner in one baseline run.
///
/// Rationale: resolving a container's PIDs requires reading /proc/<pid>/cgroup
/// for every PID on the host. Doing that per container per scanner is
/// O(containers x processes) — on a node with 100 containers and 2000 processes
/// the previous per-call design performed 300 full /proc walks (~600k file
/// reads) per baseline cycle. One sweep answers every lookup instead.
///
/// The index is a point-in-time snapshot: a PID that exits after Build() is
/// still listed, so consumers must tolerate a read failing (they already do —
/// every scanner treats an unreadable /proc entry as "skip", not "error").
class PidIndex
{
    public:
        /// @brief Perform the single /proc sweep and build the index.
        static PidIndex Build();

        /// @brief Live PIDs belonging to `container_id`, ascending, so
        /// `.front()` is the lowest PID — the one most likely to be the
        /// container's entrypoint and the longest-lived. Returns a reference to
        /// a shared empty vector when the container has no live process.
        [[nodiscard]] const std::vector<pid_t>& pidsFor(const std::string& container_id) const;

        /// @brief Every container id seen during the sweep, each paired with its
        /// ascending PID list. Lets the caller derive cross-container facts in
        /// one pass — e.g. grouping containers by network-namespace inode to
        /// detect a shared (pod) netns.
        [[nodiscard]] const std::unordered_map<std::string, std::vector<pid_t>>& all() const noexcept
        {
            return m_byContainer;
        }

        /// @brief Number of distinct containers seen during the sweep.
        [[nodiscard]] std::size_t containerCount() const noexcept { return m_byContainer.size(); }

        /// @brief Number of PIDs attributed to some container during the sweep.
        [[nodiscard]] std::size_t processCount() const noexcept { return m_processCount; }

    private:
        std::unordered_map<std::string, std::vector<pid_t>> m_byContainer;
        std::size_t                                         m_processCount{0};
};

/// @brief Resolve the set of live PIDs (in the agent's own PID namespace) that
/// belong to a given container, with its own /proc sweep.
///
/// Prefer PidIndex when more than one container (or more than one scanner) needs
/// PIDs in the same run — this helper exists for single-container callers (the
/// qa/ harnesses) and for unit tests.
///
/// @param container_id CRI container id without runtime prefix (as returned by
///                      ContainerInstancesClient::listContainers()/resolveByCgroupId()).
/// @return Every live PID found in that container's cgroup, ascending. Empty if
///         the container has no live processes or the id is empty.
std::vector<pid_t> ResolvePidsForContainer(const std::string& container_id);

/// @brief Extract the CRI container id from a cgroup v2 unified path.
///
/// Exposed for unit testing; mirrors container_instances cgroup-id extraction
/// rules (cri-containerd-*.scope, crio-*.scope, docker-*.scope, and bare-hex
/// cgroupfs-driver leaves), always reading from the path LEAF so outer-Docker
/// wraps (kind/k3d) don't get masked.
std::string ExtractContainerIdFromCgroupPath(const std::string& cgroup_path);

} // namespace wazuh::container_baseline
