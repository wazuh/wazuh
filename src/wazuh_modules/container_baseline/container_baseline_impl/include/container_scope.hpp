#pragma once

#include <sys/types.h>

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace wazuh::container_baseline {

/// @brief Whether a namespace-scoped data class can actually be attributed to
/// the container, or whether the container shares the host's namespace so the
/// "container's" view is really the whole node's.
enum class ScopeKind
{
    Container,     ///< The container has its own namespace — rows are attributable.
    HostCollapsed, ///< Shares the host namespace (hostNetwork/hostPID, --network=host,
                   ///< --pid=host). The namespace view is the NODE's, not the container's.
    Unknown        ///< Could not determine (PID gone, /proc/<pid>/ns unreadable).
};

/// @brief A container's namespace scoping, resolved once per container per scan.
///
/// Why this exists: /proc/<pid>/net/* and getifaddrs() answer for whatever
/// network namespace the target PID sits in. When a container runs with
/// hostNetwork (K8s) or --network=host (Docker), that namespace IS the host's,
/// so a naive read reports every socket and every interface on the node as
/// belonging to that container — once per such container. Node-level
/// DaemonSets (CNI agents, node exporters, ingress controllers) run this way as
/// a matter of course, so the collapse is common, not exotic.
///
/// Detection is by namespace inode identity against the AGENT'S OWN namespace:
/// the agent ships as a host package (a stated constraint of this feature), so
/// its namespaces are the host's, and /proc/self is always readable — unlike
/// /proc/1/ns/*, which needs privilege over PID 1 and would make the check
/// silently degrade to Unknown for an unprivileged caller.
struct ContainerScope
{
    ScopeKind net{ScopeKind::Unknown};
    ScopeKind pid{ScopeKind::Unknown};

    /// @brief True when network-namespace-scoped rows (ports, interfaces,
    /// addresses, routes) must NOT be attributed to this container.
    [[nodiscard]] bool netCollapsedToHost() const noexcept { return net == ScopeKind::HostCollapsed; }
};

/// @brief Resolve `pid`'s namespace scoping relative to the host (PID 1).
///
/// @param pid A live PID inside the container.
/// @return Both fields Unknown if /proc/<pid>/ns or /proc/1/ns cannot be read.
[[nodiscard]] ContainerScope DetectContainerScope(pid_t pid);

/// @brief True when `pid` and `other` share the namespace named by `ns_name`
/// ("net", "pid", "mnt", ...), compared by namespace inode identity.
///
/// Exposed for unit testing.
[[nodiscard]] bool SharesNamespace(pid_t pid, pid_t other, const char* ns_name);

/// @brief Of the given containers, which ones share their network namespace
/// with at least one *other* container.
///
/// This is the Kubernetes pod case: containers in a pod share one netns, so
/// /proc/<pid>/net/* returns the same socket table for all of them. A scanner
/// that emits every socket it reads would therefore report each socket once per
/// container in the pod. Callers use this to restrict such containers to
/// sockets they can actually attribute to their own PIDs.
///
/// Costs one stat() per container (the representative PID's netns), not one per
/// PID, and is computed once per baseline run from the shared PID index.
///
/// @param pids_by_container Container id -> ascending PIDs (PidIndex::all()).
/// @return The subset of container ids whose netns is shared with another
///         container. Containers whose netns cannot be read are omitted.
[[nodiscard]] std::unordered_set<std::string>
SharedNetnsContainers(const std::unordered_map<std::string, std::vector<pid_t>>& pids_by_container);

} // namespace wazuh::container_baseline
