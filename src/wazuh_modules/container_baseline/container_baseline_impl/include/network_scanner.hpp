#pragma once

#include "container_context.hpp"
#include "container_scope.hpp"

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief One socket baseline row. Field names mirror syscollector's
/// PORTS_SQL_STATEMENT (dbsync_ports) column-for-column, plus container context.
struct PortBaselineRow
{
    std::string network_transport;  ///< "tcp", "tcp6", "udp", "udp6".
    std::string source_ip;
    int64_t     source_port{0};
    std::string destination_ip;
    int64_t     destination_port{0};
    std::string interface_state;    ///< e.g. "listen", "established".
    int64_t     process_pid{0};     ///< 0 if the owning process could not be attributed.
    std::string process_name;
    uint64_t    file_inode{0};

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

/// @brief Baseline the container's sockets from /proc/<pid>/net/{tcp,tcp6,udp,udp6},
/// attributing each to its owning PID via an inode -> (pid, comm) map built from
/// /proc/<pid>/fd/ across the container's PIDs.
///
/// Two scoping rules this function enforces, both of which a naive read gets
/// wrong:
///
///  1. **Host-network collapse.** With hostNetwork (K8s) or --network=host
///     (Docker), /proc/<pid>/net/* IS the host's socket table. Attributing it
///     to the container would report every socket on the node as the
///     container's, once per such container. When `scope.netCollapsedToHost()`
///     this returns empty.
///
///  2. **Pod-shared network namespace.** Containers in a Kubernetes pod share
///     one netns, so the socket table is identical for all of them. Reading it
///     "through" a container-owned PID does not disambiguate anything — the
///     file's contents are namespace-wide. When `netns_shared` is true, only
///     sockets whose inode resolves to a PID in THIS container are emitted, so
///     an N-container pod no longer reports each socket N times. When the netns
///     is exclusive to this container (the Docker default), unattributed
///     sockets are still emitted, since they can only belong here.
///
/// @param container_id CRI container id, stamped onto every row.
/// @param pids Live PIDs of this container (from PidIndex::pidsFor()).
/// @param scope Namespace scoping for this container (DetectContainerScope()).
/// @param netns_shared True when another container shares this network namespace.
/// @return Empty if the container has no live PIDs, the net/ files are
///         unreadable, or the network namespace is the host's.
std::vector<PortBaselineRow> ScanContainerNetwork(const std::string&        container_id,
                                                   const std::vector<pid_t>& pids,
                                                   const ContainerScope&     scope,
                                                   bool                      netns_shared);

/// @brief Decode a /proc/net/{tcp,udp} "AABBCCDD:PPPP" hex address into a
/// dotted-decimal (or colon-hex for v6) address string and a host-order port.
/// Exposed for unit testing.
bool DecodeHexAddress(const std::string& hex_addr_port, bool is_ipv6, std::string& ip_out, int64_t& port_out);

/// @brief Map a /proc/net TCP `st` hex byte to a human-readable socket state.
/// Exposed for unit testing.
std::string TcpStateToString(const std::string& hex_state);

} // namespace wazuh::container_baseline
