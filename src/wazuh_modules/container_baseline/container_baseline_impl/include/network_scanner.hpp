#pragma once

#include "container_context.hpp"

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

/// @brief Baseline the container's network namespace: listening/established
/// sockets read from /proc/<pid>/net/{tcp,tcp6,udp,udp6} for one representative
/// PID in the container, with each socket attributed to its owning PID/process
/// name via an inode -> (pid, comm) map built from /proc/<pid>/fd/ across every
/// PID in the container (a Kubernetes pod's containers share one net namespace,
/// so the representative-PID choice only affects *which* socket table is read,
/// not which processes can own a given socket).
///
/// @param container_id CRI container id.
/// @return Empty if the container has no live PIDs, or its net/ files could not
///         be read (e.g. permission denied — see CgroupResolver's hostPID note).
std::vector<PortBaselineRow> ScanContainerNetwork(const std::string& container_id);

/// @brief Decode a /proc/net/{tcp,udp} "AABBCCDD:PPPP" hex address into a
/// dotted-decimal (or colon-hex for v6) address string and a host-order port.
/// Exposed for unit testing.
bool DecodeHexAddress(const std::string& hex_addr_port, bool is_ipv6, std::string& ip_out, int64_t& port_out);

/// @brief Map a /proc/net TCP `st` hex byte to a human-readable socket state.
/// Exposed for unit testing.
std::string TcpStateToString(const std::string& hex_state);

} // namespace wazuh::container_baseline
