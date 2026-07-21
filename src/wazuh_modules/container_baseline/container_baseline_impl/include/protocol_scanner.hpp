#pragma once

#include "container_context.hpp"

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief The container's per-netns default route, mirroring the host
/// wazuh-states-inventory-protocols row (interface + gateway + metric). One row
/// per default route; the host equivalent is built from /proc/net/route the same
/// way (see data_provider NetworkLinuxInterface).
struct ProtocolBaselineRow
{
    std::string interface_name; ///< Route's outgoing interface (Iface column).
    std::string type;           ///< "ipv4".
    std::string gateway;        ///< Default gateway; empty for a gateway-less (0.0.0.0) route.
    std::string dhcp;           ///< "unknown" — a container rootfs rarely carries distro ifcfg files.
    int64_t     metric{0};      ///< Route metric.

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

/// @brief Decode a /proc/net/route hex gateway (the __be32 printed as
/// little-endian bytes, e.g. "010011AC" == 172.17.0.1) to a dotted IPv4 string.
/// Returns empty for the 0.0.0.0 (no-gateway) case. Exposed for unit testing.
[[nodiscard]] std::string DecodeRouteGateway(const std::string& hex_le);

/// @brief Parse one non-header /proc/net/route line into a row. Returns true
/// only for the default route (destination 0.0.0.0); other routes are skipped so
/// the row set matches the host's per-interface gateway view. Exposed for testing.
[[nodiscard]] bool ParseRouteLine(const std::string& line, ProtocolBaselineRow& row);

/// @brief Read the container netns' IPv4 routing table from /proc/<pid>/net/route
/// — a plain rootfs-relative text read (no setns, same as the ports scanner reads
/// /proc/<pid>/net/{tcp,udp}). Absent file / no default route = empty result.
[[nodiscard]] std::vector<ProtocolBaselineRow> ScanContainerProtocols(pid_t pid);

} // namespace wazuh::container_baseline
