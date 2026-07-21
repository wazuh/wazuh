#pragma once

#include "container_context.hpp"

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief One network interface inside the container's own network namespace.
/// Field names mirror syscollector's dbsync_network_iface columns, minus the
/// host-only adapter/gateway notions.
struct InterfaceBaselineRow
{
    std::string name;
    std::string mac;   ///< Empty for interfaces without link-layer address.
    int64_t     mtu{0};
    std::string state; ///< "up" / "down" (IFF_UP).
    std::string type;  ///< "loopback" / "ethernet".
    uint64_t    rx_bytes{0};
    uint64_t    rx_packets{0};
    uint64_t    rx_errors{0};
    uint64_t    rx_dropped{0};
    uint64_t    tx_bytes{0};
    uint64_t    tx_packets{0};
    uint64_t    tx_errors{0};
    uint64_t    tx_dropped{0};

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

/// @brief One IP address bound inside the container's network namespace.
/// Mirrors dbsync_network_address (iface, proto, address, netmask, broadcast).
struct NetworkAddressBaselineRow
{
    std::string interface_name;
    std::string protocol; ///< "ipv4" / "ipv6".
    std::string address;
    std::string netmask;
    std::string broadcast; ///< Empty when the interface has none (lo, v6).

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

struct InterfaceScan
{
    std::vector<InterfaceBaselineRow>      interfaces;
    std::vector<NetworkAddressBaselineRow> addresses;
};

/// @brief Map getifaddrs() ifa_flags to the state string. Exposed for unit
/// testing.
[[nodiscard]] std::string FlagsToState(unsigned int flags);

/// @brief Render a link-layer address as colon-separated lowercase hex.
/// Exposed for unit testing.
[[nodiscard]] std::string FormatMac(const unsigned char* bytes, size_t len);

/// @brief Baseline the interfaces and bound addresses of the network namespace
/// a live container PID sits in.
///
/// The ports scanner reads /proc/<pid>/net/* text files, but interface MAC/MTU
/// and bound addresses have no such rootfs-relative view — sysfs and netlink
/// both answer for the *caller's* netns. So this scanner enters the target
/// netns the way `ip netns exec` does: setns(/proc/<pid>/ns/net, CLONE_NEWNET)
/// on a throw-away thread (netns is per-thread; the calling thread never
/// moves), then plain getifaddrs() + SIOCGIFMTU inside. When the target netns
/// is the caller's own (host-network container, or a unit test on itself) the
/// setns hop is skipped entirely, so no privilege is needed for that path.
///
/// @return Empty scan if /proc/<pid>/ns/net cannot be opened or entered
///         (PID died, or missing CAP_SYS_ADMIN) — empty result, not an error.
[[nodiscard]] InterfaceScan ScanContainerInterfaces(pid_t pid);

} // namespace wazuh::container_baseline
