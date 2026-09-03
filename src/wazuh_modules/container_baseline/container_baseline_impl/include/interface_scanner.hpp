#pragma once

#include "container_context.hpp"
#include "container_scope.hpp"

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

    /// True when the scan produced nothing because the container shares the
    /// host's network namespace — the interfaces visible there are the NODE's,
    /// not this container's, so attributing them would be false.
    bool host_collapsed{false};

    /// True when entering the container's netns failed (typically a missing
    /// CAP_SYS_ADMIN). Distinguishes "no interfaces" from "could not look",
    /// which the caller must log rather than silently reporting an empty set.
    bool setns_failed{false};
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
/// moves), then plain getifaddrs() + SIOCGIFMTU inside.
///
/// DOCUMENTED EXCEPTION to the feature-wide "no in-container execution"
/// constraint (#37203-4): setns(CLONE_NEWNET) is what `nsenter --net` does.
/// It is accepted here because it is strictly weaker than in-container exec —
/// it enters ONLY the network namespace, executes no code inside the container,
/// and requires nothing to be present in the image, so distroless is
/// unaffected — and because no host-side alternative yields MAC, MTU and bound
/// addresses (/proc/<pid>/net/dev gives names and counters only). It must never
/// be extended to CLONE_NEWNS or CLONE_NEWPID without going back for review.
/// It requires CAP_SYS_ADMIN; when that is absent the result reports
/// `setns_failed` so the caller can log it instead of silently reporting no
/// interfaces.
///
/// @param pid A live PID inside the container.
/// @param scope Namespace scoping (DetectContainerScope()). When the network
///              namespace is the host's, this returns an empty scan flagged
///              `host_collapsed` rather than reporting the node's interfaces as
///              the container's.
[[nodiscard]] InterfaceScan ScanContainerInterfaces(pid_t pid, const ContainerScope& scope);

} // namespace wazuh::container_baseline
