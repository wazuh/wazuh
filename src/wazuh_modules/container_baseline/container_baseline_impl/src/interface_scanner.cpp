#include "interface_scanner.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sched.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <map>
#include <thread>

namespace wazuh::container_baseline {

namespace {

std::string AddressToString(const struct sockaddr* sa)
{
    char buf[INET6_ADDRSTRLEN] = {0};
    if (!sa) return {};

    if (sa->sa_family == AF_INET)
    {
        const auto* v4 = reinterpret_cast<const struct sockaddr_in*>(sa);
        if (!inet_ntop(AF_INET, &v4->sin_addr, buf, sizeof(buf))) return {};
    }
    else if (sa->sa_family == AF_INET6)
    {
        const auto* v6 = reinterpret_cast<const struct sockaddr_in6*>(sa);
        if (!inet_ntop(AF_INET6, &v6->sin6_addr, buf, sizeof(buf))) return {};
    }
    return buf;
}

int64_t QueryMtu(const char* if_name)
{
    const int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return 0;

    struct ifreq req;
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, if_name, IFNAMSIZ - 1);
    const int64_t mtu = (ioctl(sock, SIOCGIFMTU, &req) == 0) ? req.ifr_mtu : 0;
    close(sock);
    return mtu;
}

/// Walk the *calling thread's* current netns with getifaddrs(). Runs either
/// directly (same-netns fast path) or on the setns'd throw-away thread.
InterfaceScan CollectCurrentNetns()
{
    InterfaceScan out;

    struct ifaddrs* ifap = nullptr;
    if (getifaddrs(&ifap) != 0) return out;

    std::map<std::string, InterfaceBaselineRow> ifaces; // one row per name across the AF_* entries.

    for (const auto* ifa = ifap; ifa; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_name) continue;
        const std::string name = ifa->ifa_name;

        auto& row = ifaces[name];
        if (row.name.empty())
        {
            row.name  = name;
            row.state = FlagsToState(ifa->ifa_flags);
            row.type  = (ifa->ifa_flags & IFF_LOOPBACK) ? "loopback" : "ethernet";
            row.mtu   = QueryMtu(ifa->ifa_name);
        }

        const int family = ifa->ifa_addr ? ifa->ifa_addr->sa_family : AF_UNSPEC;

        if (family == AF_PACKET)
        {
            const auto* ll = reinterpret_cast<const struct sockaddr_ll*>(ifa->ifa_addr);
            if (ll->sll_halen > 0) row.mac = FormatMac(ll->sll_addr, ll->sll_halen);

            if (const auto* stats = static_cast<const struct rtnl_link_stats*>(ifa->ifa_data))
            {
                row.rx_bytes   = stats->rx_bytes;
                row.rx_packets = stats->rx_packets;
                row.rx_errors  = stats->rx_errors;
                row.rx_dropped = stats->rx_dropped;
                row.tx_bytes   = stats->tx_bytes;
                row.tx_packets = stats->tx_packets;
                row.tx_errors  = stats->tx_errors;
                row.tx_dropped = stats->tx_dropped;
            }
        }
        else if (family == AF_INET || family == AF_INET6)
        {
            NetworkAddressBaselineRow addr;
            addr.interface_name = name;
            addr.protocol       = (family == AF_INET) ? "ipv4" : "ipv6";
            addr.address        = AddressToString(ifa->ifa_addr);
            addr.netmask        = AddressToString(ifa->ifa_netmask);
            if (ifa->ifa_flags & IFF_BROADCAST) addr.broadcast = AddressToString(ifa->ifa_broadaddr);
            if (!addr.address.empty()) out.addresses.push_back(std::move(addr));
        }
    }
    freeifaddrs(ifap);

    out.interfaces.reserve(ifaces.size());
    for (auto& [name, row] : ifaces) out.interfaces.push_back(std::move(row));
    return out;
}

bool SameNetns(pid_t pid)
{
    struct stat self_st, target_st;
    if (stat("/proc/self/ns/net", &self_st) != 0) return false;
    if (stat(("/proc/" + std::to_string(pid) + "/ns/net").c_str(), &target_st) != 0) return false;
    return self_st.st_ino == target_st.st_ino && self_st.st_dev == target_st.st_dev;
}

} // namespace

std::string FlagsToState(unsigned int flags)
{
    return (flags & IFF_UP) ? "up" : "down";
}

std::string FormatMac(const unsigned char* bytes, size_t len)
{
    std::string out;
    char hex[4];
    for (size_t i = 0; i < len; ++i)
    {
        snprintf(hex, sizeof(hex), "%02x", bytes[i]);
        if (i) out.push_back(':');
        out += hex;
    }
    return out;
}

InterfaceScan ScanContainerInterfaces(pid_t pid)
{
    if (SameNetns(pid)) return CollectCurrentNetns(); // host-network container / self-test: no setns needed.

    const int ns_fd = open(("/proc/" + std::to_string(pid) + "/ns/net").c_str(), O_RDONLY | O_CLOEXEC);
    if (ns_fd < 0) return {};

    // setns(CLONE_NEWNET) moves only the calling thread, so a joined
    // throw-away thread leaves the rest of the process untouched — no
    // restore step, the thread just exits inside the container netns.
    InterfaceScan result;
    std::thread worker([&]
    {
        if (setns(ns_fd, CLONE_NEWNET) == 0) result = CollectCurrentNetns();
    });
    worker.join();
    close(ns_fd);
    return result;
}

} // namespace wazuh::container_baseline
