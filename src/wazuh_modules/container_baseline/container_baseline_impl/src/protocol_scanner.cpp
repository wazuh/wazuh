#include "protocol_scanner.hpp"

#include <arpa/inet.h>

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace wazuh::container_baseline {

namespace {

// /proc/net/route column order (see the kernel's rt_cache/fib seq_show).
enum RouteField
{
    kIface       = 0,
    kDestination = 1,
    kGateway     = 2,
    kMetric      = 6,
    kMask        = 7,
};

} // namespace

std::string DecodeRouteGateway(const std::string& hex_le)
{
    // The field is the gateway __be32 printed as host-order hex of its
    // little-endian bytes, so strtoul yields the in_addr.s_addr directly on a
    // little-endian host — the same decode the ports scanner uses for addresses.
    const auto raw = static_cast<uint32_t>(std::strtoul(hex_le.c_str(), nullptr, 16));
    if (raw == 0) return {}; // 0.0.0.0 — no gateway (e.g. a link-scoped default).

    struct in_addr addr;
    addr.s_addr = raw;
    char buf[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf))) return {};
    return buf;
}

bool ParseRouteLine(const std::string& line, ProtocolBaselineRow& row)
{
    std::istringstream iss(line);
    std::vector<std::string> f;
    std::string tok;
    while (iss >> tok) f.push_back(tok);
    if (f.size() <= kMask) return false;

    // Default route only: destination 0.0.0.0 (hex "00000000").
    if (std::strtoul(f[kDestination].c_str(), nullptr, 16) != 0) return false;

    row.interface_name = f[kIface];
    row.type           = "ipv4";
    row.gateway        = DecodeRouteGateway(f[kGateway]);
    row.metric         = std::strtol(f[kMetric].c_str(), nullptr, 10);
    row.dhcp           = "unknown";
    return true;
}

std::vector<ProtocolBaselineRow> ScanContainerProtocols(pid_t pid)
{
    std::vector<ProtocolBaselineRow> out;

    // ponytail: IPv4 only. IPv6 default routes live in /proc/<pid>/net/ipv6_route
    // with a different layout, and the host reader itself leaves the IPv6 metric
    // empty — add a v6 branch here if v6-only containers need coverage.
    std::ifstream file{"/proc/" + std::to_string(pid) + "/net/route"};
    if (!file) return out;

    std::string line;
    std::getline(file, line); // header
    while (std::getline(file, line))
    {
        ProtocolBaselineRow row;
        if (ParseRouteLine(line, row)) out.push_back(std::move(row));
    }
    return out;
}

} // namespace wazuh::container_baseline
