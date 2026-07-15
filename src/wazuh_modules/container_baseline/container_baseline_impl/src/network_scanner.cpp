#include "network_scanner.hpp"

#include "pid_resolver.hpp"

#include <arpa/inet.h>
#include <dirent.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unordered_map>

namespace wazuh::container_baseline {

namespace {

struct OwnerInfo
{
    pid_t       pid{0};
    std::string name;
};

std::string ReadComm(pid_t pid)
{
    std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
    std::string   line;
    if (f && std::getline(f, line)) return line;
    return {};
}

// Build inode -> owning (pid, comm) for every socket fd across every PID in the
// container. /proc/<pid>/fd/<n> is a symlink whose target is "socket:[<inode>]"
// for socket descriptors.
std::unordered_map<uint64_t, OwnerInfo> BuildInodeOwnerMap(const std::vector<pid_t>& pids)
{
    std::unordered_map<uint64_t, OwnerInfo> owners;

    for (const auto pid : pids) {
        const std::string fd_dir = "/proc/" + std::to_string(pid) + "/fd";
        DIR* d = ::opendir(fd_dir.c_str());
        if (d == nullptr) continue;

        std::string comm; // lazily resolved once per pid that actually owns a socket
        bool        comm_read = false;

        while (auto* ent = ::readdir(d)) {
            const std::string name = ent->d_name;
            if (name == "." || name == "..") continue;

            char    link_target[256];
            const std::string fd_path = fd_dir + "/" + name;
            const ssize_t n = ::readlink(fd_path.c_str(), link_target, sizeof(link_target) - 1);
            if (n <= 0) continue;
            link_target[n] = '\0';

            uint64_t inode = 0;
            if (std::sscanf(link_target, "socket:[%lu]", &inode) != 1) continue;

            if (!comm_read) {
                comm      = ReadComm(pid);
                comm_read = true;
            }
            owners[inode] = OwnerInfo{pid, comm};
        }
        ::closedir(d);
    }

    return owners;
}

void ParseNetFile(const std::string&               path,
                   const std::string&               transport,
                   bool                              is_ipv6,
                   const std::unordered_map<uint64_t, OwnerInfo>& owners,
                   std::vector<PortBaselineRow>&    out)
{
    std::ifstream f(path);
    if (!f) return;

    std::string line;
    std::getline(f, line); // header

    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::vector<std::string> fields;
        std::string tok;
        while (iss >> tok) fields.push_back(tok);
        // sl local_address rem_address st tx:rx tr:tm retrnsmt uid timeout inode ...
        if (fields.size() < 10) continue;

        PortBaselineRow row;
        row.network_transport = transport;

        if (!DecodeHexAddress(fields[1], is_ipv6, row.source_ip, row.source_port)) continue;
        if (!DecodeHexAddress(fields[2], is_ipv6, row.destination_ip, row.destination_port)) continue;

        row.interface_state = TcpStateToString(fields[3]);
        row.file_inode       = std::strtoull(fields[9].c_str(), nullptr, 10);

        if (const auto it = owners.find(row.file_inode); it != owners.end()) {
            row.process_pid  = it->second.pid;
            row.process_name = it->second.name;
        }

        out.push_back(std::move(row));
    }
}

} // namespace

bool DecodeHexAddress(const std::string& hex_addr_port, bool is_ipv6, std::string& ip_out, int64_t& port_out)
{
    const auto colon = hex_addr_port.find(':');
    if (colon == std::string::npos) return false;

    const std::string hex_addr = hex_addr_port.substr(0, colon);
    const std::string hex_port = hex_addr_port.substr(colon + 1);
    if (hex_port.empty()) return false;

    port_out = std::strtol(hex_port.c_str(), nullptr, 16);

    if (!is_ipv6) {
        if (hex_addr.size() != 8) return false;
        const auto addr = static_cast<uint32_t>(std::strtoul(hex_addr.c_str(), nullptr, 16));
        unsigned char bytes[4] = {
            static_cast<unsigned char>(addr & 0xFF),
            static_cast<unsigned char>((addr >> 8) & 0xFF),
            static_cast<unsigned char>((addr >> 16) & 0xFF),
            static_cast<unsigned char>((addr >> 24) & 0xFF),
        };
        char buf[INET_ADDRSTRLEN];
        if (::inet_ntop(AF_INET, bytes, buf, sizeof(buf)) == nullptr) return false;
        ip_out = buf;
        return true;
    }

    if (hex_addr.size() != 32) return false;
    unsigned char bytes[16];
    for (int word = 0; word < 4; ++word) {
        const auto chunk = static_cast<uint32_t>(
            std::strtoul(hex_addr.substr(static_cast<size_t>(word) * 8, 8).c_str(), nullptr, 16));
        bytes[word * 4 + 0] = static_cast<unsigned char>(chunk & 0xFF);
        bytes[word * 4 + 1] = static_cast<unsigned char>((chunk >> 8) & 0xFF);
        bytes[word * 4 + 2] = static_cast<unsigned char>((chunk >> 16) & 0xFF);
        bytes[word * 4 + 3] = static_cast<unsigned char>((chunk >> 24) & 0xFF);
    }
    char buf[INET6_ADDRSTRLEN];
    if (::inet_ntop(AF_INET6, bytes, buf, sizeof(buf)) == nullptr) return false;
    ip_out = buf;
    return true;
}

std::string TcpStateToString(const std::string& hex_state)
{
    const auto st = std::strtol(hex_state.c_str(), nullptr, 16);
    switch (st) {
        case 0x01: return "established";
        case 0x02: return "syn_sent";
        case 0x03: return "syn_recv";
        case 0x04: return "fin_wait1";
        case 0x05: return "fin_wait2";
        case 0x06: return "time_wait";
        case 0x07: return "close";
        case 0x08: return "close_wait";
        case 0x09: return "last_ack";
        case 0x0A: return "listen";
        case 0x0B: return "closing";
        default:   return "unknown";
    }
}

std::vector<PortBaselineRow> ScanContainerNetwork(const std::string& container_id)
{
    std::vector<PortBaselineRow> rows;
    if (container_id.empty()) return rows;

    const auto pids = ResolvePidsForContainer(container_id);
    if (pids.empty()) return rows;

    const auto owners = BuildInodeOwnerMap(pids);

    // Any PID in the container sees the same net namespace (Docker: one per
    // container; Kubernetes: shared across the pod but disambiguated here by
    // only ever reading files under a PID we've already confirmed belongs to
    // this container's cgroup).
    const auto representative = pids.front();
    const std::string net_dir = "/proc/" + std::to_string(representative) + "/net";

    ParseNetFile(net_dir + "/tcp",  "tcp",  false, owners, rows);
    ParseNetFile(net_dir + "/tcp6", "tcp6", true,  owners, rows);
    ParseNetFile(net_dir + "/udp",  "udp",  false, owners, rows);
    ParseNetFile(net_dir + "/udp6", "udp6", true,  owners, rows);

    for (auto& row : rows) row.container_id = container_id;
    return rows;
}

} // namespace wazuh::container_baseline
