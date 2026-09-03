#include "pid_resolver.hpp"

#include <dirent.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <string_view>

namespace wazuh::container_baseline {

namespace {

const std::vector<pid_t> kNoPids{};

bool IsAllDigits(const char* s) noexcept
{
    if (s == nullptr || *s == '\0') return false;
    for (; *s; ++s) {
        if (!std::isdigit(static_cast<unsigned char>(*s))) return false;
    }
    return true;
}

// True if every character is a lowercase hex digit and the length is within
// [min_len, max_len]. Replaces the previous std::regex match, which ran twice
// per PID per sweep — measurable at thousands of PIDs and needless for a
// pattern this simple.
bool IsHexId(std::string_view s, std::size_t min_len, std::size_t max_len) noexcept
{
    if (s.size() < min_len || s.size() > max_len) return false;
    for (const char c : s) {
        const bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!is_hex) return false;
    }
    return true;
}

std::string ReadProcCgroupV2Path(const std::string& pid)
{
    std::ifstream f("/proc/" + pid + "/cgroup");
    if (!f) return {};

    std::string line;
    while (std::getline(f, line)) {
        if (line.size() >= 3 && line[0] == '0' && line[1] == ':' && line[2] == ':') {
            return line.substr(3);
        }
    }
    return {};
}

// Invokes `visit(container_id, pid)` once for every PID on the host whose cgroup
// leaf identifies a container. The single /proc sweep both PidIndex::Build() and
// ResolvePidsForContainer() are built on.
template <typename Visitor>
void SweepProc(Visitor&& visit)
{
    DIR* d = ::opendir("/proc");
    if (d == nullptr) return;

    while (auto* ent = ::readdir(d)) {
        if (!IsAllDigits(ent->d_name)) continue;
        const std::string pid_str = ent->d_name;

        const std::string cg_path = ReadProcCgroupV2Path(pid_str);
        if (cg_path.empty()) continue;

        auto container_id = ExtractContainerIdFromCgroupPath(cg_path);
        if (container_id.empty()) continue;

        // pid_str is all digits and /proc pids fit comfortably in a long, so
        // this cannot throw.
        visit(std::move(container_id), static_cast<pid_t>(std::stol(pid_str)));
    }

    ::closedir(d);
}

} // namespace

std::string ExtractContainerIdFromCgroupPath(const std::string& cgroup_path)
{
    const auto last_slash = cgroup_path.find_last_of('/');
    std::string_view leaf =
        (last_slash == std::string::npos) ? std::string_view{cgroup_path}
                                          : std::string_view{cgroup_path}.substr(last_slash + 1);
    if (leaf.empty()) return {};

    // systemd cgroup driver: "<runtime-prefix><hex-id>.scope".
    constexpr std::string_view kScopeSuffix{".scope"};
    if (leaf.size() > kScopeSuffix.size() &&
        leaf.compare(leaf.size() - kScopeSuffix.size(), kScopeSuffix.size(), kScopeSuffix) == 0) {
        const auto body = leaf.substr(0, leaf.size() - kScopeSuffix.size());

        for (const std::string_view prefix : {std::string_view{"cri-containerd-"},
                                              std::string_view{"crio-"},
                                              std::string_view{"docker-"}}) {
            if (body.size() > prefix.size() && body.compare(0, prefix.size(), prefix) == 0) {
                const auto id = body.substr(prefix.size());
                if (IsHexId(id, 12, 128)) return std::string{id};
                return {};
            }
        }
        return {};
    }

    // cgroupfs driver: the leaf is the bare container id.
    if (IsHexId(leaf, 32, 128)) return std::string{leaf};

    return {};
}

PidIndex PidIndex::Build()
{
    PidIndex index;

    SweepProc([&index](std::string container_id, pid_t pid) {
        index.m_byContainer[std::move(container_id)].push_back(pid);
        ++index.m_processCount;
    });

    // Ascending order makes pidsFor().front() the lowest PID in the container —
    // the best available proxy for "the entrypoint", and far more stable than
    // whatever order readdir() happened to return.
    for (auto& [id, pids] : index.m_byContainer) {
        std::sort(pids.begin(), pids.end());
    }

    return index;
}

const std::vector<pid_t>& PidIndex::pidsFor(const std::string& container_id) const
{
    if (container_id.empty()) return kNoPids;

    const auto it = m_byContainer.find(container_id);
    return (it != m_byContainer.end()) ? it->second : kNoPids;
}

std::vector<pid_t> ResolvePidsForContainer(const std::string& container_id)
{
    std::vector<pid_t> out;
    if (container_id.empty()) return out;

    SweepProc([&out, &container_id](const std::string& id, pid_t pid) {
        if (id == container_id) out.push_back(pid);
    });

    std::sort(out.begin(), out.end());
    return out;
}

} // namespace wazuh::container_baseline
