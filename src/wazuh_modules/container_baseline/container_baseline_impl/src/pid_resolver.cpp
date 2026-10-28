#include "pid_resolver.hpp"

#include "cgroup_host_mode.h"

#include <dirent.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
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

// Reads /proc/<pid>/cgroup and hands the whole thing to the pure selector,
// which is where the v1/v2 decision lives (and where it is tested).
std::string ReadProcCgroupPath(const std::string& pid)
{
    std::ifstream f("/proc/" + pid + "/cgroup");
    if (!f) return {};

    std::string contents((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return SelectCgroupPathFromProcCgroup(contents);
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

        const std::string cg_path = ReadProcCgroupPath(pid_str);
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

namespace {

/// Matches ONE cgroup path component. Split out of
/// ExtractContainerIdFromCgroupPath() so the path can be scanned component by
/// component; the rules themselves are unchanged.
std::string MatchContainerIdComponent(std::string_view leaf)
{
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

} // namespace

std::string SelectCgroupPathFromProcCgroup(const std::string& proc_cgroup_contents)
{
    std::string unified;
    std::string best_numbered;
    int best_rank = WZ_CGROUP_V1_PRIORITY_COUNT; // Lower is better; this means "none yet".

    std::istringstream stream(proc_cgroup_contents);
    std::string line;
    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == '\r') line.pop_back();

        if (line.size() >= 3 && line[0] == '0' && line[1] == ':' && line[2] == ':')
        {
            unified = line.substr(3);
            continue;
        }

        // "<hierarchy-id>:<controllers>:<path>". An empty controller field is
        // what the unified line looks like and is handled above.
        const auto first = line.find(':');
        if (first == std::string::npos) continue;
        const auto second = line.find(':', first + 1);
        if (second == std::string::npos || second <= first + 1) continue;

        const std::string controllers = line.substr(first + 1, second - first - 1);
        const std::string path = line.substr(second + 1);

        // Rank by the SHARED priority order, so this agrees with the hierarchy
        // the resolver keys on and the eBPF program reads. A controller outside
        // that list is still usable -- every v1 line carries the same container
        // path -- but only as a last resort.
        int rank = WZ_CGROUP_V1_PRIORITY_COUNT;
        for (unsigned int i = 0; i < WZ_CGROUP_V1_PRIORITY_COUNT; ++i)
        {
            const char* wanted = wz_cgroup_v1_priority(i);
            if (wanted == nullptr) break;

            // Whole comma-separated element, so "cpu" does not match "cpuacct";
            // a "name=" prefix is part of the element, as in "1:name=systemd:".
            std::string_view rest{controllers};
            while (!rest.empty())
            {
                const auto comma = rest.find(',');
                const auto element = rest.substr(0, comma);
                const auto bare = element.rfind("name=", 0) == 0 ? element.substr(5) : element;
                if (bare == wanted)
                {
                    rank = static_cast<int>(i);
                    break;
                }
                if (comma == std::string_view::npos) break;
                rest.remove_prefix(comma + 1);
            }
            if (rank != WZ_CGROUP_V1_PRIORITY_COUNT) break;
        }

        // First line seen wins until something better-ranked turns up, so the
        // choice does not depend on the order the kernel happens to print.
        if (best_numbered.empty() || rank < best_rank)
        {
            best_rank = rank;
            best_numbered = path;
        }
    }

    // The unified line only wins when it NAMES something. A legacy host may
    // emit `0::/`, which identifies nothing: taking it regardless is what left
    // the baseline reporting zero containers scanned while the connector
    // reported one known.
    if (!unified.empty() && unified != "/") return unified;
    if (!best_numbered.empty()) return best_numbered;
    return unified; // "/" or nothing: let the caller's id extraction reject it.
}

std::string ExtractContainerIdFromCgroupPath(const std::string& cgroup_path)
{
    // Scan components INNERMOST FIRST, stopping at the first match. A matching
    // leaf still wins, so an outer-Docker wrap (kind/k3d) still cannot mask the
    // inner container; this only adds a result where the leaf alone gave none —
    // notably a container whose PID 1 is an init system, which places every
    // process in a CHILD cgroup of the container's own. Mirrors
    // container_instances' extractContainerId(); the two must agree.
    std::size_t end = cgroup_path.size();

    while (end > 0) {
        if (cgroup_path[end - 1] == '/') {
            --end;
            continue;
        }

        const auto slash = cgroup_path.find_last_of('/', end - 1);
        const std::size_t begin = (slash == std::string::npos) ? 0U : slash + 1U;

        auto id = MatchContainerIdComponent(
            std::string_view{cgroup_path}.substr(begin, end - begin));
        if (!id.empty()) return id;

        if (begin == 0U) break;
        end = begin - 1U;
    }

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

PidIndex PidIndex::FromMap(std::unordered_map<std::string, std::vector<pid_t>> byContainer)
{
    PidIndex index;
    index.m_byContainer = std::move(byContainer);

    for (auto& [id, pids] : index.m_byContainer) {
        std::sort(pids.begin(), pids.end());
        index.m_processCount += pids.size();
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
