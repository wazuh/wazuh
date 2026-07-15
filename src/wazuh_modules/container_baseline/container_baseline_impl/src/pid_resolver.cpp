#include "pid_resolver.hpp"

#include <dirent.h>

#include <cctype>
#include <fstream>
#include <regex>

namespace wazuh::container_baseline {

namespace {

bool IsAllDigits(const char* s) noexcept
{
    if (s == nullptr || *s == '\0') return false;
    for (; *s; ++s) {
        if (!std::isdigit(static_cast<unsigned char>(*s))) return false;
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

} // namespace

std::string ExtractContainerIdFromCgroupPath(const std::string& cgroup_path)
{
    const auto last_slash = cgroup_path.find_last_of('/');
    const std::string leaf =
        (last_slash == std::string::npos) ? cgroup_path : cgroup_path.substr(last_slash + 1);
    if (leaf.empty()) return {};

    static const std::regex re_scoped(
        R"(^(?:cri-containerd-|crio-|docker-)([0-9a-f]{12,128})\.scope$)");
    std::smatch m;
    if (std::regex_match(leaf, m, re_scoped) && m.size() >= 2) {
        return m[1].str();
    }

    static const std::regex re_leaf(R"(^([0-9a-f]{32,128})$)");
    if (std::regex_match(leaf, m, re_leaf) && m.size() >= 2) {
        return m[1].str();
    }

    return {};
}

std::vector<pid_t> ResolvePidsForContainer(const std::string& container_id)
{
    std::vector<pid_t> out;
    if (container_id.empty()) return out;

    DIR* d = ::opendir("/proc");
    if (d == nullptr) return out;

    while (auto* ent = ::readdir(d)) {
        if (!IsAllDigits(ent->d_name)) continue;
        const std::string pid_str = ent->d_name;

        const std::string cg_path = ReadProcCgroupV2Path(pid_str);
        if (cg_path.empty()) continue;

        if (ExtractContainerIdFromCgroupPath(cg_path) != container_id) continue;

        out.push_back(static_cast<pid_t>(std::stol(pid_str)));
    }

    ::closedir(d);
    return out;
}

} // namespace wazuh::container_baseline
