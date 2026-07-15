#include "cgroup_resolver.hpp"

#include <dirent.h>
#include <sys/stat.h>

#include <cctype>
#include <fstream>
#include <regex>
#include <string>
#include <unordered_map>

namespace wazuh::container_connector {

namespace {

constexpr const char* kCgroupfsRoot = "/sys/fs/cgroup";

/// Returns true if every byte of the null-terminated string is an ASCII digit.
bool IsAllDigits(const char* s) noexcept
{
    if (s == nullptr || *s == '\0') return false;
    for (; *s; ++s) {
        if (!std::isdigit(static_cast<unsigned char>(*s))) return false;
    }
    return true;
}

/// Read /proc/<pid>/cgroup and return the cgroup v2 unified path (the text
/// that follows "0::"). Empty string if the file cannot be read or there is
/// no v2 entry.
std::string ReadProcCgroupV2Path(const std::string& pid)
{
    std::ifstream f("/proc/" + pid + "/cgroup");
    if (!f) return {};

    std::string line;
    while (std::getline(f, line)) {
        // cgroup v2 unified line shape: "0::<path>".
        if (line.size() >= 3 && line[0] == '0' && line[1] == ':' && line[2] == ':') {
            return line.substr(3);
        }
    }
    return {};
}

/// Extract the CRI container id from a cgroup path. The id is always read
/// from the LEAF of the path (last segment), never from intermediate
/// segments — outer-Docker wraps (kind / k3d / minikube docker driver)
/// have a docker-*.scope segment in the middle of the path that would
/// otherwise mask the real container id below it.
///
/// Recognised leaf forms:
///   cri-containerd-<hex>.scope     (containerd, systemd driver)
///   crio-<hex>.scope               (CRI-O,      systemd driver)
///   docker-<hex>.scope             (docker via cri-dockerd)
///   <hex>                          (cgroupfs driver, hex 32-128 chars)
///
/// Returns an empty string if the leaf does not match any recognised form
/// (e.g. system slices, kubelet itself, host processes outside any container).
std::string ExtractCriId(const std::string& cgroup_path)
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

    // cgroupfs driver: the leaf is bare hex.
    static const std::regex re_leaf(R"(^([0-9a-f]{32,128})$)");
    if (std::regex_match(leaf, m, re_leaf) && m.size() >= 2) {
        return m[1].str();
    }

    return {};
}

} // namespace

std::unordered_map<std::string, uint64_t> BuildCgroupIdMap()
{
    std::unordered_map<std::string, uint64_t> result;

    DIR* d = ::opendir("/proc");
    if (d == nullptr) {
        return result;
    }

    while (auto* ent = ::readdir(d)) {
        if (!IsAllDigits(ent->d_name)) continue;
        const std::string pid = ent->d_name;

        const std::string cg_path = ReadProcCgroupV2Path(pid);
        if (cg_path.empty()) continue;

        const std::string cid = ExtractCriId(cg_path);
        if (cid.empty()) continue;

        // Skip if we already have a mapping for this container; one valid
        // sample is enough and reduces redundant stat() calls.
        if (result.find(cid) != result.end()) continue;

        struct stat st{};
        const std::string fs_path = std::string{kCgroupfsRoot} + cg_path;
        if (::stat(fs_path.c_str(), &st) != 0) continue;

        result.emplace(cid, static_cast<uint64_t>(st.st_ino));
    }

    ::closedir(d);
    return result;
}

uint64_t ResolveCgroupId(const std::string& /*pod_uid*/, const std::string& container_id)
{
    if (container_id.empty()) return 0;
    const auto m = BuildCgroupIdMap();
    const auto it = m.find(container_id);
    return (it == m.end()) ? 0 : it->second;
}

} // namespace wazuh::container_connector
