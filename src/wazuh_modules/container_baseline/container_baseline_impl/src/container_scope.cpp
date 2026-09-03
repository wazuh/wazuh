#include "container_scope.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <string>

namespace wazuh::container_baseline {

namespace {

// A namespace is identified by the (dev, ino) pair of /proc/<pid>/ns/<name>.
// Two PIDs in the same namespace stat to the same pair.
bool NamespaceId(pid_t pid, const char* ns_name, struct stat& out)
{
    const std::string path = "/proc/" + std::to_string(pid) + "/ns/" + ns_name;
    return ::stat(path.c_str(), &out) == 0;
}

// The host's namespace is taken to be the AGENT'S OWN namespace, read through
// /proc/self, rather than PID 1's.
//
// Two reasons. Semantically they are the same thing: the agent ships as a host
// package (systemd), which is a stated constraint of this feature, so the
// agent already sits in the host's namespaces. Practically, /proc/self is
// always readable, whereas stat()ing /proc/1/ns/* requires privilege over PID 1
// — so keying off PID 1 makes collapse detection silently degrade to "Unknown"
// for any unprivileged caller, which is exactly the case where reporting the
// node's sockets as a container's would go unnoticed.
ScopeKind ClassifyAgainstHost(pid_t pid, const char* ns_name)
{
    struct stat target {};
    struct stat host {};

    if (!NamespaceId(pid, ns_name, target)) return ScopeKind::Unknown;
    if (!NamespaceId(::getpid(), ns_name, host)) return ScopeKind::Unknown;

    const bool same = (target.st_ino == host.st_ino) && (target.st_dev == host.st_dev);
    return same ? ScopeKind::HostCollapsed : ScopeKind::Container;
}

} // namespace

bool SharesNamespace(pid_t pid, pid_t other, const char* ns_name)
{
    struct stat a {};
    struct stat b {};

    if (!NamespaceId(pid, ns_name, a)) return false;
    if (!NamespaceId(other, ns_name, b)) return false;

    return (a.st_ino == b.st_ino) && (a.st_dev == b.st_dev);
}

ContainerScope DetectContainerScope(pid_t pid)
{
    ContainerScope scope;
    scope.net = ClassifyAgainstHost(pid, "net");
    scope.pid = ClassifyAgainstHost(pid, "pid");
    return scope;
}

std::unordered_set<std::string>
SharedNetnsContainers(const std::unordered_map<std::string, std::vector<pid_t>>& pids_by_container)
{
    // netns inode -> container ids sitting in it.
    std::unordered_map<ino_t, std::vector<std::string>> byNetns;

    for (const auto& [container_id, pids] : pids_by_container)
    {
        if (pids.empty()) continue;

        struct stat st {};
        if (!NamespaceId(pids.front(), "net", st)) continue;

        byNetns[st.st_ino].push_back(container_id);
    }

    std::unordered_set<std::string> shared;
    for (const auto& [inode, ids] : byNetns)
    {
        if (ids.size() < 2) continue;
        shared.insert(ids.begin(), ids.end());
    }

    return shared;
}

} // namespace wazuh::container_baseline
