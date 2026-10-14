#pragma once

#include "../core/host_key.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace wazuh::container_instances
{

    enum class RuntimeHint : std::uint8_t
    {
        unknown,
        containerd,
        crio,
        docker
    };

    /// One `/proc/<pid>/cgroup` resolution row. `containerId` empty means the
    /// cgroup exists but does not match any container naming scheme — evidence for
    /// a host_process verdict, not a failure.
    struct CgroupEntry
    {
        std::string containerId;
        std::uint64_t inode {0};
        RuntimeHint hint {RuntimeHint::unknown};
        std::string cgroupPath;

        /// Which v1 controller hierarchy `inode` was read from; empty on a
        /// unified or hybrid host, where the inode comes from the v2 line.
        ///
        /// Recorded rather than discarded because on v1 every controller is a
        /// separate mount with its own inode, so two entries resolved through
        /// different controllers are keyed on numbers that cannot be compared.
        /// Keeping the choice visible makes that detectable instead of
        /// silently wrong.
        std::string keyController;

        /// Mount namespace inode of a process observed in this cgroup.
        ///
        /// Populated on EVERY host, not only where it is used as the key: it
        /// makes the v1 and v2 paths structurally identical, and lets a v2 host
        /// cross-check attribution. It is the correlation key on cgroup v1,
        /// where an event's cgroup_id is a constant.
        std::uint64_t mntNsInode {0};
    };

    /// Full scan output. `allHostKeys` covers every distinct HOST KEY observed
    /// (container or not) — the store uses it for verdict liveness eviction, so
    /// it has to be drawn from the same space as the keys it is evicting
    /// against, which on a legacy host is mount namespaces and not cgroups.
    struct CgroupScan
    {
        std::vector<CgroupEntry> containers;
        std::unordered_set<std::uint64_t> allHostKeys;

        /// Which of each entry's two inodes is this host's key. Travels with
        /// the scan rather than being looked up by each consumer: one host
        /// constant, read once, carried to wherever it is needed.
        KeyKind keyKind {KeyKind::cgroupInode};
    };

    /// The number a container is filed under and correlated by.
    ///
    /// A free function over the raw facts rather than a third field beside
    /// them, and that is deliberate. A stored key is state that can disagree
    /// with the two numbers it was derived from — a caller that populates
    /// `inode` and forgets the key gets 0, which reads as "unresolved" and is
    /// indistinguishable from a container the resolver has not caught up with.
    /// Deriving it on demand cannot be forgotten.
    [[nodiscard]] inline std::uint64_t hostKeyOf(const CgroupEntry& entry, KeyKind kind)
    {
        return (kind == KeyKind::mntNsInode) ? entry.mntNsInode : entry.inode;
    }

    /// Isolated container-id/inode resolution: /proc walk + cgroupfs stat. Fully
    /// independent from the Kubernetes/Docker API clients by design (fixed
    /// decision); the cache is built by joining this output with API metadata on
    /// the container-id string.
    class ICgroupResolver
    {
    public:
        virtual ~ICgroupResolver() = default;

        [[nodiscard]] virtual CgroupScan scan() const = 0;

        /// Cold-path targeted rescan for one inode. nullopt = inode not currently
        /// observable (retry-worthy); entry with empty containerId = host cgroup.
        [[nodiscard]] virtual std::optional<CgroupEntry> scanOne(std::uint64_t hostKey) const = 0;
    };

} // namespace wazuh::container_instances
