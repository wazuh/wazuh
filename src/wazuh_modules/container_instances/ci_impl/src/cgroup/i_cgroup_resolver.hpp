#pragma once

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

    /// Full scan output. `allInodes` covers every distinct cgroup inode observed
    /// (container or not) — the store uses it for verdict liveness eviction.
    struct CgroupScan
    {
        std::vector<CgroupEntry> containers;
        std::unordered_set<std::uint64_t> allInodes;
    };

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
        [[nodiscard]] virtual std::optional<CgroupEntry> scanOne(std::uint64_t cgroupInode) const = 0;
    };

} // namespace wazuh::container_instances
