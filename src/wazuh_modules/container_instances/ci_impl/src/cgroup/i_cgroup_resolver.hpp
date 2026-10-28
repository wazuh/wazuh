#pragma once

#include "../core/host_key.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
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

    /// One host key per container id, chosen so the SAME scan always yields the
    /// same answer.
    ///
    /// A scan reports one entry per distinct cgroup, and a container running an
    /// init system occupies several: PID 1 in `init.scope`, each unit in
    /// `system.slice/<unit>.service`, every one its own kernfs node with its own
    /// inode. They all carry the container's id, so the id maps to several
    /// entries and SOMETHING has to pick.
    ///
    /// The connectors used to pick by inserting into an unordered map and
    /// letting the first insertion win, which made the choice depend on the
    /// order a hash table happened to iterate. Across two scans that order can
    /// differ, and a container whose host key changes is published as `changed`
    /// (lifecycle_journal.hpp) -- so consumers re-walked its files and re-scanned
    /// its inventory, repeatedly, for a container that had not moved.
    ///
    /// Shortest path wins, ties broken lexicographically: the container's own
    /// cgroup is a prefix of every child's, so when a process is observed there
    /// it is chosen, and when none is -- which is exactly the init-system case --
    /// the same child is chosen every time regardless of walk order.
    [[nodiscard]] inline std::unordered_map<std::string, std::uint64_t> hostKeysByContainerId(const CgroupScan& scan)
    {
        std::unordered_map<std::string, std::string> pathByContainerId;
        std::unordered_map<std::string, std::uint64_t> out;

        for (const auto& entry : scan.containers)
        {
            const auto hostKey = hostKeyOf(entry, scan.keyKind);
            const auto existing = pathByContainerId.find(entry.containerId);

            if (existing != pathByContainerId.end())
            {
                const auto& chosen = existing->second;
                const bool better = entry.cgroupPath.size() < chosen.size() ||
                                    (entry.cgroupPath.size() == chosen.size() && entry.cgroupPath < chosen);
                if (!better)
                {
                    continue;
                }
            }

            pathByContainerId[entry.containerId] = entry.cgroupPath;
            out[entry.containerId] = hostKey;
        }

        return out;
    }

    /// The host keys a container occupies BESIDES the one it is filed under.
    ///
    /// hostKeysByContainerId() collapses a container to one key on purpose, so
    /// its identity cannot flap. The kernel event filter needs the other half of
    /// that picture: a container running an init system occupies several cgroups
    /// -- `init.scope`, one per unit -- and rt_file.bpf.c matches an event's
    /// cgroup id by EQUALITY against the allowlist. An allowlist holding only
    /// the canonical key therefore discards, in the kernel, every event the
    /// container's units produce; nothing downstream ever sees them, so nothing
    /// downstream can recover them either.
    ///
    /// Returned separately from the canonical key rather than as one combined
    /// set, so there is no second copy of the canonical key that could disagree
    /// with `hostKey`. Sorted, because an order that varied between scans would
    /// read as keys coming and going to a consumer diffing the two.
    ///
    /// Empty for the ordinary case: a container whose processes all sit in its
    /// own cgroup has no extra keys, and this costs it nothing.
    [[nodiscard]] inline std::unordered_map<std::string, std::vector<std::uint64_t>>
    extraHostKeysByContainerId(const CgroupScan& scan)
    {
        const auto canonical = hostKeysByContainerId(scan);
        std::unordered_map<std::string, std::vector<std::uint64_t>> out;

        for (const auto& entry : scan.containers)
        {
            if (entry.containerId.empty())
            {
                continue;
            }

            const auto hostKey = hostKeyOf(entry, scan.keyKind);

            /* 0 is "no key could be determined", not an inode -- see
             * CgroupContainerMap::install(), which drops it for the same
             * reason. */
            if (hostKey == 0)
            {
                continue;
            }

            const auto chosen = canonical.find(entry.containerId);

            if (chosen != canonical.end() && chosen->second == hostKey)
            {
                continue;
            }

            auto& keys = out[entry.containerId];

            if (std::find(keys.begin(), keys.end(), hostKey) == keys.end())
            {
                keys.push_back(hostKey);
            }
        }

        for (auto& [containerId, keys] : out)
        {
            (void)containerId;
            std::sort(keys.begin(), keys.end());
        }

        return out;
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
