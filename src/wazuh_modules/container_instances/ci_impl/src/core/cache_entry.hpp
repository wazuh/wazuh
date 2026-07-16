#pragma once

#include "container_record.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>

namespace wazuh::container_instances
{

    /// The store never reads the clock itself: every mutating call receives `now`,
    /// so the whole state machine is testable with a fake clock.
    using TimePoint = std::chrono::steady_clock::time_point;

    /// Identity of an enrichment source (one connector instance). Generic string
    /// so the store is N-ary by construction: "kubernetes", "docker@<socket>", ...
    using SourceId = std::string;

    inline const SourceId KUBERNETES_SOURCE {"kubernetes"};

    [[nodiscard]] inline SourceId dockerSource(const std::string& socketPath)
    {
        return "docker@" + socketPath;
    }

    enum class VerdictReason : std::uint8_t
    {
        hostProcess,   ///< Inode belongs to a non-container cgroup (system.slice/...).
        hostNamespace, ///< Pod runs with hostNetwork/hostPID.
        cgroupnsHost,  ///< Container shares the host cgroup namespace.
        kata           ///< Kata Containers: cgroup not resolvable from the host. v1 limitation.
    };

    /// Cold cache: a query arrived for this inode and bounded resolution failed.
    /// The caller re-queries later; reconcile or a later query may resolve it.
    struct PendingEntry
    {
        TimePoint firstSeen;
        TimePoint lastAttempt;
        int attempts {0};
    };

    /// Fully enriched. `deletedAt` set = the container left the last reconcile
    /// snapshot; the record is kept for a grace period so late events still enrich.
    struct ResolvedEntry
    {
        ContainerRecordPtr record;
        std::optional<TimePoint> deletedAt;
        SourceId source; ///< Which connector's snapshot owns this record.
    };

    /// Permanent "definitively not a container" answer. Never retried while the
    /// cgroup lives; superseded by positive reconcile evidence, evicted when the
    /// inode vanishes from the resolver scan (cgroup-inode reuse protection).
    struct VerdictEntry
    {
        VerdictReason reason {VerdictReason::hostProcess};
        int missedScans {0};
    };

    /// Sum type: an inode is exactly one of pending/resolved/verdict (absence is
    /// expressed by not being in the map at all).
    using CacheEntry = std::variant<PendingEntry, ResolvedEntry, VerdictEntry>;

} // namespace wazuh::container_instances
