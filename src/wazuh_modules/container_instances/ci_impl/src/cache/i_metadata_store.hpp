#pragma once

#include "../core/cache_entry.hpp"
#include "../core/container_record.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace wazuh::container_instances
{

    struct LookupResult
    {
        enum class Status : std::uint8_t
        {
            miss,     ///< Nothing known for this key.
            resolved, ///< `record` is set.
            pending,  ///< Cold cache; caller re-queries later.
            verdict   ///< `reason` is set; permanent "not a container".
        };

        Status status {Status::miss};
        ContainerRecordPtr record;
        std::optional<VerdictReason> reason;
    };

    struct StoreStats
    {
        std::size_t resolved {0};
        std::size_t pending {0};
        std::size_t verdicts {0};
        std::optional<TimePoint> lastReconcile;
    };

    /// Concurrent metadata cache. Threading contract:
    ///  - applySnapshot: exactly one caller, the connector thread.
    ///  - upsertPending/upsertVerdict: targeted single-key writes from IPC workers.
    ///  - lookups: any thread, shared-lock, return immutable record copies.
    class IMetadataStore
    {
    public:
        virtual ~IMetadataStore() = default;

        [[nodiscard]] virtual LookupResult lookupByCgroup(std::uint64_t cgroupInode) const = 0;
        [[nodiscard]] virtual LookupResult lookupByContainerId(const std::string& containerId) const = 0;
        [[nodiscard]] virtual LookupResult lookupByPodContainer(const std::string& podUid,
                                                                const std::string& containerName) const = 0;
        [[nodiscard]] virtual StoreStats stats() const = 0;
        [[nodiscard]] virtual std::vector<ContainerRecordPtr> listContainers() const = 0;

        /// Reconcile ONE source's view: replace that source's resolved set with
        /// `snapshot` (diff is computed within the source, so multiple sources
        /// coexist without evicting each other), sweep pending TTLs, age grace
        /// entries, and run verdict liveness against `liveInodes`.
        virtual void applySnapshot(const SourceId& source,
                                   std::vector<ContainerRecord> snapshot,
                                   const std::unordered_set<std::uint64_t>& liveInodes,
                                   TimePoint now) = 0;

        virtual void upsertPending(std::uint64_t cgroupInode, int attempts, TimePoint now) = 0;
        virtual void upsertVerdict(std::uint64_t cgroupInode, VerdictReason reason) = 0;

        /// Targeted single-record insert from the cold path (on-demand refresh).
        virtual void upsertResolved(const SourceId& source, ContainerRecord record) = 0;
    };

} // namespace wazuh::container_instances
