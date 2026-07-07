#pragma once

#include "../core/logger.hpp"
#include "i_metadata_store.hpp"

#include <chrono>
#include <cstdint>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace wazuh::container_instances
{

    inline constexpr auto PENDING_TTL = std::chrono::seconds {60};
    inline constexpr auto REMOVAL_GRACE = std::chrono::seconds {60};
    inline constexpr int MISSED_SCANS_LIMIT = 2;

    /// Concurrent cache + resolution state machine (design doc §8).
    ///
    /// Verdict-permanence contract: a verdict is never re-evaluated while its
    /// cgroup lives, but positive reconcile evidence supersedes it, and a verdict
    /// whose inode is absent from the resolver scan for MISSED_SCANS_LIMIT
    /// consecutive reconciles is evicted — together these make permanent negatives
    /// safe against cgroup-inode recycling.
    class MetadataStore final : public IMetadataStore
    {
    public:
        explicit MetadataStore(Logger logger);

        [[nodiscard]] LookupResult lookupByCgroup(std::uint64_t cgroupInode) const override;
        [[nodiscard]] LookupResult lookupByContainerId(const std::string& containerId) const override;
        [[nodiscard]] LookupResult lookupByPodContainer(const std::string& podUid,
                                                        const std::string& containerName) const override;
        [[nodiscard]] StoreStats stats() const override;

        void applySnapshot(std::vector<ContainerRecord> snapshot,
                           const std::unordered_set<std::uint64_t>& liveInodes,
                           TimePoint now) override;

        void upsertPending(std::uint64_t cgroupInode, int attempts, TimePoint now) override;
        void upsertVerdict(std::uint64_t cgroupInode, VerdictReason reason) override;
        void upsertResolved(ContainerRecord record) override;

    private:
        void insertResolvedLocked(ContainerRecord record);
        void eraseResolvedLocked(const std::string& containerId);

        static std::string podContainerKey(const std::string& podUid, const std::string& containerName)
        {
            return podUid + "/" + containerName;
        }

        mutable std::shared_mutex m_mutex;
        std::unordered_map<std::uint64_t, CacheEntry> m_byCgroup;
        std::unordered_map<std::string, ContainerRecordPtr> m_byContainerId;
        std::unordered_map<std::string, ContainerRecordPtr> m_byPodContainer;
        std::optional<TimePoint> m_lastReconcile;
        Logger m_logger;
    };

} // namespace wazuh::container_instances
