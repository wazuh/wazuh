#pragma once

#include "../core/logger.hpp"
#include "i_metadata_store.hpp"

#include <atomic>
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
        /// `keyKind` is a host constant, read once at construction. Injectable
        /// only so the legacy path can be tested on a unified build host.
        explicit MetadataStore(Logger logger, KeyKind keyKind = keyKindFor(wz_cgroup_mode()));

        [[nodiscard]] LookupResult lookup(HostKey key) const override;

        [[nodiscard]] KeyKind keyKind() const override
        {
            return m_keyKind;
        }
        [[nodiscard]] LookupResult lookupByContainerId(const std::string& containerId) const override;
        [[nodiscard]] LookupResult lookupByPodContainer(const std::string& podUid,
                                                        const std::string& containerName) const override;
        [[nodiscard]] StoreStats stats() const override;
        [[nodiscard]] std::vector<ContainerRecordPtr> listContainers() const override;

        void applySnapshot(const SourceId& source,
                           std::vector<ContainerRecord> snapshot,
                           const std::unordered_set<std::uint64_t>& liveInodes,
                           TimePoint now) override;

        void upsertPending(std::uint64_t cgroupInode, int attempts, TimePoint now) override;
        void upsertVerdict(std::uint64_t cgroupInode, VerdictReason reason) override;
        void upsertResolved(const SourceId& source, ContainerRecord record) override;

        [[nodiscard]] LifecycleDelta lifecycleSince(const LifecycleCursor& from) const override;
        [[nodiscard]] LifecycleCursor lifecycleCursor() const override;
        void setOnLifecycleChange(std::function<void(LifecycleCursor)> callback) override;

    private:
        /// Raw mutations. These do NOT journal, and nothing outside the two
        /// journaling wrappers below may call them.
        ///
        /// The split exists because insertResolvedLocked has to erase the prior
        /// entry first, so a journal hook placed inside the erase would emit a
        /// spurious removed+added pair for every ordinary update. Keeping the
        /// raw operations free of journaling makes that mistake impossible to
        /// make by accident rather than merely documented against.
        void insertResolvedRawLocked(const SourceId& source, ContainerRecord record);
        void eraseResolvedRawLocked(const SourceId& source, const std::string& containerId);

        /// Journaling wrappers: observe visibility before and after, and append
        /// the resulting transition.
        void insertResolvedLocked(const SourceId& source, ContainerRecord record);
        void eraseResolvedLocked(const SourceId& source, const std::string& containerId);

        /// The record listContainers() would publish for this id, or null.
        /// Visibility, not existence — that distinction is the whole contract.
        [[nodiscard]] ContainerRecordPtr visibleRecordLocked(const std::string& containerId) const;

        /// Appends the transition between two visibility states, dropping the
        /// ones no consumer acts on.
        void journalTransitionLocked(const std::string& containerId,
                                     const ContainerRecordPtr& before,
                                     const ContainerRecordPtr& after);

        /// Fires the lifecycle callback if this batch journalled anything.
        /// MUST be called with the write lock released.
        void notifyLifecycleUnlocked();

        static std::string podContainerKey(const std::string& podUid, const std::string& containerName)
        {
            return podUid + "/" + containerName;
        }

        mutable std::shared_mutex m_mutex;
        std::unordered_map<std::uint64_t, CacheEntry> m_byCgroup;
        /// One resolved-record map per source: removal diffs never cross sources.
        std::unordered_map<SourceId, std::unordered_map<std::string, ContainerRecordPtr>> m_bySource;
        std::unordered_map<std::string, ContainerRecordPtr> m_byPodContainer;
        std::optional<TimePoint> m_lastReconcile;
        Logger m_logger;
        KeyKind m_keyKind;

        LifecycleJournal m_journal;

        /// Set by journalTransitionLocked, consumed by notifyLifecycleUnlocked.
        /// Guarded by m_mutex like everything else it sits beside.
        bool m_lifecycleDirty {false};

        /// Set once at startup before any thread races for it, then only read.
        std::function<void(LifecycleCursor)> m_onLifecycleChange;

        /// How many running-but-unresolved records listContainers() withheld the
        /// last time it said so. Withholding them is correct, but doing it in
        /// silence made a container that can NEVER be resolved — one whose PID 1
        /// is an init system, so nothing ever reports its cgroup — look exactly
        /// like a container that does not exist. Logging on change rather than
        /// per call keeps a steady state quiet while still naming a new one.
        /// Atomic because listContainers() is const and holds only a shared lock.
        mutable std::atomic<std::size_t> m_withheldReported {SIZE_MAX};
    };

} // namespace wazuh::container_instances
