#pragma once

#include "../core/logger.hpp"
#include "i_metadata_store.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <set>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace wazuh::container_instances
{

    inline constexpr auto PENDING_TTL = std::chrono::seconds {60};
    inline constexpr auto REMOVAL_GRACE = std::chrono::seconds {60};
    inline constexpr int MISSED_SCANS_LIMIT = 2;

    /// How long admission may stay unknown before the store decides on what it
    /// has. A ceiling, not the ordinary wait: the barrier normally clears as
    /// soon as every source has enumerated and the resolver has keyed what it
    /// can, which is one resolver pass. The grace exists for the node where
    /// that never happens -- one container whose cgroup nothing reports -- so a
    /// single unkeyable container cannot suspend the cap for the life of the
    /// agent.
    inline constexpr auto ADMISSION_SETTLE_GRACE = std::chrono::seconds {30};

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
        [[nodiscard]] std::set<std::string> admittedIds() const override;

        [[nodiscard]] std::set<std::string> unkeyedContainerIds() const override;
        [[nodiscard]] ListSnapshot listSnapshot(const std::optional<LifecycleCursor>& since) const override;
        void setSyncLimit(int limit) override;
        void settleAdmissionIfDue(TimePoint now) override;

        /// How many sources will enumerate this node. Set by the facade before
        /// it starts any connector thread; the store cannot work this out, and
        /// the number of sources that HAVE reported says nothing about how many
        /// will.
        ///
        /// 0, the default, means no barrier and admission is settled from the
        /// start -- which is what every caller that does not configure one, the
        /// tests included, already relied on.
        void setExpectedSources(std::size_t count);

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

        /// The record this source holds for this id, or null. Existence, not
        /// visibility — the opposite of visibleRecordLocked() below, and the
        /// difference matters: this one answers "is there anything to point an
        /// alias at", which a running-but-unresolved record still is.
        [[nodiscard]] ContainerRecordPtr recordLocked(const SourceId& source, const std::string& containerId) const;

        /// File `hostKey` as another way to reach this container, leaving the
        /// key it is indexed under alone. See AliasEntry for why the cold path
        /// must not simply re-key the record instead.
        void indexAliasLocked(const SourceId& source, const std::string& containerId, std::uint64_t hostKey);

        /// The record listContainers() would publish for this id, or null.
        /// Visibility, not existence — that distinction is the whole contract.
        [[nodiscard]] ContainerRecordPtr visibleRecordLocked(const std::string& containerId) const;

        /// Whether any source holds a record for this id. Existence across all
        /// of them, where recordLocked() answers for one. A hash lookup per
        /// source, against the two full id sets containerIdSetsLocked() builds.
        [[nodiscard]] bool knownToAnySourceLocked(const std::string& containerId) const;

        /// listContainers() and unkeyedContainerIds() with the lock already
        /// held, so listSnapshot() can take all three at one instant. The
        /// mutex is a shared_mutex, so a second shared acquisition on this
        /// thread would deadlock behind a waiting writer -- these exist for
        /// that reason, not for tidiness.
        [[nodiscard]] std::vector<ContainerRecordPtr> listContainersLocked() const;
        [[nodiscard]] std::set<std::string> unkeyedContainerIdsLocked() const;

        /// The two id sets the admission rule needs, from ONE walk of m_bySource.
        ///
        /// `known` is every container this store knows of; `visible` is the
        /// subset listContainers() publishes, which is `known` minus the running
        /// records the resolver has not keyed yet.
        ///
        /// Both, because admitContainers() needs both and for opposite reasons:
        /// incumbency is decided over what EXISTS, so a container that restarts
        /// does not lose its slot while it has no key, and free slots are filled
        /// from what can be PUBLISHED, so a container nothing can ever key never
        /// takes one it cannot use. See its header for what each half prevents.
        struct ContainerIdSets
        {
            std::set<std::string> known;
            std::set<std::string> visible;
        };

        [[nodiscard]] ContainerIdSets containerIdSetsLocked() const;

        /// Re-runs the admission rule over every known container. Cheap and
        /// idempotent, so it is called after any batch that can change what
        /// exists rather than tracked incrementally — the rule is a pure
        /// function of (known, visible, admitted, limit), and recomputing it is
        /// how a slot freed by a departure is handed on in the same pass.
        void recomputeAdmittedLocked();

        /// Arms the settle deadline on the first call that carries a clock, and
        /// expires it on a later one. Split from recomputeAdmittedLocked()
        /// because that runs on paths with no time to hand -- setSyncLimit()
        /// and the on-demand resolve -- and reading a cached timestamp instead
        /// meant a store whose snapshots stopped never expired the grace at
        /// all.
        void armOrExpireSettleDeadlineLocked(TimePoint now);

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

        /// Which containers may report, and the ceiling that decided it. Both
        /// guarded by m_mutex like everything beside them.
        ///
        /// There is no database here to seed stickiness from, so after an agent
        /// restart this is re-derived as "the lowest `m_syncLimit` ids that
        /// exist" — which is only true because the verdict waits for the whole
        /// node to be in view; see m_admissionSettled. That can differ from the
        /// set in flight before the restart, which shows up as a one-time shift
        /// in what the manager is told — deterministic, bounded to restarts,
        /// and written down rather than discovered.
        std::set<std::string> m_admitted;
        int m_syncLimit {0};

        /// Whether m_admitted is an answer yet, and the two conditions that
        /// make it one.
        ///
        /// Ranking before the node is fully in view freezes an arbitrary set:
        /// incumbency is sticky, so whoever the resolver happened to key first
        /// keeps its slot for the life of the process, and a restart with no
        /// real change moves documents on the manager. Both halves are needed
        /// and neither implies the other -- a source that has not enumerated
        /// yet contributes no containers at all, and a source that has may
        /// still be waiting on keys.
        ///
        /// While unsettled the verdict is WITHHELD rather than guessed: the
        /// reply omits it and every consumer keeps reporting, the same as
        /// against a connector too old to decide. The cost is a bounded window
        /// in which the node can report past containers.synced_limit, and on a
        /// restart where the cap binds syscollector will promote the rows it
        /// refused last run and retract them again once the verdict lands --
        /// one CREATE+DELETE pair per over-cap container. That is the price of
        /// not freezing the wrong set for ever.
        bool m_admissionSettled {true};
        std::size_t m_expectedSources {0};
        std::set<SourceId> m_enumeratedSources;
        std::optional<TimePoint> m_settleDeadline;

        /// How many containers the last recompute withheld, so the count is
        /// reported when it changes rather than on every reconcile. SIZE_MAX
        /// means "nothing said yet", so the first real answer always speaks.
        std::size_t m_withheldFromSyncReported {SIZE_MAX};

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
