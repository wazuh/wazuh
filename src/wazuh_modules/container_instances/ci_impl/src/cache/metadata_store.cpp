#include "metadata_store.hpp"

#include "container_admission.hpp"
#include "reconciler.hpp"

#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace wazuh::container_instances
{

    namespace
    {

        LookupResult toLookupResult(const CacheEntry& entry)
        {
            LookupResult result;
            if (const auto* resolved = std::get_if<ResolvedEntry>(&entry))
            {
                result.status = LookupResult::Status::resolved;
                result.record = resolved->record;
            }
            else if (const auto* verdict = std::get_if<VerdictEntry>(&entry))
            {
                result.status = LookupResult::Status::verdict;
                result.reason = verdict->reason;
            }
            else
            {
                result.status = LookupResult::Status::pending;
            }
            return result;
        }

    } // namespace

    MetadataStore::MetadataStore(Logger logger, KeyKind keyKind)
        : m_logger(std::move(logger))
        , m_keyKind(keyKind)
    {
    }

    LookupResult MetadataStore::lookup(HostKey key) const
    {
        if (key.value == 0)
        {
            return {};
        }
        if (key.kind != m_keyKind)
        {
            // Refused, not looked up, and the refusal has to be TOLD APART from
            // a miss by the caller. The two kinds are both 64-bit inode
            // numbers, so a mismatched one merely fails to match; reported as
            // "unknown container" it sends the caller off re-resolving
            // something that is sitting right here.
            LookupResult refused;
            refused.status = LookupResult::Status::wrongKeyKind;
            return refused;
        }
        std::shared_lock lock(m_mutex);
        const auto it = m_byCgroup.find(key.value);
        if (it == m_byCgroup.end())
        {
            return {};
        }
        if (const auto* alias = std::get_if<AliasEntry>(&it->second))
        {
            // Resolved through the container rather than held as a record: an
            // alias that outlives its container answers `miss`, which is the
            // truth, instead of serving a record that has been swept.
            const auto record = recordLocked(alias->source, alias->containerId);
            if (!record)
            {
                return {};
            }
            LookupResult result;
            result.status = LookupResult::Status::resolved;
            result.record = record;
            return result;
        }
        return toLookupResult(it->second);
    }

    LookupResult MetadataStore::lookupByContainerId(const std::string& containerId) const
    {
        std::shared_lock lock(m_mutex);
        for (const auto& [source, records] : m_bySource)
        {
            const auto it = records.find(containerId);
            if (it != records.end())
            {
                LookupResult result;
                result.status = LookupResult::Status::resolved;
                result.record = it->second;
                return result;
            }
        }
        return {};
    }

    LookupResult MetadataStore::lookupByPodContainer(const std::string& podUid, const std::string& containerName) const
    {
        std::shared_lock lock(m_mutex);
        const auto it = m_byPodContainer.find(podContainerKey(podUid, containerName));
        if (it == m_byPodContainer.end())
        {
            return {};
        }
        LookupResult result;
        result.status = LookupResult::Status::resolved;
        result.record = it->second;
        return result;
    }

    StoreStats MetadataStore::stats() const
    {
        std::shared_lock lock(m_mutex);
        StoreStats result;
        for (const auto& [source, records] : m_bySource)
        {
            result.resolved += records.size();
        }
        for (const auto& [inode, entry] : m_byCgroup)
        {
            if (std::holds_alternative<PendingEntry>(entry))
            {
                ++result.pending;
            }
            else if (std::holds_alternative<VerdictEntry>(entry))
            {
                ++result.verdicts;
            }
        }
        result.lastReconcile = m_lastReconcile;
        return result;
    }

    std::vector<ContainerRecordPtr> MetadataStore::listContainers() const
    {
        std::shared_lock lock(m_mutex);
        std::vector<ContainerRecordPtr> result;
        std::unordered_set<std::string> seen;
        std::size_t withheld = 0;
        std::string withheldExample;

        for (const auto& [source, records] : m_bySource)
        {
            for (const auto& [containerId, record] : records)
            {
                if (record && record->hostKey == 0 && isRunning(record->state))
                {
                    ++withheld;
                    if (withheldExample.empty())
                    {
                        withheldExample = containerId;
                    }
                }
                // Hide only UNRESOLVED RUNNING records. A running container with
                // no inode yet is one the resolver has not caught up with, and
                // publishing it would let a consumer act on an attribution key
                // that is about to change. A container that is not running has
                // no inode to wait for and is published as it is — otherwise a
                // stop would read, to every consumer, exactly like a deletion.
                if (!record || (record->hostKey == 0 && isRunning(record->state)) || !seen.insert(containerId).second)
                {
                    continue;
                }
                result.push_back(record);
            }
        }

        // Say so when the number changes. A container stuck here forever is the
        // signature of one the resolver can never key -- see the comment on
        // m_withheldReported -- and it used to be indistinguishable from absence.
        if (m_withheldReported.exchange(withheld) != withheld && m_logger)
        {
            if (withheld == 0)
            {
                m_logger(LogLevel::debug, "All running containers are resolved; none withheld from the list.");
            }
            else
            {
                m_logger(LogLevel::debug,
                         "Withholding " + std::to_string(withheld) +
                             " running container(s) from the list until the resolver keys them (e.g. '" +
                             withheldExample.substr(0, 12) +
                             "'). A container that stays here is one whose cgroup no process reports.");
            }
        }

        return result;
    }

namespace
{
    /// Whether an alias still points at a cgroup of ITS OWN container.
    ///
    /// The plain liveness test -- "is this inode in the scan" -- cannot answer
    /// that. `allHostKeys` holds every key observed on the host, so an inode
    /// that died with one container's unit and was promptly reused by an
    /// unrelated cgroup reads as live, and the alias goes on pointing at the old
    /// container; its events would then be attributed to the wrong one.
    ///
    /// The snapshot knows the answer directly, because a record now carries the
    /// container's other cgroups as well as the one it is filed under. That is
    /// only authoritative for the source that produced the snapshot, though: an
    /// alias owned by another connector is not described by these records at
    /// all, and judging it against them would expire something perfectly good.
    /// For those, the old liveness rule stands.
    [[nodiscard]] bool aliasInodeIsLive(const AliasEntry& alias,
                                        std::uint64_t inode,
                                        const SourceId& snapshotSource,
                                        const std::unordered_map<std::string, std::unordered_set<std::uint64_t>>&
                                            snapshotKeysByContainerId,
                                        const std::unordered_set<std::uint64_t>& liveInodes)
    {
        if (alias.source != snapshotSource)
        {
            return liveInodes.count(inode) > 0;
        }

        const auto keys = snapshotKeysByContainerId.find(alias.containerId);

        return keys != snapshotKeysByContainerId.end() && keys->second.count(inode) > 0;
    }
} // namespace


    void MetadataStore::applySnapshot(const SourceId& source,
                                      std::vector<ContainerRecord> snapshot,
                                      const std::unordered_set<std::uint64_t>& liveInodes,
                                      TimePoint now)
    {
        std::unique_lock lock(m_mutex);

        auto& sourceRecords = m_bySource[source];
        auto delta = diffSnapshot(sourceRecords, snapshot);

        for (auto& record : delta.added)
        {
            insertResolvedLocked(source, std::move(record));
        }
        for (auto& record : delta.updated)
        {
            insertResolvedLocked(source, std::move(record));
        }

        // A container present in this source's snapshot is alive even when its
        // record is byte-identical to the stored one: clear any grace mark.
        for (const auto& record : snapshot)
        {
            if (record.hostKey == 0)
            {
                continue;
            }
            const auto entryIt = m_byCgroup.find(record.hostKey);
            if (entryIt != m_byCgroup.end())
            {
                if (auto* resolved = std::get_if<ResolvedEntry>(&entryIt->second);
                    resolved != nullptr && resolved->source == source &&
                    resolved->record != nullptr && resolved->record->containerId == record.containerId)
                {
                    resolved->deletedAt.reset();
                }
            }
        }

        // Removals affect ONLY this source's records; records unreachable by
        // cgroup id have nothing to serve late events with, so they go now.
        for (const auto& containerId : delta.removedContainerIds)
        {
            const auto it = sourceRecords.find(containerId);
            if (it == sourceRecords.end())
            {
                continue;
            }
            const auto& record = it->second;
            if (record->hostKey == 0)
            {
                eraseResolvedLocked(source, containerId);
                continue;
            }
            // The key must still belong to THIS container. A mount-namespace
            // inode is reused by the kernel, so by the time a removal is
            // processed the key can already have been rebound to a live
            // container -- marking that one would delete something running and
            // leave the departed record to sit here forever, since the expiry
            // sweep below only ever walks m_byCgroup.
            const auto entryIt = m_byCgroup.find(record->hostKey);
            auto* resolved = entryIt != m_byCgroup.end() ? std::get_if<ResolvedEntry>(&entryIt->second) : nullptr;
            const bool stillOurs = resolved != nullptr && resolved->source == source &&
                                   resolved->record != nullptr && resolved->record->containerId == containerId;
            if (!stillOurs)
            {
                eraseResolvedLocked(source, containerId);
                continue;
            }
            if (!resolved->deletedAt)
            {
                resolved->deletedAt = now;
            }
        }

        // Which host keys this snapshot says each of its containers occupies.
        // An alias is only true while its inode is one of ITS container's, and
        // `liveInodes` cannot answer that: it holds every key observed on the
        // host, so an inode that died with one container's unit and was reused
        // by an unrelated cgroup is still "live" there. See the alias sweep.
        std::unordered_map<std::string, std::unordered_set<std::uint64_t>> snapshotKeysByContainerId;
        for (const auto& record : snapshot)
        {
            auto& keys = snapshotKeysByContainerId[record.containerId];

            if (record.hostKey != 0)
            {
                keys.insert(record.hostKey);
            }

            keys.insert(record.extraHostKeys.begin(), record.extraHostKeys.end());
        }

        // Sweeps: expired grace records (any source — expiry is owner-marked),
        // pending TTL, verdict liveness.
        std::vector<std::pair<SourceId, std::string>> expiredRecords;
        std::vector<std::uint64_t> expiredInodes;
        for (auto& [inode, entry] : m_byCgroup)
        {
            if (const auto* resolved = std::get_if<ResolvedEntry>(&entry))
            {
                if (resolved->deletedAt && now - *resolved->deletedAt >= REMOVAL_GRACE)
                {
                    expiredRecords.emplace_back(resolved->source, resolved->record->containerId);
                }
            }
            else if (const auto* pending = std::get_if<PendingEntry>(&entry))
            {
                if (now - pending->lastAttempt >= PENDING_TTL)
                {
                    expiredInodes.push_back(inode);
                }
            }
            else if (auto* verdict = std::get_if<VerdictEntry>(&entry))
            {
                if (liveInodes.count(inode) > 0)
                {
                    verdict->missedScans = 0;
                }
                else if (++verdict->missedScans >= MISSED_SCANS_LIMIT)
                {
                    expiredInodes.push_back(inode);
                }
            }
            else if (auto* alias = std::get_if<AliasEntry>(&entry))
            {
                // Two ways an alias stops being true, and both have to be swept
                // here because nothing else walks these.
                //
                // The container it names is gone: dropped at once. Not when the
                // record is erased, because a record is erased on every ordinary
                // update too, and an alias that outlived one of those is still
                // perfectly good.
                //
                // Or the cgroup it names is gone while the container lives —
                // a unit that exited. Inodes are reused, so left alone this one
                // eventually points a DIFFERENT container's events at this one.
                // Same liveness rule as a verdict, for the same reason.
                if (!recordLocked(alias->source, alias->containerId))
                {
                    expiredInodes.push_back(inode);
                }
                else if (aliasInodeIsLive(*alias, inode, source, snapshotKeysByContainerId, liveInodes))
                {
                    alias->missedScans = 0;
                }
                else if (++alias->missedScans >= MISSED_SCANS_LIMIT)
                {
                    expiredInodes.push_back(inode);
                }
            }
        }
        for (const auto& [expiredSource, containerId] : expiredRecords)
        {
            eraseResolvedLocked(expiredSource, containerId);
        }
        for (const auto inode : expiredInodes)
        {
            m_byCgroup.erase(inode);
        }

        m_lastReconcile = now;

        // After the sweeps, not before: a container still inside its removal
        // grace is still visible and still holds its slot, and one erased above
        // has just freed its slot for whoever was waiting. Recomputing earlier
        // would hand a slot to a newcomer a beat before the departure that
        // freed it, and hand it back on the next pass.
        recomputeAdmittedLocked();

        // Released before the notify on purpose: an observer's natural first
        // move is to read the store back, which would deadlock under this lock,
        // and a slow one would stall every reader for as long as it ran.
        lock.unlock();
        notifyLifecycleUnlocked();
    }

    void MetadataStore::upsertPending(std::uint64_t cgroupInode, int attempts, TimePoint now)
    {
        if (cgroupInode == 0)
        {
            return;
        }
        std::unique_lock lock(m_mutex);
        const auto it = m_byCgroup.find(cgroupInode);
        if (it == m_byCgroup.end())
        {
            PendingEntry entry;
            entry.firstSeen = now;
            entry.lastAttempt = now;
            entry.attempts = attempts;
            m_byCgroup.emplace(cgroupInode, entry);
        }
        else if (auto* pending = std::get_if<PendingEntry>(&it->second))
        {
            pending->lastAttempt = now;
            pending->attempts = attempts;
        }
        // Resolved/verdict entries are authoritative: never downgraded to pending.
    }

    void MetadataStore::upsertVerdict(std::uint64_t cgroupInode, VerdictReason reason)
    {
        if (cgroupInode == 0)
        {
            return;
        }
        std::unique_lock lock(m_mutex);
        const auto it = m_byCgroup.find(cgroupInode);
        if (it == m_byCgroup.end() || std::holds_alternative<PendingEntry>(it->second))
        {
            VerdictEntry entry;
            entry.reason = reason;
            m_byCgroup[cgroupInode] = entry;
        }
        // Resolved entries win: positive evidence is never overwritten by a verdict.
    }

    void MetadataStore::upsertResolved(const SourceId& source, ContainerRecord record)
    {
        std::unique_lock lock(m_mutex);

        // The key this arrived under is the one the COLD PATH WAS ASKED ABOUT,
        // which is not necessarily the one this container is filed under. A
        // container running an init system puts its processes in child cgroups,
        // so an event carries one of those while the reconcile files the record
        // under the single key it picks for the whole container.
        //
        // Letting this overwrite that key made the two take turns: the cold path
        // moved the container onto the child it was asked about, the next
        // reconcile moved it back, and each move is an identity change published
        // as `changed` — FIM re-walked the container's whole tree every few
        // seconds for a container that had not moved. The reconcile owns the
        // key; this path only adds a way to find the container by it.
        const auto observedKey = record.hostKey;
        const auto containerId = record.containerId;

        if (observedKey != 0)
        {
            if (const auto known = recordLocked(source, containerId); known && known->hostKey != 0)
            {
                record.hostKey = known->hostKey;
            }
        }

        const auto canonicalKey = record.hostKey;
        insertResolvedLocked(source, std::move(record));

        if (observedKey != 0 && observedKey != canonicalKey)
        {
            indexAliasLocked(source, containerId, observedKey);
        }

        // The cold path can publish a container that was not visible a moment
        // ago, so it can also fill a free slot. Without this a container first
        // seen through an on-demand resolve would stay unadmitted until the
        // next unrelated reconcile, for the same reason the notify below exists.
        recomputeAdmittedLocked();

        // The cold path publishes containers too — one first seen through an
        // on-demand resolve is as new to consumers as one the connector found,
        // and skipping the notify here would make its discovery wait for the
        // next unrelated reconcile.
        lock.unlock();
        notifyLifecycleUnlocked();
    }

    ContainerRecordPtr MetadataStore::recordLocked(const SourceId& source, const std::string& containerId) const
    {
        const auto sourceIt = m_bySource.find(source);
        if (sourceIt == m_bySource.end())
        {
            return nullptr;
        }
        const auto it = sourceIt->second.find(containerId);
        return (it == sourceIt->second.end()) ? nullptr : it->second;
    }

    void MetadataStore::indexAliasLocked(const SourceId& source, const std::string& containerId, std::uint64_t hostKey)
    {
        const auto it = m_byCgroup.find(hostKey);

        // A resolved entry is never displaced. It is some container's ONE index
        // entry, and overwriting it would leave that container unreachable by
        // the only key it has — a worse outcome than this cgroup staying on the
        // cold path. Pending and verdict entries are provisional by definition:
        // positive evidence supersedes them, exactly as it does on the resolved
        // path.
        if (it != m_byCgroup.end() && std::holds_alternative<ResolvedEntry>(it->second))
        {
            return;
        }

        AliasEntry alias;
        alias.source = source;
        alias.containerId = containerId;
        m_byCgroup[hostKey] = std::move(alias);
    }

    void MetadataStore::insertResolvedRawLocked(const SourceId& source, ContainerRecord record)
    {
        eraseResolvedRawLocked(source, record.containerId);

        auto shared = std::make_shared<const ContainerRecord>(std::move(record));

        m_bySource[source][shared->containerId] = shared;
        if (!shared->podUid.empty())
        {
            m_byPodContainer[podContainerKey(shared->podUid, shared->containerName)] = shared;
        }
        if (shared->hostKey != 0)
        {
            const auto it = m_byCgroup.find(shared->hostKey);
            if (it != m_byCgroup.end())
            {
                if (std::holds_alternative<VerdictEntry>(it->second))
                {
                    m_logger(LogLevel::info,
                             "Verdict for cgroup inode " + std::to_string(shared->hostKey) +
                                 " superseded by container " + shared->containerId);
                }
                else if (const auto* resolved = std::get_if<ResolvedEntry>(&it->second))
                {
                    // Contested inode (cri-dockerd: same container through two
                    // APIs): Kubernetes evidence outranks Docker for the index.
                    if (resolved->source != source && resolved->source == KUBERNETES_SOURCE &&
                        source != KUBERNETES_SOURCE)
                    {
                        return; // Record stored in its source map; index stays K8s.
                    }
                }
            }
            ResolvedEntry entry;
            entry.record = shared;
            entry.source = source;
            m_byCgroup[shared->hostKey] = std::move(entry);
        }
    }

    void MetadataStore::eraseResolvedRawLocked(const SourceId& source, const std::string& containerId)
    {
        const auto sourceIt = m_bySource.find(source);
        if (sourceIt == m_bySource.end())
        {
            return;
        }
        const auto it = sourceIt->second.find(containerId);
        if (it == sourceIt->second.end())
        {
            return;
        }
        const auto record = it->second;

        if (!record->podUid.empty())
        {
            const auto podIt = m_byPodContainer.find(podContainerKey(record->podUid, record->containerName));
            if (podIt != m_byPodContainer.end() && podIt->second == record)
            {
                m_byPodContainer.erase(podIt);
            }
        }
        if (record->hostKey != 0)
        {
            const auto cgroupIt = m_byCgroup.find(record->hostKey);
            if (cgroupIt != m_byCgroup.end())
            {
                if (const auto* resolved = std::get_if<ResolvedEntry>(&cgroupIt->second);
                    resolved != nullptr && resolved->record == record)
                {
                    m_byCgroup.erase(cgroupIt);
                }
            }
        }
        sourceIt->second.erase(it);
    }

    std::set<std::string> MetadataStore::admittedIds() const
    {
        std::shared_lock lock(m_mutex);
        return m_admitted;
    }

    void MetadataStore::setSyncLimit(int limit)
    {
        std::unique_lock lock(m_mutex);

        if (m_syncLimit == limit)
        {
            return;
        }

        m_syncLimit = limit;
        recomputeAdmittedLocked();
    }

    std::set<std::string> MetadataStore::visibleIdsLocked() const
    {
        std::set<std::string> visible;

        for (const auto& [source, records] : m_bySource)
        {
            for (const auto& [containerId, record] : records)
            {
                if (!record || (record->hostKey == 0 && isRunning(record->state)))
                {
                    continue; // Running but unresolved: not published yet.
                }
                visible.insert(containerId);
            }
        }

        return visible;
    }

    void MetadataStore::recomputeAdmittedLocked()
    {
        const auto visible = visibleIdsLocked();
        m_admitted = admitContainers(visible, m_admitted, m_syncLimit);

        // Say how many are NOT reporting, on change rather than per pass.
        //
        // An analyst shown ten containers when fifty exist, with nothing saying
        // so, is being told something false about coverage -- and silence here
        // is indistinguishable from a node that really runs ten. This is the
        // only place that knows both numbers.
        const std::size_t withheld = visible.size() - m_admitted.size();

        if (m_withheldFromSyncReported == withheld || !m_logger)
        {
            return;
        }

        m_withheldFromSyncReported = withheld;

        if (withheld == 0)
        {
            m_logger(LogLevel::debug, "Every container is reporting to the manager; none withheld by the limit.");
        }
        else
        {
            m_logger(LogLevel::info,
                     "Reporting " + std::to_string(m_admitted.size()) + " of " + std::to_string(visible.size()) +
                         " container(s) to the manager; " + std::to_string(withheld) +
                         " withheld by containers.synced_limit=" + std::to_string(m_syncLimit) +
                         ". The withheld containers are still monitored and their data is still stored locally -- "
                         "it is not sent. Raise the limit to report more.");
        }
    }

    ContainerRecordPtr MetadataStore::visibleRecordLocked(const std::string& containerId) const
    {
        // Mirrors listContainers()' filter, across every source, because the
        // journal logs transitions of the set that call returns. A container
        // known to two sources (cri-dockerd reports the same container through
        // both APIs) is one member, so it appears here once.
        for (const auto& [source, records] : m_bySource)
        {
            const auto it = records.find(containerId);
            if (it == records.end() || !it->second)
            {
                continue;
            }
            if (it->second->hostKey == 0 && isRunning(it->second->state))
            {
                continue; // Running but unresolved: not published yet.
            }
            return it->second;
        }
        return nullptr;
    }

    void MetadataStore::journalTransitionLocked(const std::string& containerId,
                                                const ContainerRecordPtr& before,
                                                const ContainerRecordPtr& after)
    {
        if (!before && !after)
        {
            // Invisible before, invisible after. The commonest case by far: an
            // unresolved running record being rewritten while the resolver
            // catches up. Nothing a consumer could act on happened.
            return;
        }

        LifecycleEvent event;
        event.containerId = containerId;

        if (!before)
        {
            event.kind = LifecycleKind::added;
            event.hostKey = after->hostKey;
            event.record = after;
        }
        else if (!after)
        {
            event.kind = LifecycleKind::removed;
            // The inode it had when it left: a consumer keyed on cgroup id
            // cannot act on a removal it cannot map back to one.
            event.hostKey = before->hostKey;
        }
        else
        {
            const auto mask = lifecycleChangeMask(*before, *after);

            if ((mask & ~static_cast<unsigned int>(LIFECYCLE_METADATA)) == 0)
            {
                // Nothing changed, or only labels/annotations did. Dropped at
                // append time rather than filtered by the reader: Kubernetes
                // annotation churn marks records changed on every reconcile, and
                // letting that into the ring would evict real transitions long
                // before a consumer's next poll.
                //
                // Tested on the mask rather than against LIFECYCLE_METADATA
                // exactly, so a class that arrives TOGETHER with a metadata
                // change is still published. Spelled as equality, a relabel in
                // the same reconcile as a new unit cgroup suppressed both.
                return;
            }

            event.kind = LifecycleKind::changed;
            event.hostKey = after->hostKey;
            event.changed = mask;
            event.record = after;
        }

        m_journal.append(std::move(event));
        m_lifecycleDirty = true;
    }

    void MetadataStore::insertResolvedLocked(const SourceId& source, ContainerRecord record)
    {
        const auto containerId = record.containerId;
        const auto before = visibleRecordLocked(containerId);

        insertResolvedRawLocked(source, std::move(record));

        journalTransitionLocked(containerId, before, visibleRecordLocked(containerId));
    }

    void MetadataStore::eraseResolvedLocked(const SourceId& source, const std::string& containerId)
    {
        const auto before = visibleRecordLocked(containerId);

        eraseResolvedRawLocked(source, containerId);

        journalTransitionLocked(containerId, before, visibleRecordLocked(containerId));
    }

    void MetadataStore::notifyLifecycleUnlocked()
    {
        bool dirty = false;
        LifecycleCursor cursor;

        {
            std::unique_lock lock(m_mutex);
            dirty = m_lifecycleDirty;
            m_lifecycleDirty = false;
            cursor = m_journal.cursor();
        }

        if (dirty && m_onLifecycleChange)
        {
            m_onLifecycleChange(cursor);
        }
    }

    LifecycleDelta MetadataStore::lifecycleSince(const LifecycleCursor& from) const
    {
        std::shared_lock lock(m_mutex);

        // listContainers() would take the lock again; build the resync set here
        // under the one we already hold.
        std::vector<ContainerRecordPtr> current;
        std::unordered_set<std::string> seen;

        for (const auto& [source, records] : m_bySource)
        {
            for (const auto& [containerId, record] : records)
            {
                if (!record || (record->hostKey == 0 && isRunning(record->state)) || !seen.insert(containerId).second)
                {
                    continue;
                }
                current.push_back(record);
            }
        }

        return m_journal.since(from, current);
    }

    LifecycleCursor MetadataStore::lifecycleCursor() const
    {
        std::shared_lock lock(m_mutex);
        return m_journal.cursor();
    }

    void MetadataStore::setOnLifecycleChange(std::function<void(LifecycleCursor)> callback)
    {
        m_onLifecycleChange = std::move(callback);
    }

} // namespace wazuh::container_instances
