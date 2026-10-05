#include "metadata_store.hpp"

#include "reconciler.hpp"

#include <unordered_set>
#include <mutex>
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

    MetadataStore::MetadataStore(Logger logger)
        : m_logger(std::move(logger))
    {
    }

    LookupResult MetadataStore::lookupByCgroup(std::uint64_t cgroupInode) const
    {
        if (cgroupInode == 0)
        {
            return {};
        }
        std::shared_lock lock(m_mutex);
        const auto it = m_byCgroup.find(cgroupInode);
        return (it == m_byCgroup.end()) ? LookupResult {} : toLookupResult(it->second);
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

        for (const auto& [source, records] : m_bySource)
        {
            for (const auto& [containerId, record] : records)
            {
                // Hide only UNRESOLVED RUNNING records. A running container with
                // no inode yet is one the resolver has not caught up with, and
                // publishing it would let a consumer act on an attribution key
                // that is about to change. A container that is not running has
                // no inode to wait for and is published as it is — otherwise a
                // stop would read, to every consumer, exactly like a deletion.
                if (!record || (record->cgroupId == 0 && isRunning(record->state)) ||
                    !seen.insert(containerId).second)
                {
                    continue;
                }
                result.push_back(record);
            }
        }

        return result;
    }

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
            if (record.cgroupId == 0)
            {
                continue;
            }
            const auto entryIt = m_byCgroup.find(record.cgroupId);
            if (entryIt != m_byCgroup.end())
            {
                if (auto* resolved = std::get_if<ResolvedEntry>(&entryIt->second);
                    resolved != nullptr && resolved->source == source)
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
            if (record->cgroupId == 0)
            {
                eraseResolvedLocked(source, containerId);
                continue;
            }
            const auto entryIt = m_byCgroup.find(record->cgroupId);
            if (entryIt != m_byCgroup.end())
            {
                if (auto* resolved = std::get_if<ResolvedEntry>(&entryIt->second);
                    resolved != nullptr && resolved->source == source && !resolved->deletedAt)
                {
                    resolved->deletedAt = now;
                }
            }
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
        insertResolvedLocked(source, std::move(record));

        // The cold path publishes containers too — one first seen through an
        // on-demand resolve is as new to consumers as one the connector found,
        // and skipping the notify here would make its discovery wait for the
        // next unrelated reconcile.
        lock.unlock();
        notifyLifecycleUnlocked();
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
        if (shared->cgroupId != 0)
        {
            const auto it = m_byCgroup.find(shared->cgroupId);
            if (it != m_byCgroup.end())
            {
                if (std::holds_alternative<VerdictEntry>(it->second))
                {
                    m_logger(LogLevel::info,
                             "Verdict for cgroup inode " + std::to_string(shared->cgroupId) +
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
            m_byCgroup[shared->cgroupId] = std::move(entry);
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
        if (record->cgroupId != 0)
        {
            const auto cgroupIt = m_byCgroup.find(record->cgroupId);
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
            if (it->second->cgroupId == 0 && isRunning(it->second->state))
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
            event.cgroupId = after->cgroupId;
            event.record = after;
        }
        else if (!after)
        {
            event.kind = LifecycleKind::removed;
            // The inode it had when it left: a consumer keyed on cgroup id
            // cannot act on a removal it cannot map back to one.
            event.cgroupId = before->cgroupId;
        }
        else
        {
            const auto mask = lifecycleChangeMask(*before, *after);

            if (mask == 0 || mask == LIFECYCLE_METADATA)
            {
                // Nothing changed, or only labels/annotations did. Dropped at
                // append time rather than filtered by the reader: Kubernetes
                // annotation churn marks records changed on every reconcile, and
                // letting that into the ring would evict real transitions long
                // before a consumer's next poll.
                return;
            }

            event.kind = LifecycleKind::changed;
            event.cgroupId = after->cgroupId;
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
                if (!record || (record->cgroupId == 0 && isRunning(record->state)) ||
                    !seen.insert(containerId).second)
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
