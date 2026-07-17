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
                if (!record || record->cgroupId == 0 || !seen.insert(containerId).second)
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
    }

    void MetadataStore::insertResolvedLocked(const SourceId& source, ContainerRecord record)
    {
        eraseResolvedLocked(source, record.containerId);

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

    void MetadataStore::eraseResolvedLocked(const SourceId& source, const std::string& containerId)
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

} // namespace wazuh::container_instances
