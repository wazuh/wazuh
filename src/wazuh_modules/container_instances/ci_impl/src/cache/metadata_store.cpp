#include "metadata_store.hpp"

#include "reconciler.hpp"

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
        const auto it = m_byContainerId.find(containerId);
        if (it == m_byContainerId.end())
        {
            return {};
        }
        LookupResult result;
        result.status = LookupResult::Status::resolved;
        result.record = it->second;
        return result;
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
        result.resolved = m_byContainerId.size();
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

    void MetadataStore::applySnapshot(std::vector<ContainerRecord> snapshot,
                                      const std::unordered_set<std::uint64_t>& liveInodes,
                                      TimePoint now)
    {
        std::unique_lock lock(m_mutex);

        auto delta = diffSnapshot(m_byContainerId, snapshot);

        for (auto& record : delta.added)
        {
            insertResolvedLocked(std::move(record));
        }
        for (auto& record : delta.updated)
        {
            insertResolvedLocked(std::move(record));
        }

        // A container present in the snapshot is alive even when its record is
        // byte-identical to the stored one (the diff calls it "unchanged"): clear
        // any grace-period mark so a reappearance never gets swept.
        for (const auto& record : snapshot)
        {
            if (record.cgroupId == 0)
            {
                continue;
            }
            const auto entryIt = m_byCgroup.find(record.cgroupId);
            if (entryIt != m_byCgroup.end())
            {
                if (auto* resolved = std::get_if<ResolvedEntry>(&entryIt->second))
                {
                    resolved->deletedAt.reset();
                }
            }
        }

        // Removals enter the grace period; records unreachable by cgroup id have
        // nothing to serve late events with, so they go immediately.
        for (const auto& containerId : delta.removedContainerIds)
        {
            const auto it = m_byContainerId.find(containerId);
            if (it == m_byContainerId.end())
            {
                continue;
            }
            const auto& record = it->second;
            if (record->cgroupId == 0)
            {
                eraseResolvedLocked(containerId);
                continue;
            }
            const auto entryIt = m_byCgroup.find(record->cgroupId);
            if (entryIt != m_byCgroup.end())
            {
                if (auto* resolved = std::get_if<ResolvedEntry>(&entryIt->second);
                    resolved != nullptr && !resolved->deletedAt)
                {
                    resolved->deletedAt = now;
                }
            }
        }

        // Sweeps: expired grace records, pending TTL, verdict liveness.
        std::vector<std::string> expiredContainerIds;
        std::vector<std::uint64_t> expiredInodes;
        for (auto& [inode, entry] : m_byCgroup)
        {
            if (const auto* resolved = std::get_if<ResolvedEntry>(&entry))
            {
                if (resolved->deletedAt && now - *resolved->deletedAt >= REMOVAL_GRACE)
                {
                    expiredContainerIds.push_back(resolved->record->containerId);
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
        for (const auto& containerId : expiredContainerIds)
        {
            eraseResolvedLocked(containerId);
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

    void MetadataStore::upsertResolved(ContainerRecord record)
    {
        std::unique_lock lock(m_mutex);
        insertResolvedLocked(std::move(record));
    }

    void MetadataStore::insertResolvedLocked(ContainerRecord record)
    {
        eraseResolvedLocked(record.containerId);

        auto shared = std::make_shared<const ContainerRecord>(std::move(record));

        m_byContainerId[shared->containerId] = shared;
        if (!shared->podUid.empty())
        {
            m_byPodContainer[podContainerKey(shared->podUid, shared->containerName)] = shared;
        }
        if (shared->cgroupId != 0)
        {
            const auto it = m_byCgroup.find(shared->cgroupId);
            if (it != m_byCgroup.end() && std::holds_alternative<VerdictEntry>(it->second))
            {
                m_logger(LogLevel::info,
                         "Verdict for cgroup inode " + std::to_string(shared->cgroupId) + " superseded by container " +
                             shared->containerId);
            }
            ResolvedEntry entry;
            entry.record = shared;
            m_byCgroup[shared->cgroupId] = std::move(entry);
        }
    }

    void MetadataStore::eraseResolvedLocked(const std::string& containerId)
    {
        const auto it = m_byContainerId.find(containerId);
        if (it == m_byContainerId.end())
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
        m_byContainerId.erase(it);
    }

} // namespace wazuh::container_instances
