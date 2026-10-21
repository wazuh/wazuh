// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _AGENTCACHE_AGENT_METADATA_CACHE_HPP
#define _AGENTCACHE_AGENT_METADATA_CACHE_HPP

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <agentcache/canonicalAgentId.hpp>
#include <agentcache/identityError.hpp>
#include <base/json.hpp>
#include <fastmetrics/iMetric.hpp>
#include <fastmetrics/metric_names.hpp>
#include <fastmetrics/registry.hpp>

namespace agentcache
{

/// Retained-cache limits; zero independently disables each constraint.
struct Limits
{
    static constexpr std::size_t MAX_ENTRIES =
        std::min<std::uint64_t>(std::numeric_limits<std::size_t>::max(), std::uint64_t {1} << 32);
    static constexpr std::size_t MAX_BYTES =
        std::min<std::uint64_t>(std::numeric_limits<std::size_t>::max(), std::uint64_t {1} << 40);

    std::size_t maxEntries {0};
    std::size_t maxBytes {0};
};

/**
 * @brief Thread-safe cache for parsed agent metadata (header JSON).
 *
 * When many small batches arrive for the same agent, each batch carries an identical
 * header JSON string.  Parsing each one into a json::Json object is expensive because
 * RapidJSON allocates a memory pool (growing in ~64 KB chunks) per Document.  This cache
 * deduplicates headers by agent ID, returning a shared_ptr to an already-parsed header
 * when the content has not changed. Headers use json::Json::compact; their actual pool
 * capacity is included in the retained-byte accounting.
 *
 * Lookups are O(1) by canonical agent ID, followed by a full header-byte comparison. A hit
 * reuses a document already validated for that ID. Exactly one entry is kept per agent — a
 * new valid header replaces the previous one if it fits the configured limits. A valid header
 * that does not fit is returned without retention; an older entry for that agent is removed.
 * Admission does not evict unrelated agents. Only the TTL sweep evicts stale entries.
 *
 * Accounted bytes include header/id lengths, document pool capacity and a fixed entry overhead.
 * They exclude allocator rounding, spare string capacities, map buckets, pool bookkeeping,
 * transient candidates and documents held by callers after removal. This is not a process-memory
 * limit: concurrent parsing and returned shared pointers can keep additional memory alive.
 *
 * Thread safety: multiple readers can call getOrParse() concurrently under a shared lock;
 * the per-entry last-used timestamp is a relaxed atomic so it can be refreshed without an
 * exclusive lock.  Inserts, replacements and eviction take an exclusive lock.
 *
 * Metrics: the cache records its own fastmetrics counters (hits, insertions, updates and
 * evictions). This requires fastmetrics::registerManager() to have been called beforehand.
 * The instantaneous entry count is exposed as a pull metric via registerCacheMetrics().
 */
class AgentMetadataCache
{
public:
    /**
     * @brief Outcome of a getOrParse() call against the cache.
     */
    enum class Operation
    {
        Retrieved,        ///< An entry with identical content already existed (cache hit, no parse).
        Inserted,         ///< No previous entry for this agent; a newly parsed one was stored.
        Updated,          ///< The agent had a different header; its entry was replaced.
        BypassedCapacity, ///< Valid metadata returned without retention because admission did not fit.
    };

    /// Result of getOrParse(): the shared header plus what happened in the cache.
    using GetResult = std::pair<std::shared_ptr<const json::Json>, Operation>;
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    /**
     * @brief Construct the cache with a given time-to-live for entries.
     * @param ttl Entries not accessed within this duration are eligible for eviction.
     * @param limits Entry/byte limits, each zero for unlimited; bounded by Limits::MAX_ENTRIES/MAX_BYTES.
     * @param clock Clock used to timestamp entries and calculate TTL expiry.
     *
     * @note fastmetrics::registerManager() must have been called before construction, as the
     *       cache resolves its metric counters from the metrics manager.
     */
    explicit AgentMetadataCache(
        std::chrono::seconds ttl, Limits limits = {}, ClockFn clock = []() { return std::chrono::steady_clock::now(); })
        : m_limits(limits)
        , m_ttl(ttl)
        , m_clock(std::move(clock))
        , m_hitsCounter(fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_HITS))
        , m_insertionsCounter(fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_INSERTIONS))
        , m_updatesCounter(fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_UPDATES))
        , m_evictionsCounter(fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_EVICTIONS))
    {
        if (ttl <= std::chrono::seconds(0) || ttl > std::chrono::seconds(3600 * 24)) // 1 day
        {
            throw std::invalid_argument("AgentMetadataCache: TTL must be > 0 and <= 86400 seconds");
        }
        if (!m_clock)
        {
            throw std::invalid_argument("AgentMetadataCache: clock function must be valid");
        }
        if (limits.maxEntries > Limits::MAX_ENTRIES || limits.maxBytes > Limits::MAX_BYTES)
        {
            throw std::invalid_argument("AgentMetadataCache: limits exceed supported entry/byte bounds");
        }
        m_byId.reserve(CACHE_INITIAL_CAPACITY);
    }

    /**
     * @brief Look up or parse a header bound to a canonical, trusted agent ID.
     *
     * A hit requires the same ID and identical bytes. On a miss, the identity path must be unique
     * and its string value must equal the trusted ID before anything is stored. Parsing and
     * validation run outside the lock; admission is double-checked under the exclusive lock.
     *
     * @param trustedAgentId Canonical identity supplied by the authenticated or local producer.
     * @param headerStr Raw JSON after "H " in the NDJson batch.
     * @return Parsed header and Retrieved, Inserted, Updated or BypassedCapacity outcome.
     * Capacity bypass still parses and validates identity; it never returns an older header.
     * @throws IdentityError On a non-canonical ID or an absent, ambiguous, non-string or mismatched
     *         identity in the header. Existing entries remain unchanged.
     * @throws std::runtime_error On invalid JSON.
     */
    GetResult getOrParse(std::string_view trustedAgentId, std::string_view headerStr)
    {
        if (!isCanonicalAgentId(trustedAgentId))
        {
            throw IdentityError("AgentMetadataCache: trusted agent ID must be canonical");
        }
        const std::string agentId(trustedAgentId);

        // Fast path: only an already validated (ID, header bytes) pair can hit.
        {
            std::shared_lock lock(m_mutex);
            auto it = m_byId.find(agentId);
            if (it != m_byId.end() && std::string_view(it->second->headerStr) == headerStr)
            {
                it->second->lastUsed.store(nowRep(), std::memory_order_relaxed);
                m_hitsCounter->add(1);
                return {it->second->header, Operation::Retrieved};
            }
        }

        auto parsed = std::make_shared<const json::Json>(json::Json::compact(headerStr));
        std::string_view headerId;
        if (parsed->getUniqueString(headerId, AGENT_ID_PATH) != json::RetGet::Success)
        {
            throw IdentityError("AgentMetadataCache: missing, repeated or non-string /wazuh/agent/id in header");
        }
        if (headerId != trustedAgentId)
        {
            throw IdentityError("AgentMetadataCache: header agent ID does not match the trusted agent ID");
        }

        const auto candidateBytes = entryBytes(headerStr.size(), agentId.size(), parsed->getAllocatedMemory());
        std::unique_lock lock(m_mutex);
        auto it = m_byId.find(agentId);
        // Another thread may have admitted the same pair while this call parsed it.
        if (it != m_byId.end() && std::string_view(it->second->headerStr) == headerStr)
        {
            it->second->lastUsed.store(nowRep(), std::memory_order_relaxed);
            m_hitsCounter->add(1);
            return {it->second->header, Operation::Retrieved};
        }
        const bool agentExisted = it != m_byId.end();
        const auto retainedBytes = m_accountedBytes - (agentExisted ? it->second->accountedBytes : 0);
        const auto retainedEntries = m_byId.size() - (agentExisted ? 1 : 0);
        const auto bytesAfter = candidateBytes ? checkedAdd(retainedBytes, *candidateBytes) : std::nullopt;
        const bool fitsEntries = retainedEntries < std::numeric_limits<std::size_t>::max()
                                 && (m_limits.maxEntries == 0 || retainedEntries < m_limits.maxEntries);
        const bool fitsBytes = bytesAfter && (m_limits.maxBytes == 0 || *bytesAfter <= m_limits.maxBytes);
        if (!fitsEntries || !fitsBytes)
        {
            if (agentExisted)
            {
                m_byId.erase(it);
                m_accountedBytes = retainedBytes;
            }
            return {std::move(parsed), Operation::BypassedCapacity};
        }

        // Prepare all potentially throwing state before publishing a replacement. Failed allocation
        // or clock evaluation must leave the old entry and running total intact.
        auto entry = std::make_shared<CacheEntry>(std::move(parsed), headerStr, *candidateBytes, nowRep());
        if (agentExisted)
        {
            it->second = entry;
        }
        else
        {
            m_byId.emplace(agentId, entry);
        }
        m_accountedBytes = *bytesAfter;

        if (agentExisted)
        {
            m_updatesCounter->add(1);
        }
        else
        {
            m_insertionsCounter->add(1);
        }
        return {entry->header, agentExisted ? Operation::Updated : Operation::Inserted};
    }

    /**
     * @brief Remove entries that have not been accessed within the TTL.
     *
     * Two-phase to minimise the time the map is held under the exclusive lock, since reads
     * (getOrParse hits) are the hot path:
     *  - Phase 1 (shared lock): scan and collect the agent IDs of stale entries. Read-only, so
     *    concurrent getOrParse hits are not blocked; only the slow (insert/replace) path waits.
     *  - Phase 2 (exclusive lock): erase the collected candidates. Each is re-validated because a
     *    concurrent getOrParse may have refreshed or replaced the entry between the two phases.
     *
     * @return Number of entries evicted.
     */
    std::size_t evictStale()
    {
        const auto nowNs = nowRep();
        const auto ttlNs = std::chrono::duration_cast<std::chrono::steady_clock::duration>(m_ttl).count();

        const auto isStale = [nowNs, ttlNs](const CacheEntry& entry)
        {
            return (nowNs - entry.lastUsed.load(std::memory_order_relaxed)) > ttlNs;
        };

        // Phase 1: collect stale candidates under a shared lock (no mutation).
        std::vector<std::string> staleAgents;
        {
            std::shared_lock lock(m_mutex);
            for (const auto& [agentId, entry] : m_byId)
            {
                if (isStale(*entry))
                {
                    staleAgents.push_back(agentId);
                }
            }
        }

        if (staleAgents.empty())
        {
            return 0;
        }

        // Phase 2: erase the candidates under an exclusive lock, re-validating each (a concurrent
        // getOrParse may have refreshed its timestamp or replaced the entry since phase 1).
        std::size_t evicted = 0;
        {
            std::unique_lock lock(m_mutex);
            for (const auto& agentId : staleAgents)
            {
                auto it = m_byId.find(agentId);
                if (it == m_byId.end() || !isStale(*it->second))
                {
                    continue;
                }
                m_accountedBytes -= it->second->accountedBytes;
                m_byId.erase(it);
                ++evicted;
            }
        }

        if (evicted > 0)
        {
            m_evictionsCounter->add(evicted);
        }
        return evicted;
    }

    /**
     * @brief Return the number of cached entries (one per agent).
     */
    std::size_t size() const
    {
        std::shared_lock lock(m_mutex);
        return m_byId.size();
    }

    /// Accounted retained state, excluding documents kept alive only by callers.
    std::size_t accountedBytes() const
    {
        std::shared_lock lock(m_mutex);
        return m_accountedBytes;
    }

    /**
     * @brief Remove all cached entries and release their accounted bytes.
     */
    void clear()
    {
        std::unique_lock lock(m_mutex);
        m_byId.clear();
        m_accountedBytes = 0;
    }

private:
    friend struct AgentMetadataCacheTestAccess;
    static inline const json::PointerPath AGENT_ID_PATH {"/wazuh/agent/id"}; ///< JSON pointer path to the agent ID.
    static constexpr std::size_t CACHE_INITIAL_CAPACITY = 1024; ///< Initial capacity for the cache's index.

    std::chrono::steady_clock::rep nowRep() const { return m_clock().time_since_epoch().count(); }

    struct CacheEntry
    {
        CacheEntry(std::shared_ptr<const json::Json> parsed,
                   std::string_view raw,
                   std::size_t bytes,
                   std::chrono::steady_clock::rep lastAccess)
            : header(std::move(parsed))
            , headerStr(raw)
            , lastUsed(lastAccess)
            , accountedBytes(bytes)
        {
        }

        std::shared_ptr<const json::Json> header;
        std::string headerStr;
        std::atomic<std::chrono::steady_clock::rep> lastUsed;
        const std::size_t accountedBytes;
    };
    using CacheMap = std::unordered_map<std::string, std::shared_ptr<CacheEntry>>;

    // Fixed estimate: entry, document and map value objects, plus six pointers for a node's
    // link/hash and two shared-owner control blocks. Not measured allocator/RSS usage.
    static constexpr std::size_t ENTRY_OVERHEAD =
        sizeof(CacheEntry) + sizeof(json::Json) + sizeof(CacheMap::value_type) + 6 * sizeof(void*);

    static std::optional<std::size_t> checkedAdd(std::size_t left, std::size_t right)
    {
        if (right > std::numeric_limits<std::size_t>::max() - left)
        {
            return std::nullopt;
        }
        return left + right;
    }

    static std::optional<std::size_t> entryBytes(std::size_t header, std::size_t id, std::size_t pool)
    {
        auto cost = checkedAdd(ENTRY_OVERHEAD, header);
        if (cost)
        {
            cost = checkedAdd(*cost, id);
        }
        return cost ? checkedAdd(*cost, pool) : std::nullopt;
    }

    const Limits m_limits;
    std::chrono::seconds m_ttl;
    ClockFn m_clock;
    mutable std::shared_mutex m_mutex; ///< Protects the index and running byte total.
    CacheMap m_byId;
    std::size_t m_accountedBytes {0};

    // Metric counters (process-wide singletons resolved from the fastmetrics manager).
    std::shared_ptr<fastmetrics::ICounter> m_hitsCounter;       ///< agent.cache.hits (Retrieved).
    std::shared_ptr<fastmetrics::ICounter> m_insertionsCounter; ///< agent.cache.insertions (Inserted).
    std::shared_ptr<fastmetrics::ICounter> m_updatesCounter;    ///< agent.cache.updates (Updated).
    std::shared_ptr<fastmetrics::ICounter> m_evictionsCounter;  ///< agent.cache.evictions (evictStale).
};

/**
 * @brief Register the instantaneous "agent.cache.entries" pull metric for a cache instance.
 *
 * Uses a weak_ptr so the metrics manager never keeps the cache alive nor dereferences it
 * after destruction (mirrors the engine's other pull-metric registrations). Safe to call
 * once after the cache is constructed; re-registering the same metric name is a no-op.
 *
 * @param cache The cache whose size() should be exposed.
 */
inline void registerCacheMetrics(const std::shared_ptr<AgentMetadataCache>& cache)
{
    std::weak_ptr<AgentMetadataCache> weakCache = cache;
    FASTMETRICS_PULL(std::size_t,
                     fastmetrics::names::AGENT_CACHE_ENTRIES,
                     [weakCache]()
                     {
                         auto c = weakCache.lock();
                         return c ? c->size() : std::size_t {0};
                     });
}

} // namespace agentcache

#endif // _AGENTCACHE_AGENT_METADATA_CACHE_HPP
