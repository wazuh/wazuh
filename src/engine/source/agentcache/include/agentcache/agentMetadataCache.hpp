// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _AGENTCACHE_AGENT_METADATA_CACHE_HPP
#define _AGENTCACHE_AGENT_METADATA_CACHE_HPP

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <agentcache/canonicalAgentId.hpp>
#include <base/json.hpp>
#include <fastmetrics/iMetric.hpp>
#include <fastmetrics/metric_names.hpp>
#include <fastmetrics/registry.hpp>

namespace agentcache
{

/**
 * @brief Thread-safe cache for parsed agent metadata (header JSON).
 *
 * When many small batches arrive for the same agent, each batch carries an identical
 * header JSON string.  Parsing each one into a json::Json object is expensive because
 * RapidJSON allocates a memory pool (growing in ~64 KB chunks) per Document.  This cache
 * deduplicates headers by agent ID, returning a shared_ptr to an already-parsed header
 * when the content has not changed.  Headers are stored as compact documents
 * (json::Json::compact — small allocator, ~4 KB instead of 64 KB per header), since they
 * live for as long as the agent is active.
 *
 * Lookups are O(1) by canonical agent ID, followed by a full header-byte comparison. A hit
 * reuses a document already validated for that ID. Exactly one entry is kept per agent — a
 * new valid header for a known agent replaces the previous one.
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
        Retrieved, ///< An entry with identical content already existed (cache hit, no parse).
        Inserted,  ///< No previous entry for this agent; a newly parsed one was stored.
        Updated,   ///< The agent had a different header; its entry was replaced.
    };

    /// Result of getOrParse(): the shared header plus what happened in the cache.
    using GetResult = std::pair<std::shared_ptr<const json::Json>, Operation>;
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    /**
     * @brief Construct the cache with a given time-to-live for entries.
     * @param ttl Entries not accessed within this duration are eligible for eviction.
     * @param clock Clock used to timestamp entries and calculate TTL expiry.
     *
     * @note fastmetrics::registerManager() must have been called before construction, as the
     *       cache resolves its metric counters from the metrics manager.
     */
    explicit AgentMetadataCache(
        std::chrono::seconds ttl, ClockFn clock = []() { return std::chrono::steady_clock::now(); })
        : m_ttl(ttl)
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
     * @return Parsed header and Retrieved, Inserted or Updated outcome.
     * @throws std::runtime_error On invalid JSON, a non-canonical ID, or an absent, ambiguous,
     *         non-string or mismatched identity in the header. Existing entries remain unchanged.
     */
    GetResult getOrParse(std::string_view trustedAgentId, std::string_view headerStr)
    {
        if (!isCanonicalAgentId(trustedAgentId))
        {
            throw std::runtime_error("AgentMetadataCache: trusted agent ID must be canonical");
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
            throw std::runtime_error("AgentMetadataCache: missing, repeated or non-string /wazuh/agent/id in header");
        }
        if (headerId != trustedAgentId)
        {
            throw std::runtime_error("AgentMetadataCache: header agent ID does not match the trusted agent ID");
        }

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
        auto entry = std::make_shared<CacheEntry>();
        entry->header = std::move(parsed);
        entry->headerStr.assign(headerStr);
        entry->lastUsed.store(nowRep(), std::memory_order_relaxed);
        m_byId[agentId] = entry;

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
     * @brief Temporary compatibility path for callers that do not yet pass the trusted ID.
     *
     * Derives the ID from the body, parsing even on a cache hit. Remove this overload once
     * the ingest handler passes the producer's carrier; it is not an authentication boundary.
     */
    GetResult getOrParse(std::string_view headerStr)
    {
        const auto parsed = json::Json::compact(headerStr);
        std::string_view id;
        if (parsed.getUniqueString(id, AGENT_ID_PATH) != json::RetGet::Success)
        {
            throw std::runtime_error("AgentMetadataCache: missing, repeated or non-string /wazuh/agent/id in header");
        }
        return getOrParse(id, headerStr);
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

    /**
     * @brief Remove all cached entries.
     */
    void clear()
    {
        std::unique_lock lock(m_mutex);
        m_byId.clear();
    }

private:
    static inline const json::PointerPath AGENT_ID_PATH {"/wazuh/agent/id"}; ///< JSON pointer path to the agent ID.
    static constexpr std::size_t CACHE_INITIAL_CAPACITY = 1024; ///< Initial capacity for the cache's index.

    std::chrono::steady_clock::rep nowRep() const { return m_clock().time_since_epoch().count(); }

    struct CacheEntry
    {
        std::shared_ptr<const json::Json> header;                 ///< Parsed header JSON.
        std::string headerStr;                                    ///< Compared byte for byte on cache lookups.
        std::atomic<std::chrono::steady_clock::rep> lastUsed {0}; ///< Last access timestamp for eviction.
    };

    std::chrono::seconds m_ttl;        ///< Time-to-live for entries.
    ClockFn m_clock;                   ///< Clock used for cache entry age calculations.
    mutable std::shared_mutex m_mutex; ///< Protects m_byId for thread-safe access.
    std::unordered_map<std::string, std::shared_ptr<CacheEntry>> m_byId; ///< agentId -> entry (one per agent).

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
