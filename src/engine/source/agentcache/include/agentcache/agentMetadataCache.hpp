#ifndef _AGENTCACHE_AGENT_METADATA_CACHE_HPP
#define _AGENTCACHE_AGENT_METADATA_CACHE_HPP

#include <algorithm>
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
 * Lookups are O(1): a secondary index maps the header content hash directly to its entry,
 * so the hot path never scans the map.  Hits are verified by comparing the full header
 * string (guarding against hash collisions).  Exactly one entry is kept per agent — a new
 * header for a known agent replaces the previous one.
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
        m_byAgent.reserve(CACHE_INITIAL_CAPACITY);
        m_byHash.reserve(CACHE_INITIAL_CAPACITY);
    }

    /**
     * @brief Look up or parse a header JSON string.
     *
     * If an entry with the same content already exists, the cached shared_ptr is returned
     * (avoiding a new json::Json allocation).  Otherwise the header is parsed, the agent ID
     * extracted and validated, and the entry is stored, replacing any previous header for
     * the same agent.  The corresponding metric counter (hits/insertions/updates) is recorded.
     *
     * @param headerStr Raw JSON string of the header (e.g., the text after "H " in the NDJson batch).
     * @return GetResult Pair of {shared pointer to the parsed header, Operation describing whether
     *         the entry was Retrieved (hit), Inserted (new agent) or Updated (header replaced)}.
     * @throws std::runtime_error If headerStr is not valid JSON, or if `/wazuh/agent/id`
     *         is missing or not a string containing a positive numeric value.
     */
    GetResult getOrParse(std::string_view headerStr)
    {
        const std::size_t hash = std::hash<std::string_view> {}(headerStr);

        // Fast path: shared (read) lock — O(1) lookup by content hash.
        {
            std::shared_lock lock(m_mutex);
            auto it = m_byHash.find(hash);
            if (it != m_byHash.end() && std::string_view(it->second->headerStr) == headerStr)
            {
                it->second->lastUsed.store(nowRep(), std::memory_order_relaxed);
                m_hitsCounter->add(1);
                return {it->second->header, Operation::Retrieved};
            }
        }

        // Slow path: parse JSON and extract agent ID (done outside the lock). Parsed directly
        // into a compact document (small allocator) since the header lives as long as the agent.
        auto parsed = std::make_shared<const json::Json>(json::Json::compact(headerStr));

        std::string_view agentIdSv;
        if (parsed->getString(agentIdSv, AGENT_ID_PATH) != json::RetGet::Success)
        {
            throw std::runtime_error("AgentMetadataCache: missing or non-string /wazuh/agent/id in header");
        }

        if (agentIdSv.empty()
            || !std::all_of(agentIdSv.begin(), agentIdSv.end(), [](char c) { return c >= '0' && c <= '9'; }))
        {
            throw std::runtime_error("AgentMetadataCache: /wazuh/agent/id must be a non-empty positive numeric string");
        }

        std::string agentId(agentIdSv);

        // Exclusive lock — insert or replace.
        {
            std::unique_lock lock(m_mutex);

            // Double-check: another thread may have inserted this exact header while we parsed.
            auto hashIt = m_byHash.find(hash);
            if (hashIt != m_byHash.end() && std::string_view(hashIt->second->headerStr) == headerStr)
            {
                hashIt->second->lastUsed.store(nowRep(), std::memory_order_relaxed);
                m_hitsCounter->add(1);
                return {hashIt->second->header, Operation::Retrieved};
            }

            // Drop the agent's previous header (if any) from the hash index to avoid leaks.
            // Whether an entry already existed decides Updated vs Inserted.
            auto agentIt = m_byAgent.find(agentId);
            const bool agentExisted = (agentIt != m_byAgent.end());
            if (agentExisted)
            {
                m_byHash.erase(agentIt->second->headerHash);
            }

            auto entry = std::make_shared<CacheEntry>();
            entry->header = std::move(parsed);
            entry->headerHash = hash;
            entry->headerStr.assign(headerStr);
            entry->lastUsed.store(nowRep(), std::memory_order_relaxed);

            m_byAgent[agentId] = entry;
            m_byHash[hash] = entry;

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
    }

    /**
     * @brief Remove entries that have not been accessed within the TTL.
     *
     * Two-phase to minimise the time the maps are held under the exclusive lock, since reads
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
            for (const auto& [agentId, entry] : m_byAgent)
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
                auto it = m_byAgent.find(agentId);
                if (it == m_byAgent.end() || !isStale(*it->second))
                {
                    continue;
                }
                m_byHash.erase(it->second->headerHash);
                m_byAgent.erase(it);
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
        return m_byAgent.size();
    }

    /**
     * @brief Remove all cached entries.
     */
    void clear()
    {
        std::unique_lock lock(m_mutex);
        m_byAgent.clear();
        m_byHash.clear();
    }

private:
    static inline const json::PointerPath AGENT_ID_PATH {"/wazuh/agent/id"}; ///< JSON pointer path to the agent ID.
    static constexpr std::size_t CACHE_INITIAL_CAPACITY = 1024; ///< Initial capacity for the cache's internal maps.

    std::chrono::steady_clock::rep nowRep() const { return m_clock().time_since_epoch().count(); }

    struct CacheEntry
    {
        std::shared_ptr<const json::Json> header; ///< Parsed header JSON.
        std::size_t headerHash {0};               ///< Hash of the header string (used for O(1) lookup in m_byHash).
        std::string headerStr;                    ///< Verified against lookups to avoid hash collisions.
        std::atomic<std::chrono::steady_clock::rep> lastUsed {0}; ///< Last access timestamp for eviction.
    };

    std::chrono::seconds m_ttl;        ///< Time-to-live for entries.
    ClockFn m_clock;                   ///< Clock used for cache entry age calculations.
    mutable std::shared_mutex m_mutex; ///< Protects m_byAgent and m_byHash for thread-safe access.
    std::unordered_map<std::string, std::shared_ptr<CacheEntry>> m_byAgent; ///< agentId -> entry (one per agent).
    std::unordered_map<std::size_t, std::shared_ptr<CacheEntry>> m_byHash;  ///< content hash -> entry (O(1) lookup).

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
