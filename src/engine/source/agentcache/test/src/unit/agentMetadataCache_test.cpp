// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <limits>
#include <optional>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

#include <agentcache/agentMetadataCache.hpp>
#include <fastmetrics/iMetric.hpp>
#include <fastmetrics/metric_names.hpp>
#include <fastmetrics/registry.hpp>

using namespace agentcache;
using namespace std::chrono_literals;

using Op = AgentMetadataCache::Operation;

namespace agentcache
{
struct AgentMetadataCacheTestAccess
{
    static std::size_t overhead() { return AgentMetadataCache::ENTRY_OVERHEAD; }

    static bool consistent(const AgentMetadataCache& cache)
    {
        std::shared_lock lock(cache.m_mutex);
        std::size_t sum = 0;
        for (const auto& [id, entry] : cache.m_byId)
        {
            if (!entry || entry->accountedBytes > std::numeric_limits<std::size_t>::max() - sum)
            {
                return false;
            }
            sum += entry->accountedBytes;
        }
        return sum == cache.m_accountedBytes
               && (cache.m_limits.maxEntries == 0 || cache.m_byId.size() <= cache.m_limits.maxEntries)
               && (cache.m_limits.maxBytes == 0 || sum <= cache.m_limits.maxBytes);
    }

    static std::shared_ptr<const json::Json> retained(const AgentMetadataCache& cache, const std::string& id)
    {
        std::shared_lock lock(cache.m_mutex);
        const auto it = cache.m_byId.find(id);
        return it == cache.m_byId.end() ? nullptr : it->second->header;
    }

    static auto add(std::size_t a, std::size_t b) { return AgentMetadataCache::checkedAdd(a, b); }
    static auto cost(std::size_t header, std::size_t id, std::size_t pool)
    {
        return AgentMetadataCache::entryBytes(header, id, pool);
    }
};
} // namespace agentcache

namespace
{
// Register the fastmetrics manager once for all tests: the cache resolves its counters from it.
struct FastMetricsInit
{
    FastMetricsInit() { fastmetrics::registerManager(); }
};
static FastMetricsInit fastMetricsInit_;

// Valid header for agent "001"
const std::string HEADER_AGENT_001 =
    R"({"wazuh":{"agent":{"id":"001","name":"agent-one","version":"5.0.0","host":{"hostname":"host1","os":{"name":"Ubuntu","platform":"linux"}}}}})";

// Valid header for agent "002"
const std::string HEADER_AGENT_002 =
    R"({"wazuh":{"agent":{"id":"002","name":"agent-two","version":"5.0.0","host":{"hostname":"host2","os":{"name":"Debian","platform":"linux"}}}}})";

// Updated header for agent "001" (changed hostname)
const std::string HEADER_AGENT_001_UPDATED =
    R"({"wazuh":{"agent":{"id":"001","name":"agent-one","version":"5.0.0","host":{"hostname":"host1-new","os":{"name":"Ubuntu","platform":"linux"}}}}})";

// Header with missing agent id
const std::string HEADER_MISSING_ID = R"({"wazuh":{"agent":{"name":"no-id-agent"}}})";

// Header with non-numeric agent id
const std::string HEADER_NON_NUMERIC_ID = R"({"wazuh":{"agent":{"id":"abc","name":"bad-agent"}}})";

// Header with negative agent id
const std::string HEADER_NEGATIVE_ID = R"({"wazuh":{"agent":{"id":"-1","name":"bad-agent"}}})";

// Header with empty agent id
const std::string HEADER_EMPTY_ID = R"({"wazuh":{"agent":{"id":"","name":"bad-agent"}}})";

// Invalid JSON
const std::string HEADER_INVALID_JSON = R"({not valid json at all)";

struct FakeClock
{
    AgentMetadataCache::ClockFn fn()
    {
        return [this]()
        {
            return now;
        };
    }

    void advance(std::chrono::steady_clock::duration duration) { now += duration; }

    std::chrono::steady_clock::time_point now {std::chrono::steady_clock::time_point {}};
};

// A JSON failure is a parse error, not an identity rejection (the API counts only the latter).
template<typename Call>
void expectNonIdentityError(Call&& call)
{
    try
    {
        call();
        ADD_FAILURE() << "expected std::runtime_error";
    }
    catch (const IdentityError& e)
    {
        ADD_FAILURE() << "unexpected IdentityError: " << e.what();
    }
    catch (const std::runtime_error&)
    {
    }
}

} // namespace

class AgentMetadataCacheTest : public ::testing::Test
{
protected:
    AgentMetadataCache cache {60s}; // 60s TTL for most tests
};

TEST_F(AgentMetadataCacheTest, GetOrParse_NewHeader_ParsesAndCaches)
{
    auto result = cache.getOrParse("001", HEADER_AGENT_001);

    ASSERT_NE(result.first, nullptr);
    EXPECT_EQ(result.second, Op::Inserted);
    EXPECT_EQ(cache.size(), 1);

    // Verify the parsed content is correct
    std::string_view agentId;
    ASSERT_EQ(result.first->getString(agentId, "/wazuh/agent/id"), json::RetGet::Success);
    EXPECT_EQ(agentId, "001");
}

TEST_F(AgentMetadataCacheTest, GetOrParse_SameHeader_ReturnsCachedPtr)
{
    auto first = cache.getOrParse("001", HEADER_AGENT_001);
    auto second = cache.getOrParse("001", HEADER_AGENT_001);

    // Same pointer — no re-parse
    EXPECT_EQ(first.first.get(), second.first.get());
    EXPECT_EQ(first.second, Op::Inserted);
    EXPECT_EQ(second.second, Op::Retrieved);
    EXPECT_EQ(cache.size(), 1);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_DifferentHeaderSameAgent_ReplacesEntry)
{
    auto first = cache.getOrParse("001", HEADER_AGENT_001);
    auto updated = cache.getOrParse("001", HEADER_AGENT_001_UPDATED);

    // Different pointer — content changed, so a new parse happened
    EXPECT_NE(first.first.get(), updated.first.get());
    EXPECT_EQ(first.second, Op::Inserted);
    EXPECT_EQ(updated.second, Op::Updated);
    EXPECT_EQ(cache.size(), 1);

    // Verify the new content
    std::string_view hostname;
    ASSERT_EQ(updated.first->getString(hostname, "/wazuh/agent/host/hostname"), json::RetGet::Success);
    EXPECT_EQ(hostname, "host1-new");
}

TEST_F(AgentMetadataCacheTest, GetOrParse_DifferentAgents_SeparateEntries)
{
    auto r1 = cache.getOrParse("001", HEADER_AGENT_001);
    auto r2 = cache.getOrParse("002", HEADER_AGENT_002);

    EXPECT_NE(r1.first.get(), r2.first.get());
    EXPECT_EQ(r1.second, Op::Inserted);
    EXPECT_EQ(r2.second, Op::Inserted);
    EXPECT_EQ(cache.size(), 2);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_InvalidJson_Throws)
{
    expectNonIdentityError([&]() { cache.getOrParse("001", HEADER_INVALID_JSON); });
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_MissingAgentId_Throws)
{
    EXPECT_THROW(cache.getOrParse("001", HEADER_MISSING_ID), IdentityError);
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_NonNumericAgentId_Throws)
{
    EXPECT_THROW(cache.getOrParse("001", HEADER_NON_NUMERIC_ID), IdentityError);
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_NegativeAgentId_Throws)
{
    EXPECT_THROW(cache.getOrParse("001", HEADER_NEGATIVE_ID), IdentityError);
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_EmptyAgentId_Throws)
{
    EXPECT_THROW(cache.getOrParse("001", HEADER_EMPTY_ID), IdentityError);
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, EvictStale_RemovesExpiredEntries)
{
    FakeClock fakeClock;
    AgentMetadataCache shortCache(1s, {}, fakeClock.fn());

    shortCache.getOrParse("001", HEADER_AGENT_001);
    EXPECT_EQ(shortCache.size(), 1);

    fakeClock.advance(1s + 1ns);

    auto evicted = shortCache.evictStale();
    EXPECT_EQ(evicted, 1);
    EXPECT_EQ(shortCache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, EvictStale_KeepsRecentEntries)
{
    FakeClock fakeClock;
    AgentMetadataCache shortCache(2s, {}, fakeClock.fn());

    shortCache.getOrParse("001", HEADER_AGENT_001);
    shortCache.getOrParse("002", HEADER_AGENT_002);

    // Advance partially (less than TTL).
    fakeClock.advance(500ms);

    // Access agent 001 again to refresh its timestamp.
    shortCache.getOrParse("001", HEADER_AGENT_001);

    // Advance until agent 002 has expired but 001 has not.
    fakeClock.advance(1500ms + 1ns);

    auto evicted = shortCache.evictStale();
    EXPECT_EQ(evicted, 1);
    EXPECT_EQ(shortCache.size(), 1);
}

TEST_F(AgentMetadataCacheTest, Size_ReflectsEntries)
{
    EXPECT_EQ(cache.size(), 0);
    cache.getOrParse("001", HEADER_AGENT_001);
    EXPECT_EQ(cache.size(), 1);
    cache.getOrParse("002", HEADER_AGENT_002);
    EXPECT_EQ(cache.size(), 2);
}

TEST_F(AgentMetadataCacheTest, Clear_EmptiesCache)
{
    cache.getOrParse("001", HEADER_AGENT_001);
    cache.getOrParse("002", HEADER_AGENT_002);
    EXPECT_EQ(cache.size(), 2);

    cache.clear();
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, ThreadSafety_ConcurrentGetOrParse)
{
    constexpr int NUM_THREADS = 8;
    constexpr int ITERATIONS = 1000;

    // Generate headers for multiple agents
    std::vector<std::string> headers;
    std::vector<std::string> ids;
    for (int i = 1; i <= 10; ++i)
    {
        std::string id = std::to_string(i);
        // Pad to 3 digits
        while (id.size() < 3)
        {
            id = "0" + id;
        }
        ids.push_back(id);
        headers.push_back(R"({"wazuh":{"agent":{"id":")" + id + R"(","name":"agent-)" + id + R"("}}})");
    }

    std::atomic<int> errors {0};
    std::vector<std::thread> threads;
    threads.reserve(NUM_THREADS);

    for (int t = 0; t < NUM_THREADS; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                for (int i = 0; i < ITERATIONS; ++i)
                {
                    try
                    {
                        auto idx = (t * ITERATIONS + i) % headers.size();
                        auto result = cache.getOrParse(ids[idx], headers[idx]);
                        if (!result.first)
                        {
                            errors.fetch_add(1);
                        }
                    }
                    catch (...)
                    {
                        errors.fetch_add(1);
                    }
                }
            });
    }

    for (auto& th : threads)
    {
        th.join();
    }

    EXPECT_EQ(errors.load(), 0);
    EXPECT_EQ(cache.size(), 10);
}

// Exercises the agent-id index: many distinct agents
// must each be a stable O(1) hit returning the same shared_ptr on re-lookup.
TEST_F(AgentMetadataCacheTest, AgentIndex_ManyAgentsStableHits)
{
    constexpr int NUM_AGENTS = 100;

    std::vector<std::string> headers;
    std::vector<std::string> ids;
    std::vector<std::shared_ptr<const json::Json>> firstPtrs;
    for (int i = 1; i <= NUM_AGENTS; ++i)
    {
        std::string id = std::to_string(i);
        while (id.size() < 3)
        {
            id = "0" + id;
        }
        ids.push_back(id);
        headers.push_back(R"({"wazuh":{"agent":{"id":")" + id + R"(","name":"agent-)" + id + R"("}}})");
        auto inserted = cache.getOrParse(id, headers.back());
        EXPECT_EQ(inserted.second, Op::Inserted);
        firstPtrs.push_back(inserted.first);
    }

    ASSERT_EQ(cache.size(), NUM_AGENTS);

    // Re-lookup each header: must be a cache hit returning the exact same pointer.
    for (int i = 0; i < NUM_AGENTS; ++i)
    {
        auto again = cache.getOrParse(ids[i], headers[i]);
        EXPECT_EQ(again.first.get(), firstPtrs[i].get());
        EXPECT_EQ(again.second, Op::Retrieved);
    }
    EXPECT_EQ(cache.size(), NUM_AGENTS);
}

// When an agent changes its header and later reverts to the original, the cache must keep
// exactly one entry for that agent and the reverted header must still resolve correctly
// without returning the old document retained by a caller.
TEST_F(AgentMetadataCacheTest, TrustedIdHeaderUpdateReplacesEntry)
{
    auto original = cache.getOrParse("001", HEADER_AGENT_001);
    EXPECT_EQ(original.second, Op::Inserted);
    ASSERT_EQ(cache.size(), 1);

    // Change the header for the same agent -> replaces the entry.
    auto updated = cache.getOrParse("001", HEADER_AGENT_001_UPDATED);
    EXPECT_NE(original.first.get(), updated.first.get());
    EXPECT_EQ(updated.second, Op::Updated);
    EXPECT_EQ(cache.size(), 1);

    // Revert to the original header string -> the agent already had a (different) entry, so
    // this is another replacement (Updated), still one entry, and it parses correctly.
    auto reverted = cache.getOrParse("001", HEADER_AGENT_001);
    EXPECT_EQ(reverted.second, Op::Updated);
    EXPECT_NE(reverted.first, original.first);
    EXPECT_NE(reverted.first, updated.first);
    EXPECT_EQ(cache.size(), 1);

    std::string_view hostname;
    ASSERT_EQ(reverted.first->getString(hostname, "/wazuh/agent/host/hostname"), json::RetGet::Success);
    EXPECT_EQ(hostname, "host1");
}

// Headers are stored as compact json documents (small allocator): a fraction of the default
// 64 KB rapidjson chunk, and the compactness survives the shared_ptr storage and cache hits.
TEST_F(AgentMetadataCacheTest, StoresCompactHeaders)
{
    auto inserted = cache.getOrParse("001", HEADER_AGENT_001);
    ASSERT_NE(inserted.first, nullptr);
    EXPECT_LE(inserted.first->getAllocatedMemory(), json::Json::COMPACT_INITIAL_CAPACITY);

    // Content is intact...
    std::string_view id;
    ASSERT_EQ(inserted.first->getString(id, "/wazuh/agent/id"), json::RetGet::Success);
    EXPECT_EQ(id, "001");

    // ...and a cache hit returns the same compact document.
    auto hit = cache.getOrParse("001", HEADER_AGENT_001);
    EXPECT_EQ(hit.first.get(), inserted.first.get());
    EXPECT_LE(hit.first->getAllocatedMemory(), json::Json::COMPACT_INITIAL_CAPACITY);
}

// The cache records its own hit/insertion/update counters. Uses baseline deltas because the
// counters are process-wide singletons shared across every test in this binary.
TEST_F(AgentMetadataCacheTest, Metrics_RecordsHitsInsertionsUpdates)
{
    auto& mgr = fastmetrics::manager();
    auto hits = mgr.getOrCreateCounter(fastmetrics::names::AGENT_CACHE_HITS);
    auto insertions = mgr.getOrCreateCounter(fastmetrics::names::AGENT_CACHE_INSERTIONS);
    auto updates = mgr.getOrCreateCounter(fastmetrics::names::AGENT_CACHE_UPDATES);

    const auto hits0 = hits->get();
    const auto insertions0 = insertions->get();
    const auto updates0 = updates->get();

    cache.getOrParse("001", HEADER_AGENT_001);         // new agent          -> Inserted
    cache.getOrParse("001", HEADER_AGENT_001);         // identical header    -> Retrieved (hit)
    cache.getOrParse("001", HEADER_AGENT_001_UPDATED); // same agent, new hdr -> Updated

    EXPECT_EQ(insertions->get() - insertions0, 1u);
    EXPECT_EQ(hits->get() - hits0, 1u);
    EXPECT_EQ(updates->get() - updates0, 1u);
}

// evictStale() records the number of evicted entries into the evictions counter.
TEST_F(AgentMetadataCacheTest, Metrics_RecordsEvictions)
{
    auto evictions = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_EVICTIONS);
    const auto evictions0 = evictions->get();

    FakeClock fakeClock;
    AgentMetadataCache shortCache(1s, {}, fakeClock.fn());
    shortCache.getOrParse("001", HEADER_AGENT_001);
    shortCache.getOrParse("002", HEADER_AGENT_002);

    fakeClock.advance(1s + 1ns);
    const auto evicted = shortCache.evictStale();

    EXPECT_EQ(evicted, 2u);
    EXPECT_EQ(evictions->get() - evictions0, 2u);
}

TEST_F(AgentMetadataCacheTest, ThreadSafety_ConcurrentGetOrParseWithEviction)
{
    using Clock = std::chrono::steady_clock;
    std::atomic<Clock::rep> ticks {0};
    AgentMetadataCache shortCache(1s, {}, [&]() { return Clock::time_point(Clock::duration(ticks.load())); });
    constexpr int NUM_THREADS = 4;
    constexpr int ITERATIONS = 500;

    std::vector<std::string> headers;
    std::vector<std::string> ids;
    for (int i = 1; i <= 5; ++i)
    {
        std::string id = std::to_string(i);
        while (id.size() < 3)
        {
            id = "0" + id;
        }
        ids.push_back(id);
        headers.push_back(R"({"wazuh":{"agent":{"id":")" + id + R"(","name":"agent-)" + id + R"("}}})");
    }

    std::atomic<int> errors {0};
    std::atomic<int> writersLeft {NUM_THREADS};
    std::atomic<std::size_t> evicted {0};
    std::vector<std::thread> threads;

    // Writer threads
    for (int t = 0; t < NUM_THREADS; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                for (int i = 0; i < ITERATIONS; ++i)
                {
                    try
                    {
                        auto idx = (t * ITERATIONS + i) % headers.size();
                        shortCache.getOrParse(ids[idx], headers[idx]);
                    }
                    catch (...)
                    {
                        errors.fetch_add(1);
                    }
                }
                writersLeft.fetch_sub(1);
            });
    }

    // Evictor thread: every round ages all entries past the TTL before sweeping
    threads.emplace_back(
        [&]()
        {
            do
            {
                ticks.fetch_add(std::chrono::duration_cast<Clock::duration>(2s).count());
                evicted.fetch_add(shortCache.evictStale());
                if (!AgentMetadataCacheTestAccess::consistent(shortCache))
                    errors.fetch_add(1);
                std::this_thread::yield();
            } while (writersLeft.load() != 0);
        });

    for (auto& th : threads)
    {
        th.join();
    }

    // A final sweep empties the cache, so at least one eviction is always observed
    ticks.fetch_add(std::chrono::duration_cast<Clock::duration>(2s).count());
    evicted.fetch_add(shortCache.evictStale());
    EXPECT_EQ(errors.load(), 0);
    EXPECT_GT(evicted.load(), 0u);
    EXPECT_EQ(shortCache.size(), 0u);
    EXPECT_EQ(shortCache.accountedBytes(), 0u);
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(shortCache));
}

TEST_F(AgentMetadataCacheTest, TrustedIdHitRefreshesTtl)
{
    FakeClock clock;
    AgentMetadataCache shortCache(2s, {}, clock.fn());
    auto first = shortCache.getOrParse("001", HEADER_AGENT_001);
    clock.advance(1500ms);
    auto hit = shortCache.getOrParse("001", HEADER_AGENT_001);
    EXPECT_EQ(hit.second, Op::Retrieved);
    EXPECT_EQ(first.first, hit.first);
    clock.advance(1s);
    EXPECT_EQ(shortCache.evictStale(), 0u);
    clock.advance(1001ms);
    EXPECT_EQ(shortCache.evictStale(), 1u);
    std::string_view id;
    ASSERT_EQ(first.first->getString(id, "/wazuh/agent/id"), json::RetGet::Success);
    EXPECT_EQ(id, "001"); // A caller may still own the document after TTL eviction.
}

TEST_F(AgentMetadataCacheTest, TrustedIdMismatchCannotReuseHeader)
{
    auto first = cache.getOrParse("001", HEADER_AGENT_001);
    auto hits = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_HITS);
    auto insertions = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_INSERTIONS);
    const auto hitsBefore = hits->get();
    const auto insertionsBefore = insertions->get();
    EXPECT_THROW(cache.getOrParse("002", HEADER_AGENT_001), IdentityError);
    EXPECT_EQ(cache.size(), 1u);
    EXPECT_EQ(hits->get(), hitsBefore);
    EXPECT_EQ(insertions->get(), insertionsBefore);
    EXPECT_EQ(cache.getOrParse("001", HEADER_AGENT_001).first, first.first);
    EXPECT_EQ(cache.getOrParse("002", HEADER_AGENT_002).second, Op::Inserted);
}

TEST_F(AgentMetadataCacheTest, TrustedIdRejectsInvalidIdentityPath)
{
    const std::vector<std::string> invalid {R"({})",
                                            R"([])",
                                            R"({"wazuh":[]})",
                                            R"({"wazuh":{"agent":[]}})",
                                            R"({"wazuh":{"agent":{"id":1}}})",
                                            R"({"wazuh":{"agent":{"id":"002"}}})",
                                            R"({"wazuh":{"agent":{"id":"1"}}})",
                                            R"({"wazuh":{"agent":{"id":"001","id":"001"}}})",
                                            R"({"wazuh":{"agent":{"id":"001","id":"002"}}})",
                                            R"({"wazuh":{"agent":{"id":"001"},"agent":{"id":"001"}}})",
                                            R"({"wazuh":{"agent":{"id":"001"}},"wazuh":{"agent":{"id":"001"}}})",
                                            R"({"wazuh":{"agent":{"id":"001"}},"\u0077azuh":{"agent":{"id":"002"}}})",
                                            R"({"wazuh":{"agent":{"id":"001\u0000"}}})"};
    const auto original = cache.getOrParse("001", HEADER_AGENT_001);
    for (const auto& header : invalid)
    {
        SCOPED_TRACE(header);
        EXPECT_THROW(cache.getOrParse("001", header), IdentityError);
        EXPECT_EQ(cache.size(), 1u);
        EXPECT_EQ(cache.getOrParse("001", HEADER_AGENT_001).first, original.first);
    }
}

TEST_F(AgentMetadataCacheTest, TrustedIdRejectsNoncanonicalId)
{
    const auto first = cache.getOrParse("001", HEADER_AGENT_001);
    for (const auto id : {"", "1", "0001", "abc", "4294967296", "10000000000"})
    {
        EXPECT_THROW(cache.getOrParse(id, HEADER_AGENT_001), IdentityError) << id;
        EXPECT_EQ(cache.size(), 1u);
    }
    EXPECT_EQ(cache.getOrParse("001", HEADER_AGENT_001).first, first.first);
}

TEST_F(AgentMetadataCacheTest, AcceptsOffPathMetadataWithinJsonDepthLimit)
{
    const std::string prefix =
        R"({"wazuh":{"agent":{"id":"001"},"cluster":1,"cluster":2},"wazuh\u0000x":{},"wazuh/agent":{},"x":)";
    const auto header =
        prefix + std::string(json::Json::MAX_DEPTH - 1, '[') + "0" + std::string(json::Json::MAX_DEPTH - 1, ']') + "}";
    EXPECT_NO_THROW(cache.getOrParse("001", header));
    const auto tooDeep =
        prefix + std::string(json::Json::MAX_DEPTH, '[') + "0" + std::string(json::Json::MAX_DEPTH, ']') + "}";
    expectNonIdentityError([&]() { cache.getOrParse("001", tooDeep); });
    EXPECT_EQ(cache.size(), 1u);
}

TEST_F(AgentMetadataCacheTest, ThreadSafety_ConcurrentReplacementsKeepReturnedHeaders)
{
    std::atomic<bool> start {false};
    std::atomic<int> errors {0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                const auto name = std::to_string(t);
                const auto header = R"({"wazuh":{"agent":{"id":"001","name":")" + name + R"("}}})";
                while (!start.load())
                {
                    std::this_thread::yield();
                }
                for (int i = 0; i < 500; ++i)
                {
                    try
                    {
                        const auto result = cache.getOrParse("001", header);
                        std::string_view actual;
                        if (result.first->getString(actual, "/wazuh/agent/name") != json::RetGet::Success
                            || actual != name)
                        {
                            ++errors;
                        }
                    }
                    catch (...)
                    {
                        ++errors;
                    }
                }
            });
    }
    threads.emplace_back(
        [&]()
        {
            while (!start.load())
            {
                std::this_thread::yield();
            }
            for (int i = 0; i < 500; ++i)
            {
                cache.clear();
                cache.evictStale();
            }
        });
    start.store(true);
    for (auto& thread : threads)
    {
        thread.join();
    }
    EXPECT_EQ(errors.load(), 0);
    EXPECT_LE(cache.size(), 1u);
}

namespace
{
std::string sizedHeader(const std::string& id, std::size_t padding)
{
    return R"({"wazuh":{"agent":{"id":")" + id + R"(","name":")" + std::string(padding, 'x') + R"("}}})";
}

std::size_t costOf(const std::string& id, const std::string& header)
{
    return header.size() + id.size() + json::Json::compact(header).getAllocatedMemory()
           + AgentMetadataCacheTestAccess::overhead();
}

void expectHeader(const std::shared_ptr<const json::Json>& header, const std::string& id, std::size_t padding)
{
    ASSERT_NE(header, nullptr);
    std::string_view value;
    ASSERT_EQ(header->getString(value, "/wazuh/agent/id"), json::RetGet::Success);
    EXPECT_EQ(value, id);
    ASSERT_EQ(header->getString(value, "/wazuh/agent/name"), json::RetGet::Success);
    EXPECT_EQ(value, std::string(padding, 'x'));
}
} // namespace

TEST_F(AgentMetadataCacheTest, AccountsRetainedComponentsExactly)
{
    std::size_t expected = 0;
    for (const auto id : {"001", "4294967295"})
    {
        const auto header = sizedHeader(id, 32);
        const auto first = cache.getOrParse(id, header);
        expected += header.size() + std::string_view(id).size() + first.first->getAllocatedMemory()
                    + AgentMetadataCacheTestAccess::overhead();
        EXPECT_EQ(cache.accountedBytes(), expected);
        EXPECT_EQ(cache.getOrParse(id, header).first, first.first);
        EXPECT_EQ(cache.accountedBytes(), expected);
    }
    const auto changed = sizedHeader("001", 512);
    expected = expected - costOf("001", sizedHeader("001", 32)) + costOf("001", changed);
    EXPECT_EQ(cache.getOrParse("001", changed).second, Op::Updated);
    EXPECT_EQ(cache.accountedBytes(), expected);
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(cache));
}

TEST_F(AgentMetadataCacheTest, ZeroLimitsKeepUnlimitedAdmission)
{
    const auto a = sizedHeader("001", 16);
    const auto b = sizedHeader("002", 16);
    for (const auto limits : {Limits {}, Limits {2, 0}, Limits {0, costOf("001", a) + costOf("002", b)}})
    {
        AgentMetadataCache bounded(60s, limits);
        EXPECT_EQ(bounded.getOrParse("001", a).second, Op::Inserted);
        EXPECT_EQ(bounded.getOrParse("002", b).second, Op::Inserted);
        EXPECT_EQ(bounded.size(), 2u);
        EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
    }
    for (int i = 100; i < 120; ++i)
    {
        const auto id = std::to_string(i);
        EXPECT_EQ(cache.getOrParse(id, sizedHeader(id, 16)).second, Op::Inserted);
    }
    EXPECT_EQ(cache.size(), 20u);
}

TEST_F(AgentMetadataCacheTest, EntryLimitBypassesWithoutEvicting)
{
    AgentMetadataCache bounded(60s, {2, 0});
    const auto a = bounded.getOrParse("001", sizedHeader("001", 16)).first;
    const auto b = bounded.getOrParse("002", sizedHeader("002", 16)).first;
    const auto before = bounded.accountedBytes();
    const auto c = bounded.getOrParse("003", sizedHeader("003", 16));
    const auto again = bounded.getOrParse("003", sizedHeader("003", 16));
    EXPECT_EQ(c.second, Op::BypassedCapacity);
    EXPECT_EQ(again.second, Op::BypassedCapacity);
    EXPECT_NE(c.first, again.first);
    expectHeader(c.first, "003", 16);
    EXPECT_EQ(bounded.size(), 2u);
    EXPECT_EQ(bounded.accountedBytes(), before);
    EXPECT_EQ(AgentMetadataCacheTestAccess::retained(bounded, "001"), a);
    EXPECT_EQ(AgentMetadataCacheTestAccess::retained(bounded, "002"), b);
    EXPECT_EQ(AgentMetadataCacheTestAccess::retained(bounded, "003"), nullptr);
}

TEST_F(AgentMetadataCacheTest, ByteLimitAcceptsExactFit)
{
    const auto a = sizedHeader("001", 16);
    const auto b = sizedHeader("002", 16);
    const auto exact = costOf("001", a) + costOf("002", b);
    for (const auto budget : {exact, exact - 1})
    {
        AgentMetadataCache bounded(60s, {0, budget});
        EXPECT_EQ(bounded.getOrParse("001", a).second, Op::Inserted);
        EXPECT_EQ(bounded.getOrParse("002", b).second, budget == exact ? Op::Inserted : Op::BypassedCapacity);
        EXPECT_EQ(bounded.accountedBytes(), budget == exact ? exact : costOf("001", a));
        EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
    }
}

TEST_F(AgentMetadataCacheTest, BothLimitsRejectTheSameAdmission)
{
    const auto a = sizedHeader("001", 16);
    AgentMetadataCache bounded(60s, {1, costOf("001", a)});
    const auto first = bounded.getOrParse("001", a).first;
    const auto large = bounded.getOrParse("002", sizedHeader("002", 8192));
    EXPECT_EQ(large.second, Op::BypassedCapacity);
    expectHeader(large.first, "002", 8192);
    EXPECT_EQ(AgentMetadataCacheTestAccess::retained(bounded, "001"), first);
    EXPECT_EQ(bounded.size(), 1u);
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
}

TEST_F(AgentMetadataCacheTest, OversizedEntryIsReturnedWithoutRetention)
{
    AgentMetadataCache bounded(60s, {0, 1});
    const auto result = bounded.getOrParse("001", sizedHeader("001", 16384));
    EXPECT_EQ(result.second, Op::BypassedCapacity);
    expectHeader(result.first, "001", 16384);
    EXPECT_EQ(bounded.size(), 0u);
    EXPECT_EQ(bounded.accountedBytes(), 0u);
}

TEST_F(AgentMetadataCacheTest, ReplacementUsesNetDelta)
{
    const auto small = sizedHeader("001", 16);
    const auto large = sizedHeader("001", 256);
    const auto other = sizedHeader("002", 16);
    const auto budget = costOf("001", large) + costOf("002", other);
    AgentMetadataCache bounded(60s, {2, budget});
    const auto old = bounded.getOrParse("001", small).first;
    bounded.getOrParse("002", other);
    const auto result = bounded.getOrParse("001", large);
    EXPECT_EQ(result.second, Op::Updated);
    EXPECT_NE(result.first, old);
    EXPECT_EQ(bounded.size(), 2u);
    EXPECT_EQ(bounded.accountedBytes(), budget);
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
}

TEST_F(AgentMetadataCacheTest, UnfittingReplacementReleasesOldEntry)
{
    const auto a = sizedHeader("001", 16);
    const auto b = sizedHeader("002", 16);
    AgentMetadataCache bounded(60s, {2, costOf("001", a) + costOf("002", b)});
    const auto old = bounded.getOrParse("001", a).first;
    const auto other = bounded.getOrParse("002", b).first;
    const auto result = bounded.getOrParse("001", sizedHeader("001", 8192));
    EXPECT_EQ(result.second, Op::BypassedCapacity);
    EXPECT_NE(result.first, old);
    expectHeader(result.first, "001", 8192);
    expectHeader(old, "001", 16);
    EXPECT_EQ(bounded.size(), 1u);
    EXPECT_EQ(bounded.accountedBytes(), costOf("002", b));
    EXPECT_EQ(AgentMetadataCacheTestAccess::retained(bounded, "001"), nullptr);
    EXPECT_EQ(AgentMetadataCacheTestAccess::retained(bounded, "002"), other);
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
}

TEST_F(AgentMetadataCacheTest, ShrinkingReplacementReleasesBytes)
{
    const auto large = sizedHeader("001", 8192);
    const auto small = sizedHeader("001", 16);
    const auto b = sizedHeader("002", 16);
    const auto c = sizedHeader("003", 16);
    AgentMetadataCache bounded(60s, {0, costOf("001", large) + costOf("002", b)});
    bounded.getOrParse("001", large);
    bounded.getOrParse("002", b);
    EXPECT_EQ(bounded.getOrParse("001", small).second, Op::Updated);
    EXPECT_EQ(bounded.accountedBytes(), costOf("001", small) + costOf("002", b));
    EXPECT_EQ(bounded.getOrParse("003", c).second, Op::Inserted);
    EXPECT_EQ(bounded.accountedBytes(), costOf("001", small) + costOf("002", b) + costOf("003", c));
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
}

TEST_F(AgentMetadataCacheTest, InvalidReplacementPreservesAccounting)
{
    const auto a = sizedHeader("001", 16);
    AgentMetadataCache bounded(60s, {1, costOf("001", a)});
    const auto old = bounded.getOrParse("001", a).first;
    for (const auto& invalid : {HEADER_INVALID_JSON,
                                HEADER_MISSING_ID,
                                HEADER_NON_NUMERIC_ID,
                                sizedHeader("002", 8192),
                                std::string(R"({"wazuh":{"agent":{"id":"001","id":"002"}}})")})
    {
        EXPECT_THROW(bounded.getOrParse("001", invalid), std::runtime_error);
        EXPECT_EQ(bounded.accountedBytes(), costOf("001", a));
        EXPECT_EQ(bounded.size(), 1u);
        EXPECT_EQ(AgentMetadataCacheTestAccess::retained(bounded, "001"), old);
        EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
    }
}

TEST_F(AgentMetadataCacheTest, ClockFailurePreservesAccounting)
{
    const auto a = sizedHeader("001", 16);
    auto changed = a;
    changed.replace(changed.find(std::string(16, 'x')), 16, std::string(16, 'y'));
    bool failClock = false;
    AgentMetadataCache bounded(60s,
                               {1, costOf("001", a)},
                               [&]()
                               {
                                   if (failClock)
                                       throw std::runtime_error("clock unavailable");
                                   return std::chrono::steady_clock::time_point {};
                               });
    const auto original = bounded.getOrParse("001", a).first;
    auto updates = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_UPDATES);
    const auto before = updates->get();
    failClock = true;
    EXPECT_THROW(bounded.getOrParse("001", changed), std::runtime_error);
    EXPECT_EQ(updates->get(), before);
    EXPECT_EQ(AgentMetadataCacheTestAccess::retained(bounded, "001"), original);
    EXPECT_EQ(bounded.accountedBytes(), costOf("001", a));
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
}

TEST_F(AgentMetadataCacheTest, EvictionAndClearReleaseAccountedBytes)
{
    FakeClock clock;
    AgentMetadataCache bounded(1s, {2, 0}, clock.fn());
    const auto a = sizedHeader("001", 16);
    const auto b = sizedHeader("002", 16);
    bounded.getOrParse("001", a);
    bounded.getOrParse("002", b);
    clock.advance(1s);
    EXPECT_EQ(bounded.evictStale(), 0u);
    EXPECT_EQ(bounded.getOrParse("001", a).second, Op::Retrieved);
    clock.advance(1ns);
    EXPECT_EQ(bounded.evictStale(), 1u);
    EXPECT_EQ(bounded.accountedBytes(), costOf("001", a));
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
    bounded.clear();
    bounded.clear();
    EXPECT_EQ(bounded.size(), 0u);
    EXPECT_EQ(bounded.accountedBytes(), 0u);
    EXPECT_EQ(bounded.getOrParse("002", b).second, Op::Inserted);
    EXPECT_EQ(bounded.accountedBytes(), costOf("002", b));
}

TEST_F(AgentMetadataCacheTest, ReturnedHeadersSurviveRemoval)
{
    const auto initial = sizedHeader("001", 128);
    for (int action = 0; action < 4; ++action)
    {
        FakeClock clock;
        AgentMetadataCache bounded(1s, {1, costOf("001", initial)}, clock.fn());
        const auto old = bounded.getOrParse("001", initial).first;
        if (action < 2)
        {
            const auto padding = action == 0 ? 16u : 8192u;
            const auto result = bounded.getOrParse("001", sizedHeader("001", padding));
            EXPECT_EQ(result.second, action == 0 ? Op::Updated : Op::BypassedCapacity);
            bounded.clear();
            expectHeader(result.first, "001", padding);
        }
        else if (action == 2)
        {
            clock.advance(1s + 1ns);
            EXPECT_EQ(bounded.evictStale(), 1u);
        }
        else
        {
            bounded.clear();
        }
        expectHeader(old, "001", 128);
        EXPECT_EQ(bounded.accountedBytes(), 0u);
    }
}

TEST_F(AgentMetadataCacheTest, BypassLeavesExistingCountersUnchanged)
{
    auto& mgr = fastmetrics::manager();
    const std::vector<std::shared_ptr<fastmetrics::ICounter>> counters {
        mgr.getOrCreateCounter(fastmetrics::names::AGENT_CACHE_HITS),
        mgr.getOrCreateCounter(fastmetrics::names::AGENT_CACHE_INSERTIONS),
        mgr.getOrCreateCounter(fastmetrics::names::AGENT_CACHE_UPDATES),
        mgr.getOrCreateCounter(fastmetrics::names::AGENT_CACHE_EVICTIONS)};
    const auto a = sizedHeader("001", 16);
    AgentMetadataCache bounded(60s, {1, costOf("001", a)});
    bounded.getOrParse("001", a);
    std::vector<std::uint64_t> before;
    for (const auto& counter : counters) before.push_back(counter->get());
    EXPECT_EQ(bounded.getOrParse("002", sizedHeader("002", 16)).second, Op::BypassedCapacity);
    EXPECT_EQ(bounded.getOrParse("001", sizedHeader("001", 8192)).second, Op::BypassedCapacity);
    bounded.clear();
    for (std::size_t i = 0; i < counters.size(); ++i) EXPECT_EQ(counters[i]->get(), before[i]);
}

TEST_F(AgentMetadataCacheTest, RejectsLimitsAboveSupportedBounds)
{
    EXPECT_NO_THROW((AgentMetadataCache(60s, {Limits::MAX_ENTRIES, Limits::MAX_BYTES})));
    EXPECT_NO_THROW((AgentMetadataCache(60s, {})));
    if (Limits::MAX_ENTRIES < std::numeric_limits<std::size_t>::max())
    {
        EXPECT_THROW((AgentMetadataCache(60s, {Limits::MAX_ENTRIES + 1, 0})), std::invalid_argument);
    }
    if (Limits::MAX_BYTES < std::numeric_limits<std::size_t>::max())
    {
        EXPECT_THROW((AgentMetadataCache(60s, {0, Limits::MAX_BYTES + 1})), std::invalid_argument);
    }
    EXPECT_THROW((AgentMetadataCache(60s, {}, {})), std::invalid_argument);
}

TEST_F(AgentMetadataCacheTest, AccountingArithmeticCannotWrap)
{
    const auto max = std::numeric_limits<std::size_t>::max();
    EXPECT_EQ(AgentMetadataCacheTestAccess::add(max, 0), max);
    EXPECT_EQ(AgentMetadataCacheTestAccess::add(max - 1, 1), max);
    EXPECT_FALSE(AgentMetadataCacheTestAccess::add(max, 1));
    const auto available = max - AgentMetadataCacheTestAccess::overhead();
    EXPECT_EQ(AgentMetadataCacheTestAccess::cost(available - 3, 3, 0), max);
    EXPECT_FALSE(AgentMetadataCacheTestAccess::cost(available - 3, 3, 1));
    EXPECT_FALSE(AgentMetadataCacheTestAccess::cost(max, 3, 1));
    EXPECT_FALSE(AgentMetadataCacheTestAccess::cost(0, max, 1));
}

TEST_F(AgentMetadataCacheTest, ConcurrentIdenticalMissesConverge)
{
    AgentMetadataCache bounded(60s, {1, 0});
    const auto header = sizedHeader("001", 128);
    auto insertions = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_INSERTIONS);
    const auto before = insertions->get();
    std::atomic<int> ready {0};
    std::atomic<bool> start {false};
    std::vector<AgentMetadataCache::GetResult> results(8);
    std::vector<std::thread> threads;
    for (std::size_t t = 0; t < results.size(); ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                ready.fetch_add(1);
                while (!start.load()) std::this_thread::yield();
                results[t] = bounded.getOrParse("001", header);
            });
    }
    while (ready.load() != static_cast<int>(results.size())) std::this_thread::yield();
    start.store(true);
    for (auto& thread : threads) thread.join();
    std::size_t inserted = 0;
    for (const auto& result : results)
    {
        inserted += result.second == Op::Inserted;
        EXPECT_TRUE(result.second == Op::Inserted || result.second == Op::Retrieved);
        EXPECT_EQ(result.first, results.front().first);
    }
    EXPECT_EQ(inserted, 1u);
    EXPECT_EQ(insertions->get() - before, 1u);
    EXPECT_EQ(bounded.accountedBytes(), costOf("001", header));
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
}

TEST_F(AgentMetadataCacheTest, ThreadSafety_BoundedMutationsKeepAccountingConsistent)
{
    using Clock = std::chrono::steady_clock;
    const auto budget = 2 * costOf("001", sizedHeader("001", 128));
    std::atomic<Clock::rep> ticks {0};
    AgentMetadataCache bounded(1s, {3, budget}, [&]() { return Clock::time_point(Clock::duration(ticks.load())); });
    std::atomic<bool> start {false};
    std::atomic<int> errors {0};
    std::atomic<int> bypasses {0};
    std::atomic<int> writersLeft {8};
    std::atomic<bool> maintenanceStarted {false};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                while (!start.load() || !maintenanceStarted.load()) std::this_thread::yield();
                for (int i = 0; i < 200; ++i)
                {
                    const auto id = "00" + std::to_string(1 + (t + i) % 5);
                    const auto padding = i % 3 == 0 ? 8192u : 128u;
                    const auto header = sizedHeader(id, padding);
                    try
                    {
                        for (int repeat = 0; repeat < 2; ++repeat)
                        {
                            const auto result = bounded.getOrParse(id, header);
                            bypasses.fetch_add(result.second == Op::BypassedCapacity);
                            std::string_view actualId, actualName;
                            if (result.first->getString(actualId, "/wazuh/agent/id") != json::RetGet::Success
                                || actualId != id
                                || result.first->getString(actualName, "/wazuh/agent/name") != json::RetGet::Success
                                || actualName.size() != padding)
                            {
                                ++errors;
                            }
                        }
                        if (!AgentMetadataCacheTestAccess::consistent(bounded))
                            ++errors;
                    }
                    catch (...)
                    {
                        ++errors;
                    }
                }
                writersLeft.fetch_sub(1);
            });
    }
    threads.emplace_back(
        [&]()
        {
            while (!start.load()) std::this_thread::yield();
            maintenanceStarted.store(true);
            std::size_t i = 0;
            do
            {
                ticks.fetch_add(std::chrono::duration_cast<Clock::duration>(2s).count());
                bounded.evictStale();
                if (i % 3 == 0)
                    bounded.clear();
                if (!AgentMetadataCacheTestAccess::consistent(bounded))
                    ++errors;
                ++i;
                std::this_thread::yield();
            } while (writersLeft.load() != 0);
        });
    start.store(true);
    for (auto& thread : threads) thread.join();
    EXPECT_EQ(errors.load(), 0);
    EXPECT_GT(bypasses.load(), 0);
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
    bounded.clear();
    EXPECT_EQ(bounded.size(), 0u);
    EXPECT_EQ(bounded.accountedBytes(), 0u);
}

TEST_F(AgentMetadataCacheTest, CleanIntervalRange)
{
    EXPECT_THROW(validateCleanInterval(0), std::invalid_argument);
    EXPECT_THROW(validateCleanInterval(86401), std::invalid_argument);
    EXPECT_THROW(validateCleanInterval(std::numeric_limits<std::size_t>::max()), std::invalid_argument);
    for (const auto seconds : {1u, 60u, 86400u}) EXPECT_EQ(validateCleanInterval(seconds), seconds);
}

TEST_F(AgentMetadataCacheTest, BypassMetricsTrackEachConstraint)
{
    auto entries = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_BYPASS_MAX_ENTRIES);
    auto bytes = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_BYPASS_MAX_BYTES);
    EXPECT_EQ(entries->type(), fastmetrics::MetricType::COUNTER);
    EXPECT_EQ(bytes->type(), fastmetrics::MetricType::COUNTER);
    const auto a = sizedHeader("001", 16);
    for (const auto limits : {Limits {1, 0}, Limits {0, costOf("001", a)}, Limits {1, costOf("001", a)}})
    {
        AgentMetadataCache bounded(60s, limits);
        const auto entriesBefore = entries->get();
        const auto bytesBefore = bytes->get();
        EXPECT_EQ(bounded.getOrParse("001", a).second, Op::Inserted);
        EXPECT_EQ(bounded.getOrParse("001", a).second, Op::Retrieved);
        for (const auto& invalid : {HEADER_INVALID_JSON, HEADER_MISSING_ID, sizedHeader("002", 8192)})
            EXPECT_THROW(bounded.getOrParse("001", invalid), std::runtime_error);
        EXPECT_EQ(entries->get(), entriesBefore);
        EXPECT_EQ(bytes->get(), bytesBefore);
        EXPECT_EQ(bounded.getOrParse("002", sizedHeader("002", 16)).second, Op::BypassedCapacity);
        EXPECT_EQ(entries->get(), entriesBefore + (limits.maxEntries != 0));
        EXPECT_EQ(bytes->get(), bytesBefore + (limits.maxBytes != 0));
        if (limits.maxBytes != 0)
        {
            EXPECT_EQ(bounded.getOrParse("001", sizedHeader("001", 8192)).second, Op::BypassedCapacity);
            EXPECT_EQ(entries->get(), entriesBefore + (limits.maxEntries != 0));
            EXPECT_EQ(bytes->get(), bytesBefore + 2);
            EXPECT_EQ(bounded.size(), 0u);
            EXPECT_EQ(bounded.accountedBytes(), 0u);
        }
    }
}

TEST_F(AgentMetadataCacheTest, RetentionPullMetricsFollowMutationsAndDestruction)
{
    // Pull metrics are registered first-wins: drop the ones a previous run bound to a destroyed cache
    fastmetrics::manager().clear();
    FakeClock clock;
    const auto small = sizedHeader("001", 16);
    const auto large = sizedHeader("001", 512);
    const Limits limits {1, costOf("001", large)};
    auto bounded = std::make_shared<AgentMetadataCache>(1s, limits, clock.fn());
    const std::weak_ptr<AgentMetadataCache> weak = bounded;
    registerCacheMetrics(bounded);
    const auto names = {fastmetrics::names::AGENT_CACHE_ENTRIES,
                        fastmetrics::names::AGENT_CACHE_BYTES,
                        fastmetrics::names::AGENT_CACHE_MAX_ENTRIES,
                        fastmetrics::names::AGENT_CACHE_MAX_BYTES};
    for (const auto name : names)
    {
        const auto metric = fastmetrics::manager().get(name);
        ASSERT_NE(metric, nullptr);
        EXPECT_EQ(metric->type(), fastmetrics::MetricType::PULL);
        metric->enable();
    }
    std::vector<std::shared_ptr<fastmetrics::ICounter>> counters;
    for (const auto name : {fastmetrics::names::AGENT_CACHE_HITS,
                            fastmetrics::names::AGENT_CACHE_INSERTIONS,
                            fastmetrics::names::AGENT_CACHE_UPDATES,
                            fastmetrics::names::AGENT_CACHE_EVICTIONS})
    {
        counters.push_back(fastmetrics::manager().getOrCreateCounter(name));
    }
    const auto snapshot = [&]()
    {
        std::vector<uint64_t> values;
        for (const auto& counter : counters) values.push_back(counter->get());
        return values;
    };
    auto last = snapshot();
    // deltas: hits, insertions, updates, evictions since the previous step
    const auto expectPulls = [&](std::size_t count, std::size_t bytes, std::vector<uint64_t> deltas)
    {
        EXPECT_EQ(fastmetrics::manager().get(fastmetrics::names::AGENT_CACHE_ENTRIES)->value(), count);
        EXPECT_EQ(fastmetrics::manager().get(fastmetrics::names::AGENT_CACHE_BYTES)->value(), bytes);
        EXPECT_EQ(fastmetrics::manager().get(fastmetrics::names::AGENT_CACHE_MAX_ENTRIES)->value(), limits.maxEntries);
        EXPECT_EQ(fastmetrics::manager().get(fastmetrics::names::AGENT_CACHE_MAX_BYTES)->value(), limits.maxBytes);
        const auto now = snapshot();
        for (std::size_t i = 0; i < now.size(); ++i) EXPECT_EQ(now[i] - last[i], deltas[i]) << "counter " << i;
        last = now;
    };
    expectPulls(0, 0, {0, 0, 0, 0});
    EXPECT_EQ(bounded->getOrParse("001", small).second, Op::Inserted);
    expectPulls(1, costOf("001", small), {0, 1, 0, 0});
    EXPECT_EQ(bounded->getOrParse("001", small).second, Op::Retrieved);
    expectPulls(1, costOf("001", small), {1, 0, 0, 0});
    EXPECT_EQ(bounded->getOrParse("001", large).second, Op::Updated);
    expectPulls(1, costOf("001", large), {0, 0, 1, 0});
    EXPECT_EQ(bounded->getOrParse("002", sizedHeader("002", 16)).second, Op::BypassedCapacity);
    expectPulls(1, costOf("001", large), {0, 0, 0, 0});
    EXPECT_EQ(bounded->getOrParse("001", small).second, Op::Updated);
    expectPulls(1, costOf("001", small), {0, 0, 1, 0});
    // A bypass that drops the old version is not an eviction
    EXPECT_EQ(bounded->getOrParse("001", sizedHeader("001", 8192)).second, Op::BypassedCapacity);
    expectPulls(0, 0, {0, 0, 0, 0});
    bounded->getOrParse("001", small);
    clock.advance(1s + 1ns);
    EXPECT_EQ(bounded->evictStale(), 1u);
    expectPulls(0, 0, {0, 1, 0, 1});
    bounded->getOrParse("001", small);
    bounded->clear();
    expectPulls(0, 0, {0, 1, 0, 0});
    bounded->getOrParse("001", small);
    bounded.reset();
    EXPECT_TRUE(weak.expired());
    for (const auto name : names) EXPECT_EQ(fastmetrics::manager().get(name)->value(), 0);
}

TEST_F(AgentMetadataCacheTest, FullCacheBypassesAbsentAgentsWithoutExclusiveLock)
{
    const auto cached = sizedHeader("001", 16);
    const auto absent = sizedHeader("002", 16);
    AgentMetadataCache bounded(60s, {1, 0});
    const auto retained = bounded.getOrParse("001", cached).first;
    const auto bytes = bounded.accountedBytes();
    auto entries = fastmetrics::manager().getOrCreateCounter(fastmetrics::names::AGENT_CACHE_BYPASS_MAX_ENTRIES);
    const auto before = entries->get();
    std::atomic<bool> start {false};
    std::atomic<int> errors {0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t)
    {
        threads.emplace_back(
            [&]()
            {
                while (!start.load()) std::this_thread::yield();
                for (int i = 0; i < 1000; ++i)
                {
                    if (bounded.getOrParse("002", absent).second != Op::BypassedCapacity
                        || bounded.getOrParse("001", cached).second != Op::Retrieved)
                    {
                        errors.fetch_add(1);
                    }
                }
            });
    }
    start.store(true);
    for (auto& thread : threads) thread.join();
    EXPECT_EQ(errors.load(), 0);
    EXPECT_EQ(entries->get() - before, 4000u);
    EXPECT_EQ(bounded.size(), 1u);
    EXPECT_EQ(bounded.accountedBytes(), bytes);
    EXPECT_EQ(AgentMetadataCacheTestAccess::retained(bounded, "001"), retained);
    EXPECT_TRUE(AgentMetadataCacheTestAccess::consistent(bounded));
}

TEST_F(AgentMetadataCacheTest, FitsBytesHandlesOverflowAndUnlimited)
{
    constexpr auto max = std::numeric_limits<std::size_t>::max();
    const auto expectFit = [](AgentMetadataCache::ByteFit fit, bool fits, bool countAsBypass)
    {
        EXPECT_EQ(fit.fits, fits);
        EXPECT_EQ(fit.countAsBypass, countAsBypass);
    };
    // An unrepresentable total never fits, but only a configured byte limit counts it as a bypass
    expectFit(AgentMetadataCache::fitsBytes(max - 1, 2, 0), false, false);
    expectFit(AgentMetadataCache::fitsBytes(max - 1, 2, 100), false, true);
    expectFit(AgentMetadataCache::fitsBytes(10, std::nullopt, 100), false, true);
    expectFit(AgentMetadataCache::fitsBytes(10, 5, 15), true, false);
    expectFit(AgentMetadataCache::fitsBytes(10, 6, 15), false, true);
    expectFit(AgentMetadataCache::fitsBytes(max - 1, 1, 0), true, false);
}
