// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
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
    EXPECT_THROW(cache.getOrParse("001", HEADER_INVALID_JSON), std::runtime_error);
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
    AgentMetadataCache shortCache(1s, fakeClock.fn());

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
    AgentMetadataCache shortCache(2s, fakeClock.fn());

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
    AgentMetadataCache shortCache(1s, fakeClock.fn());
    shortCache.getOrParse("001", HEADER_AGENT_001);
    shortCache.getOrParse("002", HEADER_AGENT_002);

    fakeClock.advance(1s + 1ns);
    const auto evicted = shortCache.evictStale();

    EXPECT_EQ(evicted, 2u);
    EXPECT_EQ(evictions->get() - evictions0, 2u);
}

TEST_F(AgentMetadataCacheTest, ThreadSafety_ConcurrentGetOrParseWithEviction)
{
    AgentMetadataCache shortCache(1s);
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
    std::atomic<bool> running {true};
    std::vector<std::thread> threads;

    // Writer threads
    for (int t = 0; t < NUM_THREADS; ++t)
    {
        threads.emplace_back(
            [&, t]()
            {
                for (int i = 0; i < ITERATIONS && running.load(); ++i)
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
            });
    }

    // Evictor thread
    threads.emplace_back(
        [&]()
        {
            for (int i = 0; i < 10 && running.load(); ++i)
            {
                std::this_thread::sleep_for(100ms);
                shortCache.evictStale();
            }
        });

    for (auto& th : threads)
    {
        th.join();
    }

    EXPECT_EQ(errors.load(), 0);
}

TEST(CanonicalAgentIdTest, MatchesJwtProfileVectors)
{
    for (const auto id : {"000", "001", "007", "010", "099", "100", "999", "1000", "4294967295"})
    {
        EXPECT_TRUE(isCanonicalAgentId(id)) << id;
    }
    for (const auto id : {"",
                          "0",
                          "1",
                          "01",
                          "0000",
                          "0001",
                          "0123",
                          "abc",
                          "-01",
                          "+01",
                          " 01",
                          "001 ",
                          "1.0",
                          "1e3",
                          "4294967296",
                          "9999999999",
                          "10000000000",
                          "001\r\n"})
    {
        EXPECT_FALSE(isCanonicalAgentId(id)) << id;
    }
    EXPECT_FALSE(isCanonicalAgentId(std::string_view("001\0", 4)));
}

TEST_F(AgentMetadataCacheTest, TrustedIdHitRefreshesTtl)
{
    FakeClock clock;
    AgentMetadataCache shortCache(2s, clock.fn());
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
    EXPECT_THROW(cache.getOrParse("001", tooDeep), std::runtime_error);
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
