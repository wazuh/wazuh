#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <base/agentMetadataCache.hpp>

using namespace base;
using namespace std::chrono_literals;

using Op = AgentMetadataCache::Operation;

namespace
{
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

} // namespace

class AgentMetadataCacheTest : public ::testing::Test
{
protected:
    AgentMetadataCache cache {60s}; // 60s TTL for most tests
};

TEST_F(AgentMetadataCacheTest, GetOrParse_NewHeader_ParsesAndCaches)
{
    auto result = cache.getOrParse(HEADER_AGENT_001);

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
    auto first = cache.getOrParse(HEADER_AGENT_001);
    auto second = cache.getOrParse(HEADER_AGENT_001);

    // Same pointer — no re-parse
    EXPECT_EQ(first.first.get(), second.first.get());
    EXPECT_EQ(first.second, Op::Inserted);
    EXPECT_EQ(second.second, Op::Retrieved);
    EXPECT_EQ(cache.size(), 1);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_DifferentHeaderSameAgent_ReplacesEntry)
{
    auto first = cache.getOrParse(HEADER_AGENT_001);
    auto updated = cache.getOrParse(HEADER_AGENT_001_UPDATED);

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
    auto r1 = cache.getOrParse(HEADER_AGENT_001);
    auto r2 = cache.getOrParse(HEADER_AGENT_002);

    EXPECT_NE(r1.first.get(), r2.first.get());
    EXPECT_EQ(r1.second, Op::Inserted);
    EXPECT_EQ(r2.second, Op::Inserted);
    EXPECT_EQ(cache.size(), 2);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_InvalidJson_Throws)
{
    EXPECT_THROW(cache.getOrParse(HEADER_INVALID_JSON), std::runtime_error);
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_MissingAgentId_Throws)
{
    EXPECT_THROW(cache.getOrParse(HEADER_MISSING_ID), std::runtime_error);
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_NonNumericAgentId_Throws)
{
    EXPECT_THROW(cache.getOrParse(HEADER_NON_NUMERIC_ID), std::runtime_error);
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_NegativeAgentId_Throws)
{
    EXPECT_THROW(cache.getOrParse(HEADER_NEGATIVE_ID), std::runtime_error);
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, GetOrParse_EmptyAgentId_Throws)
{
    EXPECT_THROW(cache.getOrParse(HEADER_EMPTY_ID), std::runtime_error);
    EXPECT_EQ(cache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, EvictStale_RemovesExpiredEntries)
{
    AgentMetadataCache shortCache(1s);

    shortCache.getOrParse(HEADER_AGENT_001);
    EXPECT_EQ(shortCache.size(), 1);

    // Wait for TTL to expire
    std::this_thread::sleep_for(1100ms);

    auto evicted = shortCache.evictStale();
    EXPECT_EQ(evicted, 1);
    EXPECT_EQ(shortCache.size(), 0);
}

TEST_F(AgentMetadataCacheTest, EvictStale_KeepsRecentEntries)
{
    AgentMetadataCache shortCache(2s);

    shortCache.getOrParse(HEADER_AGENT_001);
    shortCache.getOrParse(HEADER_AGENT_002);

    // Wait partially (less than TTL)
    std::this_thread::sleep_for(500ms);

    // Access agent 001 again to refresh its timestamp
    shortCache.getOrParse(HEADER_AGENT_001);

    // Wait until agent 002 has expired but 001 hasn't
    std::this_thread::sleep_for(1600ms);

    auto evicted = shortCache.evictStale();
    EXPECT_EQ(evicted, 1);
    EXPECT_EQ(shortCache.size(), 1);
}

TEST_F(AgentMetadataCacheTest, Size_ReflectsEntries)
{
    EXPECT_EQ(cache.size(), 0);
    cache.getOrParse(HEADER_AGENT_001);
    EXPECT_EQ(cache.size(), 1);
    cache.getOrParse(HEADER_AGENT_002);
    EXPECT_EQ(cache.size(), 2);
}

TEST_F(AgentMetadataCacheTest, Clear_EmptiesCache)
{
    cache.getOrParse(HEADER_AGENT_001);
    cache.getOrParse(HEADER_AGENT_002);
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
    for (int i = 1; i <= 10; ++i)
    {
        std::string id = std::to_string(i);
        // Pad to 3 digits
        while (id.size() < 3)
        {
            id = "0" + id;
        }
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
                        auto result = cache.getOrParse(headers[idx]);
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

// Exercises the two-index (agentId + content-hash) synchronization: many distinct agents
// must each be a stable O(1) hit returning the same shared_ptr on re-lookup.
TEST_F(AgentMetadataCacheTest, TwoIndexSync_ManyAgentsStableHits)
{
    constexpr int NUM_AGENTS = 100;

    std::vector<std::string> headers;
    std::vector<std::shared_ptr<const json::Json>> firstPtrs;
    for (int i = 1; i <= NUM_AGENTS; ++i)
    {
        std::string id = std::to_string(i);
        while (id.size() < 3)
        {
            id = "0" + id;
        }
        headers.push_back(R"({"wazuh":{"agent":{"id":")" + id + R"(","name":"agent-)" + id + R"("}}})");
        auto inserted = cache.getOrParse(headers.back());
        EXPECT_EQ(inserted.second, Op::Inserted);
        firstPtrs.push_back(inserted.first);
    }

    ASSERT_EQ(cache.size(), NUM_AGENTS);

    // Re-lookup each header: must be a cache hit returning the exact same pointer.
    for (int i = 0; i < NUM_AGENTS; ++i)
    {
        auto again = cache.getOrParse(headers[i]);
        EXPECT_EQ(again.first.get(), firstPtrs[i].get());
        EXPECT_EQ(again.second, Op::Retrieved);
    }
    EXPECT_EQ(cache.size(), NUM_AGENTS);
}

// When an agent changes its header and later reverts to the original, the cache must keep
// exactly one entry for that agent and the reverted header must still resolve correctly
// (i.e. the stale hash index must have been cleaned on replacement).
TEST_F(AgentMetadataCacheTest, TwoIndexSync_HeaderRevertNoLeak)
{
    auto original = cache.getOrParse(HEADER_AGENT_001);
    EXPECT_EQ(original.second, Op::Inserted);
    ASSERT_EQ(cache.size(), 1);

    // Change the header for the same agent -> replaces the entry.
    auto updated = cache.getOrParse(HEADER_AGENT_001_UPDATED);
    EXPECT_NE(original.first.get(), updated.first.get());
    EXPECT_EQ(updated.second, Op::Updated);
    EXPECT_EQ(cache.size(), 1);

    // Revert to the original header string -> the agent already had a (different) entry, so
    // this is another replacement (Updated), still one entry, and it parses correctly.
    auto reverted = cache.getOrParse(HEADER_AGENT_001);
    EXPECT_EQ(reverted.second, Op::Updated);
    EXPECT_EQ(cache.size(), 1);

    std::string_view hostname;
    ASSERT_EQ(reverted.first->getString(hostname, "/wazuh/agent/host/hostname"), json::RetGet::Success);
    EXPECT_EQ(hostname, "host1");
}

TEST_F(AgentMetadataCacheTest, ThreadSafety_ConcurrentGetOrParseWithEviction)
{
    AgentMetadataCache shortCache(1s);
    constexpr int NUM_THREADS = 4;
    constexpr int ITERATIONS = 500;

    std::vector<std::string> headers;
    for (int i = 1; i <= 5; ++i)
    {
        std::string id = std::to_string(i);
        while (id.size() < 3)
        {
            id = "0" + id;
        }
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
                        shortCache.getOrParse(headers[idx]);
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
