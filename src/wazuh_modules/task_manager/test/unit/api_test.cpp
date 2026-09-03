/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cache/pendingCache.hpp"
#include "http/apiHandlers.hpp"
#include "testDoubles.hpp"

#include <gtest/gtest.h>

#include <ctime>

using namespace task_manager;
using namespace task_manager::http;
using namespace task_manager::test;

namespace
{
    class ApiTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            m_store = makeMemoryStore();
            m_handler = std::make_shared<TestHandler>();

            // One coalescing, bounded type, so the descriptor-authority tests have something to
            // assert against.
            registry::TaskTypeDescriptor scan;
            scan.name = "vd_scan";
            scan.concurrencyGroup = "vd_scan";
            scan.maxConcurrent = 1;
            scan.coalesceByAgent = true;
            scan.maxPending = 2;
            scan.watchdogBudget = std::chrono::seconds {60};
            scan.handler = m_handler;

            // A plain type beside it: no coalescing, no admission bound. The tests about ids,
            // collisions and paging use this one, so that vd_scan's policy cannot decide their
            // outcome for a reason they are not testing -- a request that coalesces never reaches
            // the primary-key collision, and a bound of two never yields a second page.
            registry::TaskTypeDescriptor plain;
            plain.name = "plain_type";
            plain.concurrencyGroup = "plain_type";
            plain.maxConcurrent = 1;
            plain.watchdogBudget = std::chrono::seconds {60};
            plain.handler = m_handler;

            m_registry = std::make_unique<registry::TaskRegistry>(
                registry::TaskRegistry {registry::RetryPolicy {}, {scan, plain}});

            m_api = std::make_unique<ApiHandlers>(
                *m_store,
                *m_registry,
                m_cache,
                [this](const std::string& type) { m_notifiedManager.push_back(type); },
                [this](const std::string& type) { m_notifiedAgent.push_back(type); },
                nullptr,
                1024,
                10);
        }

        static nlohmann::json agentTaskBody(const std::string& agentId = "001",
                                            const std::string& type = "agent_restart")
        {
            return nlohmann::json {{"agent_id", agentId},
                                   {"task_type", type},
                                   {"create_time", static_cast<Timestamp>(std::time(nullptr))},
                                   {"payload", nlohmann::json::object()}};
        }

        std::unique_ptr<storage::SqliteTaskStore> m_store;
        std::shared_ptr<TestHandler> m_handler;
        std::unique_ptr<registry::TaskRegistry> m_registry;
        cache::PendingCache m_cache;
        std::unique_ptr<ApiHandlers> m_api;
        std::vector<std::string> m_notifiedManager;
        std::vector<std::string> m_notifiedAgent;
    };
} // namespace

// ---- agent tasks -------------------------------------------------------------------------------

TEST_F(ApiTest, CreatingAnAgentTaskReturnsItsId)
{
    const auto response {m_api->createAgentTask(agentTaskBody())};

    EXPECT_EQ(response.status, 200);
    ASSERT_TRUE(response.body.contains("task_id"));
    EXPECT_EQ(response.body["task_id"].get<std::string>().size(), 36U);
}

TEST_F(ApiTest, RejectsAnAgentTaskMissingARequiredField)
{
    for (const auto* field : {"agent_id", "task_type", "create_time", "payload"})
    {
        auto body = agentTaskBody();
        body.erase(field);

        const auto response {m_api->createAgentTask(body)};
        EXPECT_EQ(response.status, 400) << field;
        EXPECT_EQ(response.body["error"], "parsing_error") << field;
    }
}

TEST_F(ApiTest, RejectsATimestampOutsideItsWindow)
{
    const auto now {static_cast<Timestamp>(std::time(nullptr))};

    auto future = agentTaskBody();
    future["create_time"] = now + 3600;
    EXPECT_EQ(m_api->createAgentTask(future).body["message"], "Timestamp is in the future");

    auto ancient = agentTaskBody();
    ancient["create_time"] = now - 40000000;
    EXPECT_EQ(m_api->createAgentTask(ancient).body["message"], "Timestamp is too old (>1 year)");
}

TEST_F(ApiTest, RejectsAnOversizedPayload)
{
    auto body = agentTaskBody();
    body["payload"] = nlohmann::json {{"blob", std::string(4096, 'x')}};

    const auto response {m_api->createAgentTask(body)};
    EXPECT_EQ(response.status, 413);
    EXPECT_EQ(response.body["error"], "payload_too_large");
}

TEST_F(ApiTest, TheSameLogicalRequestProducesTheSameId)
{
    const auto body = agentTaskBody();

    const auto first {m_api->createAgentTask(body)};
    const auto second {m_api->createAgentTask(body)};

    // Deterministic ids are what make a retry, or the same request routed to two cluster nodes,
    // one task rather than two.
    EXPECT_EQ(first.body["task_id"], second.body["task_id"]);
}

TEST_F(ApiTest, ASourceIdChangesTheId)
{
    auto withSource = agentTaskBody();
    withSource["source_id"] = "ar-doc-1";

    EXPECT_NE(m_api->createAgentTask(agentTaskBody()).body["task_id"],
              m_api->createAgentTask(withSource).body["task_id"]);
}

TEST_F(ApiTest, TakingPendingTasksReturnsThemOnceAndHandsBackParsedPayloads)
{
    auto body = agentTaskBody();
    body["payload"] = nlohmann::json {{"wpk_file", "x.wpk"}};
    m_api->createAgentTask(body);

    const auto first {m_api->takePendingAgentTasks(nlohmann::json {{"agent_id", "001"}})};
    ASSERT_EQ(first.status, 200);
    ASSERT_EQ(first.body["tasks"].size(), 1U);

    // The payload is stored as text and handed back as an OBJECT, so a consumer sees what it
    // created rather than a string containing it.
    EXPECT_TRUE(first.body["tasks"][0]["payload"].is_object());
    EXPECT_EQ(first.body["tasks"][0]["payload"]["wpk_file"], "x.wpk");

    const auto second {m_api->takePendingAgentTasks(nlohmann::json {{"agent_id", "001"}})};
    EXPECT_TRUE(second.body["tasks"].empty()) << "marking on read is the preserved behaviour";
}

TEST_F(ApiTest, TheNegativeCacheAnswersIdlePollsWithoutTouchingTheStore)
{
    // The first read finds nothing and records the absence.
    EXPECT_TRUE(m_api->takePendingAgentTasks(nlohmann::json {{"agent_id", "001"}}).body["tasks"].empty());
    EXPECT_TRUE(m_cache.knownEmpty("001"));

    // This is the branch that keeps a fleet's idle polls off the write path entirely: the pending
    // route is the only high-frequency one, and it WRITES.
    EXPECT_TRUE(m_api->takePendingAgentTasks(nlohmann::json {{"agent_id", "001"}}).body["tasks"].empty());
}

TEST_F(ApiTest, CreatingATaskEvictsTheAgentFromTheNegativeCache)
{
    m_api->takePendingAgentTasks(nlohmann::json {{"agent_id", "001"}});
    ASSERT_TRUE(m_cache.knownEmpty("001"));

    m_api->createAgentTask(agentTaskBody());

    // Without the eviction the task would sit invisible until something else cleared the entry.
    EXPECT_FALSE(m_cache.knownEmpty("001"));
    EXPECT_EQ(m_api->takePendingAgentTasks(nlohmann::json {{"agent_id", "001"}}).body["tasks"].size(), 1U);
}

TEST_F(ApiTest, BulkCreationReportsOnePerAgent)
{
    nlohmann::json tasks = nlohmann::json::array();
    for (int i = 1; i <= 5; ++i)
    {
        tasks.push_back(agentTaskBody("00" + std::to_string(i)));
    }

    const auto response {m_api->createAgentTasksBulk(nlohmann::json {{"tasks", tasks}})};

    ASSERT_EQ(response.status, 200);
    ASSERT_EQ(response.body["results"].size(), 5U);
    for (const auto& result : response.body["results"])
    {
        EXPECT_TRUE(result["created"].get<bool>());
        EXPECT_FALSE(result["task_id"].get<std::string>().empty());
    }
}

TEST_F(ApiTest, ABulkRequestWithOneBadEntryWritesNothing)
{
    auto good = agentTaskBody("001");
    auto bad = agentTaskBody("002");
    bad.erase("task_type");

    const auto response {m_api->createAgentTasksBulk(nlohmann::json {{"tasks", nlohmann::json::array({good, bad})}})};

    EXPECT_EQ(response.status, 400);

    // Every entry is validated before ANY is written, so a malformed one cannot leave half a
    // fleet's restart written and the other half rejected.
    EXPECT_TRUE(m_api->takePendingAgentTasks(nlohmann::json {{"agent_id", "001"}}).body["tasks"].empty());
}

// ---- manager tasks -----------------------------------------------------------------------------

namespace
{
    nlohmann::json
    managerTaskBody(const std::string& id, const std::string& agentId = "007", const std::string& type = "vd_scan")
    {
        return nlohmann::json {{"task_id", id},
                               {"task_type", type},
                               {"agent_id", agentId},
                               {"payload", nlohmann::json {{"agent_id", agentId}}}};
    }
} // namespace

TEST_F(ApiTest, CreatingAManagerTaskWakesTheExecutorImmediately)
{
    const auto response {m_api->createManagerTask(managerTaskBody("a"))};

    ASSERT_EQ(response.status, 200);
    EXPECT_EQ(response.body["result"], "created");

    // This is why a task created through the socket starts now rather than at some poll interval:
    // there is no poll interval.
    ASSERT_EQ(m_notifiedManager.size(), 1U);
    EXPECT_EQ(m_notifiedManager[0], "vd_scan");
}

TEST_F(ApiTest, TheDescriptorDecidesCoalescingNotTheRequest)
{
    m_api->createManagerTask(managerTaskBody("a", "007"));

    // The request says do not coalesce; the registry says this type does. The registry wins,
    // because a producer that could contradict it would be able to bypass the queue's policy.
    auto second = managerTaskBody("b", "007");
    second["coalesce"] = false;

    const auto response {m_api->createManagerTask(second)};
    EXPECT_EQ(response.body["result"], "coalesced");
    EXPECT_EQ(response.body["task_id"], "a") << "the surviving id, not the requested one";
}

TEST_F(ApiTest, TheDescriptorDecidesTheAdmissionBoundNotTheRequest)
{
    m_api->createManagerTask(managerTaskBody("a", "001"));
    m_api->createManagerTask(managerTaskBody("b", "002"));

    // maxPending is 2 in the descriptor. A request asking for more does not get it.
    auto third = managerTaskBody("c", "003");
    third["max_pending"] = 1000;

    const auto response {m_api->createManagerTask(third)};
    EXPECT_EQ(response.status, 503);
    EXPECT_EQ(response.body["result"], "queue_full");
}

TEST_F(ApiTest, AnUnknownTypeMayCarryItsOwnPolicy)
{
    // The escape hatch a test fixture uses to register a synthetic type. Only reachable for types
    // this build does not know, so it cannot be used to contradict a real descriptor.
    auto body = managerTaskBody("a");
    body["task_type"] = "synthetic_type";
    body["max_pending"] = 1;

    EXPECT_EQ(m_api->createManagerTask(body).body["result"], "created");

    auto second = managerTaskBody("b");
    second["task_type"] = "synthetic_type";
    second["max_pending"] = 1;
    EXPECT_EQ(m_api->createManagerTask(second).body["result"], "queue_full");
}

TEST_F(ApiTest, ARepeatedIdCollidesRatherThanFailing)
{
    // A non-coalescing type on purpose: with coalescing on, the second request would be absorbed
    // by the agent's existing row and never reach the primary key at all.
    m_api->createManagerTask(managerTaskBody("a", "001", "plain_type"));

    auto again = managerTaskBody("a", "001", "plain_type");
    const auto response {m_api->createManagerTask(again)};

    // Normal for a deterministic-id creator that can run twice for one logical event.
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body["result"], "collided");
    EXPECT_EQ(response.body["task_id"], "a");
}

TEST_F(ApiTest, GettingAnUnknownTaskIsANotFoundNotAnEmptyRow)
{
    const auto response {m_api->getManagerTask(nlohmann::json {{"task_id", "nope"}})};
    EXPECT_EQ(response.status, 404);
}

TEST_F(ApiTest, TheByAgentLookupAnswersEmptyRatherThanErroringWhenThereIsNoRow)
{
    const auto response {m_api->getManagerTaskByAgent(nlohmann::json {{"agent_id", "404"}, {"task_type", "vd_scan"}})};

    // "This agent has no such task" is the answer authd's pending-purge check is actually asking
    // for, so it must not look like a failure.
    EXPECT_EQ(response.status, 200);
    EXPECT_FALSE(response.body.contains("task"));
}

TEST_F(ApiTest, TheByAgentLookupReturnsTheRowWithItsStatus)
{
    m_api->createManagerTask(managerTaskBody("a", "007"));

    const auto response {m_api->getManagerTaskByAgent(nlohmann::json {{"agent_id", "007"}, {"task_type", "vd_scan"}})};

    ASSERT_TRUE(response.body.contains("task"));
    EXPECT_EQ(response.body["task"]["status"], "pending");
}

TEST_F(ApiTest, ListingIsNarrowAndPagesOnTaskId)
{
    // plain_type rather than vd_scan: vd_scan admits two pending rows, and three is the smallest
    // number that proves a second page exists at all.
    for (int i = 0; i < 5; ++i)
    {
        m_api->createManagerTask(managerTaskBody("task-" + std::to_string(i), "00" + std::to_string(i), "plain_type"));
    }

    const auto page {m_api->listManagerTasks(nlohmann::json {{"task_type", "plain_type"}, {"limit", 2}})};

    ASSERT_EQ(page.body["tasks"].size(), 2U);

    // Deliberately narrow: enough to see WHAT failed and why, without paging whole payloads.
    EXPECT_FALSE(page.body["tasks"][0].contains("payload"));
    EXPECT_TRUE(page.body["tasks"][0].contains("status"));

    const auto next {m_api->listManagerTasks(nlohmann::json {
        {"task_type", "plain_type"}, {"limit", 2}, {"last_task_id", page.body["tasks"][1]["task_id"]}})};

    // Asserted rather than expected: indexing an empty array below is undefined behaviour, and a
    // regression here should read as a failed test rather than as a crashed one.
    ASSERT_EQ(next.body["tasks"].size(), 2U);
    EXPECT_EQ(next.body["tasks"][0]["task_id"], "task-2");
}

TEST_F(ApiTest, ListingRejectsAnUnknownStatus)
{
    const auto response {m_api->listManagerTasks(nlohmann::json {{"task_type", "vd_scan"}, {"status", "almost_done"}})};

    EXPECT_EQ(response.status, 400);
}

TEST_F(ApiTest, CountingRequiresBothFields)
{
    EXPECT_EQ(m_api->countManagerTasks(nlohmann::json {{"task_type", "vd_scan"}}).status, 400);
    EXPECT_EQ(m_api->countManagerTasks(nlohmann::json {{"status", "pending"}}).status, 400);

    m_api->createManagerTask(managerTaskBody("a", "001"));
    const auto response {m_api->countManagerTasks(nlohmann::json {{"task_type", "vd_scan"}, {"status", "pending"}})};

    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body["count"], 1);
}

// ---- the negative cache itself -----------------------------------------------------------------

TEST(PendingCache, OnlyEverRecordsAbsence)
{
    cache::PendingCache cache;

    EXPECT_FALSE(cache.knownEmpty("001"));

    cache.markEmpty("001");
    EXPECT_TRUE(cache.knownEmpty("001"));
    EXPECT_EQ(cache.size(), 1U);

    cache.invalidate("001");
    EXPECT_FALSE(cache.knownEmpty("001"));
    EXPECT_EQ(cache.size(), 0U);
}

TEST(PendingCache, InvalidatingAnAbsentAgentIsHarmless)
{
    cache::PendingCache cache;
    cache.invalidate("never-seen");
    EXPECT_EQ(cache.size(), 0U);
}
