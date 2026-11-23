/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "cache/pendingCache.hpp"
#include "http/apiHandlers.hpp"
#include "metrics/taskMetrics.hpp"
#include "testDoubles.hpp"

#include <wazuh_metrics/manager.hpp>

#include <gtest/gtest.h>

#include <stdexcept>

using namespace task_manager;
using namespace task_manager::test;

namespace
{
    constexpr auto CREATED_PREFIX {"task_manager.manager_tasks.created."};
    constexpr auto RETIRED_PREFIX {"task_manager.manager_tasks.retired."};
    constexpr auto OUTCOME_PREFIX {"task_manager.handler.outcome."};

    class TaskMetricsTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            m_manager = std::make_shared<wazuh::metrics::Manager>();
            m_metrics = std::make_shared<metrics::TaskMetrics>(m_manager, std::vector<std::string> {"vd_scan"});
        }

        /// @brief The counter's value, or -1 when no metric of that name exists.
        long long value(const std::string& name) const
        {
            const auto metric {m_manager->get(name)};
            return metric ? static_cast<long long>(metric->value()) : -1;
        }
        long long created(const std::string& type, const std::string& result) const
        {
            return value(CREATED_PREFIX + type + "." + result);
        }
        long long retired(const std::string& type, const std::string& status) const
        {
            return value(RETIRED_PREFIX + type + "." + status);
        }
        long long outcome(const std::string& type, const std::string& result) const
        {
            return value(OUTCOME_PREFIX + type + "." + result);
        }

        std::shared_ptr<wazuh::metrics::Manager> m_manager;
        std::shared_ptr<metrics::TaskMetrics> m_metrics;
    };
} // namespace

TEST_F(TaskMetricsTest, EveryCreateCounterExistsBeforeTheFirstRequest)
{
    for (const auto* result : {"created", "coalesced", "collided", "queue_full"})
    {
        EXPECT_EQ(created("vd_scan", result), 0) << result;
        EXPECT_EQ(created("unknown", result), 0) << result;
    }
}

TEST_F(TaskMetricsTest, ARegisteredTypeCountsUnderItsOwnName)
{
    m_metrics->taskCreated("vd_scan", CreateResult::Created);
    m_metrics->taskCreated("vd_scan", CreateResult::Coalesced);

    EXPECT_EQ(created("vd_scan", "created"), 1);
    EXPECT_EQ(created("vd_scan", "coalesced"), 1);
    EXPECT_EQ(created("unknown", "created"), 0);
}

TEST_F(TaskMetricsTest, UnregisteredTypesShareOneBucketAndMintNoMetric)
{
    m_metrics->taskCreated("misspelt", CreateResult::Created);
    m_metrics->taskCreated("also_misspelt", CreateResult::Created);
    m_metrics->taskCreated("misspelt", CreateResult::QueueFull);

    EXPECT_EQ(created("unknown", "created"), 2);
    EXPECT_EQ(created("unknown", "queue_full"), 1);
    EXPECT_EQ(created("misspelt", "created"), -1) << "a type from the request must never name a metric";
    EXPECT_EQ(created("also_misspelt", "created"), -1);
    EXPECT_EQ(created("vd_scan", "created"), 0);
}

TEST_F(TaskMetricsTest, ARegisteredTypeMayNotTakeTheBucketName)
{
    EXPECT_THROW(metrics::TaskMetrics(std::make_shared<wazuh::metrics::Manager>(),
                                      std::vector<std::string> {"vd_scan", "unknown"}),
                 std::invalid_argument);
}

TEST_F(TaskMetricsTest, TheCreateRouteCountsAnUnknownTypeInTheBucket)
{
    auto store {makeMemoryStore()};
    const auto handler {std::make_shared<TestHandler>()};

    registry::TaskTypeDescriptor scan;
    scan.name = "vd_scan";
    scan.concurrencyGroup = "vd_scan";
    scan.maxConcurrent = 1;
    scan.watchdogBudget = std::chrono::seconds {60};
    scan.handler = handler;
    const registry::TaskRegistry taskRegistry {registry::RetryPolicy {}, {scan}};

    cache::PendingCache cache;
    http::ApiHandlers api {*store, taskRegistry, cache, nullptr, m_metrics, 1024, 10};

    const auto body = [](const std::string& id, const std::string& type)
    {
        return nlohmann::json {{"task_id", id}, {"task_type", type}, {"payload", nlohmann::json::object()}};
    };
    api.createManagerTask(body("a", "vd_scan"));
    api.createManagerTask(body("b", "vd_sacn"));
    api.createManagerTask(body("b", "vd_sacn"));

    EXPECT_EQ(created("vd_scan", "created"), 1);
    EXPECT_EQ(created("unknown", "created"), 1);
    EXPECT_EQ(created("unknown", "collided"), 1);
    EXPECT_EQ(created("vd_sacn", "created"), -1);
}

TEST_F(TaskMetricsTest, EveryRetiredAndOutcomeCounterExistsBeforeTheFirstEvent)
{
    for (const auto* status : {"completed", "failed", "dead_letter", "superseded"})
    {
        EXPECT_EQ(retired("vd_scan", status), 0) << status;
        // Only a registered type is ever claimed: the bucket has no counter that could never move.
        EXPECT_EQ(retired("unknown", status), -1) << status;
    }
    for (const auto* result : {"ok", "retryable", "timeout", "terminal", "not_ready", "busy", "incomplete"})
    {
        EXPECT_EQ(outcome("vd_scan", result), 0) << result;
        EXPECT_EQ(outcome("unknown", result), -1) << result;
    }
    // Not terminal, so never a retired counter.
    EXPECT_EQ(retired("vd_scan", "pending"), -1);
    EXPECT_EQ(retired("vd_scan", "claimed"), -1);
}

TEST_F(TaskMetricsTest, RetiredAndOutcomeCountUnderTheRegisteredTypesOwnName)
{
    m_metrics->taskRetired("vd_scan", TaskStatus::DeadLetter);
    m_metrics->taskRetired("vd_scan", TaskStatus::Superseded);
    m_metrics->handlerRan("vd_scan", Outcome::NotReady, 10);
    m_metrics->handlerRan("vd_scan", Outcome::Incomplete, 10);

    EXPECT_EQ(retired("vd_scan", "dead_letter"), 1);
    EXPECT_EQ(retired("vd_scan", "superseded"), 1);
    EXPECT_EQ(retired("vd_scan", "completed"), 0);
    EXPECT_EQ(outcome("vd_scan", "not_ready"), 1);
    EXPECT_EQ(outcome("vd_scan", "incomplete"), 1);
    EXPECT_EQ(value("task_manager.handler.duration"), 2) << "a histogram's value is its observation count";
}

TEST_F(TaskMetricsTest, AnUnregisteredTypeReachingRetiredOrOutcomeMintsNoMetric)
{
    m_metrics->taskRetired("misspelt", TaskStatus::Completed);
    m_metrics->handlerRan("misspelt", Outcome::Ok, 1);

    EXPECT_EQ(retired("unknown", "completed"), -1);
    EXPECT_EQ(outcome("unknown", "ok"), -1);
    EXPECT_EQ(retired("misspelt", "completed"), -1);
    EXPECT_EQ(outcome("misspelt", "ok"), -1);
    EXPECT_EQ(value("task_manager.handler.duration"), 1) << "the run itself is still timed";
}

TEST_F(TaskMetricsTest, ANonTerminalStatusIsNotCounted)
{
    m_metrics->taskRetired("vd_scan", TaskStatus::Pending);
    m_metrics->taskRetired("vd_scan", TaskStatus::Claimed);

    for (const auto* status : {"completed", "failed", "dead_letter", "superseded"})
    {
        EXPECT_EQ(retired("vd_scan", status), 0) << status;
    }
    EXPECT_EQ(retired("vd_scan", "pending"), -1);
}
