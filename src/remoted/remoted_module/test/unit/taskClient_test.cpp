/*
 * Wazuh remoted module - TaskClient unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "control/metrics.hpp"
#include "control/taskClient.hpp"
#include "fakeUdsServer.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <json.hpp>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace remoted::control;
using remoted::test::FakeUdsServer;
using namespace std::chrono_literals;

namespace
{
    template<typename T>
    struct Waiter
    {
        std::mutex mu;
        std::condition_variable cv;
        bool done {false};
        T value {};

        void complete(T v)
        {
            std::lock_guard<std::mutex> lock(mu);
            value = std::move(v);
            done = true;
            cv.notify_all();
        }
        bool wait(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(mu);
            return cv.wait_for(lock, timeout, [&] { return done; });
        }
    };
} // namespace

// -----------------------------------------------------------------------------
// Happy path: two pending tasks, well-formed JSON envelope.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksParsesTasksArray)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_ok");

    std::string lastReq;
    FakeUdsServer server(path,
                         [&](const std::string& req) -> std::string
                         {
                             lastReq = req;
                             nlohmann::json out;
                             out["status"] = "ok";
                             out["tasks"] = nlohmann::json::array();
                             out["tasks"].push_back({{"task_id", "t1"},
                                                     {"task_type", "upgrade"},
                                                     {"payload", {{"target_version", "v5.0"}}}});
                             out["tasks"].push_back(
                                 {{"task_id", "t2"}, {"task_type", "restart"}, {"payload", nlohmann::json::object()}});
                             return out.dump();
                         });

    ControlMetrics metrics;
    TaskClient client(path, /*concurrency*/ 1, /*deadlineMs*/ 1000, /*maxQueueSize*/ 100, metrics);

    Waiter<std::pair<SocketError, std::vector<Task>>> w;
    client.getPendingTasks(42, [&](SocketError e, std::vector<Task> tasks) { w.complete({e, std::move(tasks)}); });

    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.first, SocketError::None);
    ASSERT_EQ(w.value.second.size(), 2U);
    EXPECT_EQ(w.value.second[0].id, "t1");
    EXPECT_EQ(w.value.second[0].type, "upgrade");
    EXPECT_EQ(w.value.second[0].payload.value("target_version", ""), "v5.0");
    EXPECT_EQ(w.value.second[1].id, "t2");
    EXPECT_EQ(w.value.second[1].type, "restart");

    // Wire format assertion: JSON with action & string agent_id.
    auto req = nlohmann::json::parse(lastReq);
    EXPECT_EQ(req.value("action", ""), "get_pending_tasks");
    EXPECT_EQ(req.value("agent_id", ""), "042");

    EXPECT_GE(metrics.taskFetchCount.load(), 1U);
}

// -----------------------------------------------------------------------------
// Empty tasks: no error, empty vector.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksEmpty)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_empty");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "{\"status\":\"ok\",\"tasks\":[]}"; });

    ControlMetrics metrics;
    TaskClient client(path, 1, 1000, 100, metrics);

    Waiter<std::pair<SocketError, std::vector<Task>>> w;
    client.getPendingTasks(1, [&](SocketError e, std::vector<Task> t) { w.complete({e, std::move(t)}); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.first, SocketError::None);
    EXPECT_TRUE(w.value.second.empty());
}

// -----------------------------------------------------------------------------
// tasks field missing: still ok, still empty. The tasks field is optional.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksTolerantOfMissingTasksField)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_notasks");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "{\"status\":\"ok\"}"; });

    ControlMetrics metrics;
    TaskClient client(path, 1, 1000, 100, metrics);

    Waiter<std::pair<SocketError, std::vector<Task>>> w;
    client.getPendingTasks(1, [&](SocketError e, std::vector<Task> t) { w.complete({e, std::move(t)}); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value.first, SocketError::None);
    EXPECT_TRUE(w.value.second.empty());
}

// -----------------------------------------------------------------------------
// Server-side error object -> ProtocolError.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksProtocolErrorOnErrorField)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_err");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "{\"error\":\"boom\"}"; });

    ControlMetrics metrics;
    TaskClient client(path, 1, 1000, 100, metrics);

    Waiter<SocketError> w;
    client.getPendingTasks(1, [&](SocketError e, std::vector<Task>) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value, SocketError::ProtocolError);
    EXPECT_GE(metrics.taskFetchErrorCount.load(), 1U);
}

// -----------------------------------------------------------------------------
// Status not "ok" -> ProtocolError. Belt-and-suspenders check for the client
// treating "status" as a real success indicator.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksProtocolErrorOnBadStatus)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_bad");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "{\"status\":\"nope\"}"; });

    ControlMetrics metrics;
    TaskClient client(path, 1, 1000, 100, metrics);

    Waiter<SocketError> w;
    client.getPendingTasks(1, [&](SocketError e, std::vector<Task>) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value, SocketError::ProtocolError);
    EXPECT_GE(metrics.taskFetchErrorCount.load(), 1U);
}

// -----------------------------------------------------------------------------
// Malformed JSON reply -> ProtocolError (parser throws internally).
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksProtocolErrorOnMalformedJson)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_mal");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return "not json at all"; });

    ControlMetrics metrics;
    TaskClient client(path, 1, 1000, 100, metrics);

    Waiter<SocketError> w;
    client.getPendingTasks(1, [&](SocketError e, std::vector<Task>) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value, SocketError::ProtocolError);
    EXPECT_GE(metrics.taskFetchErrorCount.load(), 1U);
}

// -----------------------------------------------------------------------------
// Server drops responses -> deadline expires -> Timeout + metric.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksTimeoutIncrementsMetric)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_to");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return ""; });
    server.setDropResponses(true);

    ControlMetrics metrics;
    TaskClient client(path, 1, /*deadlineMs*/ 100, 100, metrics);

    Waiter<SocketError> w;
    client.getPendingTasks(1, [&](SocketError e, std::vector<Task>) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value, SocketError::Timeout);
    EXPECT_GE(metrics.taskFetchErrorCount.load(), 1U);
}

// -----------------------------------------------------------------------------
// QueueFull: same pattern as WazuhDBClient. Rejection is synchronous.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, QueueFullRejectsSynchronously)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_qf");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return ""; });
    server.setDropResponses(true);

    ControlMetrics metrics;
    TaskClient client(path, /*concurrency*/ 1, /*deadlineMs*/ 200, /*maxQueueSize*/ 2, metrics);

    // Let the worker connect and dequeue the first request.
    std::this_thread::sleep_for(100ms);

    std::atomic<int> queueFull {0};
    auto submit = [&]()
    {
        client.getPendingTasks(1,
                               [&](SocketError e, std::vector<Task>)
                               {
                                   if (e == SocketError::QueueFull)
                                       queueFull.fetch_add(1);
                               });
    };

    submit(); // in flight
    submit(); // queued (1)
    submit(); // queued (2)
    submit(); // rejected
    submit(); // rejected
    submit(); // rejected

    for (int i = 0; i < 200 && queueFull.load() < 3; ++i)
    {
        std::this_thread::sleep_for(5ms);
    }
    EXPECT_GE(queueFull.load(), 3);
    EXPECT_GE(metrics.taskFetchErrorCount.load(), 3U);
}

// -----------------------------------------------------------------------------
// Dtor drains queue with Io.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, DtorFailsPendingCallbacksWithIo)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_dt");
    FakeUdsServer server(path, [](const std::string&) -> std::string { return ""; });
    server.setDropResponses(true);

    ControlMetrics metrics;
    std::atomic<int> io {0};
    {
        TaskClient client(path, 1, /*deadlineMs*/ 200, 10, metrics);
        std::this_thread::sleep_for(100ms);
        for (int i = 0; i < 5; ++i)
        {
            client.getPendingTasks(1,
                                   [&](SocketError e, std::vector<Task>)
                                   {
                                       if (e == SocketError::Io)
                                           io.fetch_add(1);
                                   });
        }
    }
    EXPECT_GE(io.load(), 4);
}
