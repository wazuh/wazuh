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
// fakeUdsServer.hpp is included ONLY for makeUniqueSocketPath: the Task Manager speaks HTTP
// now, so the framed server in that header is no longer what this client talks to.
#include "fakeTaskServer.hpp"
#include "fakeUdsServer.hpp"

#include <wazuh_metrics/manager.hpp>

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
using remoted::test::FakeTaskServer;
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
// Happy path: two pending tasks, well-formed JSON body.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksParsesTasksArray)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_ok");

    FakeTaskServer server(path);
    server.setHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            nlohmann::json out;
            out["tasks"] = nlohmann::json::array();
            out["tasks"].push_back(
                {{"task_id", "t1"}, {"task_type", "upgrade"}, {"payload", {{"target_version", "v5.0"}}}});
            out["tasks"].push_back(
                {{"task_id", "t2"}, {"task_type", "restart"}, {"payload", nlohmann::json::object()}});
            res.set_content(out.dump(), "application/json");
        });

    // A real manager-backed set (not the null object): this test asserts the count.
    wazuh::metrics::Manager metricsManager;
    ControlMetrics metrics {makeControlMetrics(metricsManager)};
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

    // Wire format. The `action` member is gone with the framed protocol -- the route carries what
    // it used to say -- so the body is the agent id and nothing else, still zero-padded to match
    // the stored format.
    auto req = nlohmann::json::parse(server.lastBody());
    EXPECT_FALSE(req.contains("action"));
    EXPECT_EQ(req.value("agent_id", ""), "042");

    EXPECT_GE(metrics.taskFetch->get(), 1U);
}

// -----------------------------------------------------------------------------
// Empty tasks: no error, empty vector.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksEmpty)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_empty");
    FakeTaskServer server(path);
    server.setBody(R"({"tasks":[]})");

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
    FakeTaskServer server(path);
    server.setBody("{}");

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
    FakeTaskServer server(path);
    server.setBody(R"({"error":"boom"})");

    // A real manager-backed set (not the null object): this test asserts the count.
    wazuh::metrics::Manager metricsManager;
    ControlMetrics metrics {makeControlMetrics(metricsManager)};
    TaskClient client(path, 1, 1000, 100, metrics);

    Waiter<SocketError> w;
    client.getPendingTasks(1, [&](SocketError e, std::vector<Task>) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value, SocketError::ProtocolError);
    EXPECT_GE(metrics.taskFetchError->get(), 1U);
}

// -----------------------------------------------------------------------------
// A non-2xx status -> ProtocolError, whatever the body says.
//
// This replaces the old `status != "ok"` check. There is no `status` member on the wire any more:
// the HTTP status carries that, so THIS is now the belt-and-suspenders check that the client
// treats the server's own success signal as a real one.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksProtocolErrorOnNon2xx)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_bad");
    FakeTaskServer server(path);
    server.setStatus(500);

    // A real manager-backed set (not the null object): this test asserts the count.
    wazuh::metrics::Manager metricsManager;
    ControlMetrics metrics {makeControlMetrics(metricsManager)};
    TaskClient client(path, 1, 1000, 100, metrics);

    Waiter<SocketError> w;
    client.getPendingTasks(1, [&](SocketError e, std::vector<Task>) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value, SocketError::ProtocolError);
    EXPECT_GE(metrics.taskFetchError->get(), 1U);
}

// -----------------------------------------------------------------------------
// A 2xx carrying a body that is not JSON -> ProtocolError. Deliberately a 2xx: the status says
// the request succeeded, so only the parse can reject it.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksProtocolErrorOnMalformedJson)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_mal");
    FakeTaskServer server(path);
    server.setBody("not json at all");

    // A real manager-backed set (not the null object): this test asserts the count.
    wazuh::metrics::Manager metricsManager;
    ControlMetrics metrics {makeControlMetrics(metricsManager)};
    TaskClient client(path, 1, 1000, 100, metrics);

    Waiter<SocketError> w;
    client.getPendingTasks(1, [&](SocketError e, std::vector<Task>) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));
    EXPECT_EQ(w.value, SocketError::ProtocolError);
    EXPECT_GE(metrics.taskFetchError->get(), 1U);
}

// -----------------------------------------------------------------------------
// Server holds the response past the deadline -> Timeout + metric.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, GetPendingTasksTimeoutIncrementsMetric)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_to");
    FakeTaskServer server(path);
    server.setStall(800ms);

    // A real manager-backed set (not the null object): this test asserts the count.
    wazuh::metrics::Manager metricsManager;
    ControlMetrics metrics {makeControlMetrics(metricsManager)};
    TaskClient client(path, 1, /*deadlineMs*/ 100, 100, metrics);

    Waiter<SocketError> w;
    client.getPendingTasks(1, [&](SocketError e, std::vector<Task>) { w.complete(e); });
    ASSERT_TRUE(w.wait(3000ms));

    // Timeout, NOT Io: the poller retries a timeout and gives up differently on an I/O failure,
    // so collapsing the two would change what remoted does about a slow task manager.
    EXPECT_EQ(w.value, SocketError::Timeout);
    EXPECT_GE(metrics.taskFetchError->get(), 1U);
}

// -----------------------------------------------------------------------------
// QueueFull: same pattern as WazuhDBClient. Rejection is synchronous.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, QueueFullRejectsSynchronously)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_qf");
    FakeTaskServer server(path);
    server.setStall(5000ms); // long enough that nothing drains while the queue fills

    // A real manager-backed set (not the null object): this test asserts the count.
    wazuh::metrics::Manager metricsManager;
    ControlMetrics metrics {makeControlMetrics(metricsManager)};
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
    EXPECT_GE(metrics.taskFetchError->get(), 3U);
}

// -----------------------------------------------------------------------------
// Dtor drains queue with Io.
// -----------------------------------------------------------------------------
TEST(TaskClientTest, DtorFailsPendingCallbacksWithIo)
{
    const auto path = remoted::test::makeUniqueSocketPath("task_dt");
    FakeTaskServer server(path);
    server.setStall(5000ms);

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
