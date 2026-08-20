/*
 * Wazuh remoted module - authd enrollment bridge client - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "enrollment/authdClient.hpp"
#include "fakeUdsServer.hpp"
#include "json.hpp"

using namespace remoted::enrollment;
using remoted::test::FakeUdsServer;
using remoted::test::makeUniqueSocketPath;

namespace
{
    // Blocks the calling test thread until callback() has fired, then hands back the result.
    class ResultWaiter
    {
    public:
        std::function<void(AuthdResult)> callback()
        {
            return [this](AuthdResult result)
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_result = std::move(result);
                m_ready = true;
                m_cv.notify_one();
            };
        }

        AuthdResult wait(std::chrono::milliseconds timeout = std::chrono::seconds(2))
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            EXPECT_TRUE(m_cv.wait_for(lock, timeout, [this] { return m_ready; })) << "callback never fired";
            return m_result;
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_ready {false};
        AuthdResult m_result;
    };

    AuthdAddRequest makeRequest()
    {
        AuthdAddRequest req;
        req.name = "agent1";
        req.ip = "any";
        return req;
    }
} // namespace

TEST(AuthdClientTest, SuccessfulAddReturnsAgentData)
{
    const std::string path = makeUniqueSocketPath("authd_client_success");
    FakeUdsServer server(
        path,
        [](const std::string&)
        {
            return R"({"error":0,"data":{"id":"003","name":"agent1","ip":"any","key":"675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915"}})";
        });
    // Real authd closes the connection right after its one reply (see FakeUdsServer's
    // setCloseAfterReply doc comment) -- without this, AuthdClient's read() loop blocks trying to
    // read a second, never-coming frame until the full response timeout elapses.
    server.setCloseAfterReply(true);

    AuthdClient client(path);
    ResultWaiter waiter;
    client.addAgent(makeRequest(), waiter.callback());

    const auto result = waiter.wait();
    EXPECT_EQ(result.errorCode, 0);
    EXPECT_EQ(result.id, "003");
    EXPECT_EQ(result.name, "agent1");
    EXPECT_EQ(result.ip, "any");
    EXPECT_EQ(result.key, "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");
    EXPECT_TRUE(result.message.empty());
}

TEST(AuthdClientTest, BusinessRejectionPreservesCodeAndStripsPrefix)
{
    const std::string path = makeUniqueSocketPath("authd_client_business_error");
    FakeUdsServer server(path,
                         [](const std::string&) { return R"({"error":9008,"message":"ERROR: Duplicate name"})"; });
    server.setCloseAfterReply(true);

    AuthdClient client(path);
    ResultWaiter waiter;
    client.addAgent(makeRequest(), waiter.callback());

    const auto result = waiter.wait();
    EXPECT_EQ(result.errorCode, 9008);
    EXPECT_EQ(result.message, "Duplicate name"); // "ERROR: " prefix stripped
    EXPECT_TRUE(result.id.empty());
    EXPECT_TRUE(result.key.empty());
}

TEST(AuthdClientTest, ServerAbsentIsATransportFailure)
{
    // No FakeUdsServer bound at this path at all. connect() is a plain blocking call (see
    // authdClient.hpp's class comment), so this fails FAST with ENOENT -- distinct from
    // ServerDroppingTheResponseTimesOut below, which genuinely waits out the response timeout.
    const std::string path = makeUniqueSocketPath("authd_client_absent");

    AuthdClient client(path, /*isWorkerNode=*/false, /*connectTimeoutMs=*/0, /*responseTimeoutMs=*/5000);
    ResultWaiter waiter;
    client.addAgent(makeRequest(), waiter.callback());

    // Well under the response timeout: proves this resolves via the fast connect failure, not by
    // waiting the deadline out.
    const auto result = waiter.wait(std::chrono::milliseconds(500));
    EXPECT_EQ(result.errorCode, -1);
    EXPECT_NE(result.message.find("Could not connect"), std::string::npos);
}

TEST(AuthdClientTest, ServerDroppingTheResponseTimesOut)
{
    const std::string path = makeUniqueSocketPath("authd_client_timeout");
    FakeUdsServer server(path, [](const std::string&) { return "{}"; });
    server.setDropResponses(true);

    // Short response timeout so the test doesn't wait the full worker-aware default.
    AuthdClient client(path, /*isWorkerNode=*/false, /*connectTimeoutMs=*/0, /*responseTimeoutMs=*/200);
    ResultWaiter waiter;
    client.addAgent(makeRequest(), waiter.callback());

    const auto result = waiter.wait(std::chrono::seconds(2));
    EXPECT_EQ(result.errorCode, -1);
    EXPECT_NE(result.message.find("Timed out"), std::string::npos);
}

TEST(AuthdClientTest, MalformedResponseIsATransportFailure)
{
    const std::string path = makeUniqueSocketPath("authd_client_malformed");
    FakeUdsServer server(path, [](const std::string&) { return "not valid json{{{"; });
    server.setCloseAfterReply(true);

    AuthdClient client(path);
    ResultWaiter waiter;
    client.addAgent(makeRequest(), waiter.callback());

    const auto result = waiter.wait();
    EXPECT_EQ(result.errorCode, -1);
}

TEST(AuthdClientTest, MissingDataOnSuccessIsATransportFailure)
{
    // error:0 but no "data" object -- authd's own contract violated; must not crash or
    // fabricate a success result.
    const std::string path = makeUniqueSocketPath("authd_client_missing_data");
    FakeUdsServer server(path, [](const std::string&) { return R"({"error":0})"; });
    server.setCloseAfterReply(true);

    AuthdClient client(path);
    ResultWaiter waiter;
    client.addAgent(makeRequest(), waiter.callback());

    const auto result = waiter.wait();
    EXPECT_EQ(result.errorCode, -1);
}

TEST(AuthdClientTest, RequestOmitsForceIdAndKeyAndIncludesOptionalFieldsWhenProvided)
{
    const std::string path = makeUniqueSocketPath("authd_client_wire_shape");
    std::string capturedRequest;
    std::mutex captureMutex;

    FakeUdsServer server(path,
                         [&](const std::string& request)
                         {
                             std::lock_guard<std::mutex> lock(captureMutex);
                             capturedRequest = request;
                             return R"({"error":0,"data":{"id":"1","name":"n","ip":"i","key":"k"}})";
                         });
    server.setCloseAfterReply(true);

    AuthdClient client(path);
    AuthdAddRequest req;
    req.name = "agent1";
    req.ip = "10.0.0.15";
    req.groups = "default,web-servers";
    req.keyHash = "abc123";

    ResultWaiter waiter;
    client.addAgent(req, waiter.callback());
    ASSERT_EQ(waiter.wait().errorCode, 0);

    std::string captured;
    {
        std::lock_guard<std::mutex> lock(captureMutex);
        captured = capturedRequest;
    }
    const auto json = nlohmann::json::parse(captured);
    EXPECT_EQ(json.at("function"), "add");
    const auto& arguments = json.at("arguments");
    EXPECT_EQ(arguments.at("name"), "agent1");
    EXPECT_EQ(arguments.at("ip"), "10.0.0.15");
    EXPECT_EQ(arguments.at("groups"), "default,web-servers");
    EXPECT_EQ(arguments.at("key_hash"), "abc123");
    EXPECT_FALSE(arguments.contains("force"));
    EXPECT_FALSE(arguments.contains("id"));
    EXPECT_FALSE(arguments.contains("key"));
}

TEST(AuthdClientTest, OptionalFieldsAreOmittedWhenNotProvided)
{
    const std::string path = makeUniqueSocketPath("authd_client_wire_shape_minimal");
    std::string capturedRequest;
    std::mutex captureMutex;

    FakeUdsServer server(path,
                         [&](const std::string& request)
                         {
                             std::lock_guard<std::mutex> lock(captureMutex);
                             capturedRequest = request;
                             return R"({"error":0,"data":{"id":"1","name":"n","ip":"i","key":"k"}})";
                         });
    server.setCloseAfterReply(true);

    AuthdClient client(path);
    ResultWaiter waiter;
    client.addAgent(makeRequest(), waiter.callback()); // no groups/keyHash
    ASSERT_EQ(waiter.wait().errorCode, 0);

    std::string captured;
    {
        std::lock_guard<std::mutex> lock(captureMutex);
        captured = capturedRequest;
    }
    const auto json = nlohmann::json::parse(captured);
    const auto& arguments = json.at("arguments");
    EXPECT_FALSE(arguments.contains("groups"));
    EXPECT_FALSE(arguments.contains("key_hash"));
}

TEST(AuthdClientTest, QueueFullRejectsBeyondCapacity)
{
    const std::string path = makeUniqueSocketPath("authd_client_queue_full");
    FakeUdsServer server(path, [](const std::string&) { return "{}"; });
    server.setDropResponses(true); // keep the (single) worker thread busy on the first request

    // workerThreads=1: this test is specifically about the QUEUE filling up once the worker(s)
    // are all busy, which needs a known, small worker count to trigger deterministically -- the
    // pool's default (kDefaultWorkerThreads) would just pick up "second" immediately too.
    AuthdClient client(path,
                       /*isWorkerNode=*/false,
                       /*connectTimeoutMs=*/0,
                       /*responseTimeoutMs=*/300,
                       /*maxQueueSize=*/1,
                       /*workerThreads=*/1);

    ResultWaiter first;
    ResultWaiter second;
    ResultWaiter third;

    client.addAgent(makeRequest(), first.callback());           // picked up by the worker immediately
    std::this_thread::sleep_for(std::chrono::milliseconds(30)); // let the worker actually start it
    client.addAgent(makeRequest(), second.callback());          // queued (queue size 1, at max)
    client.addAgent(makeRequest(), third.callback());           // queue already full -> rejected now

    const auto thirdResult = third.wait();
    EXPECT_EQ(thirdResult.errorCode, -1);
    EXPECT_NE(thirdResult.message.find("queue is full"), std::string::npos);

    // Both first and second eventually fail on the drop-response timeout -- not the assertion
    // of this test, but must still complete so the fixture can tear down cleanly.
    first.wait();
    second.wait();
}

TEST(AuthdClientTest, StopFailsQueuedRequestsAndIsIdempotent)
{
    const std::string path = makeUniqueSocketPath("authd_client_stop");
    FakeUdsServer server(path, [](const std::string&) { return "{}"; });
    server.setDropResponses(true);

    // Short response timeout: the worker is blocked inside performRequest(), not workerLoop()'s
    // own wait, while handling the in-flight request -- stop()'s join() can only complete once
    // that call returns (same limitation TaskClient's own stop/destroy already has), so this must
    // resolve quickly for the test to be fast rather than technically-wrong-but-slow.
    // workerThreads=1: "queued" must land in the QUEUE (not get picked up by an idle second
    // worker) for this test's "queued.wait() sees the stopping rejection" assertion to hold.
    auto client = std::make_unique<AuthdClient>(path,
                                                /*isWorkerNode=*/false,
                                                /*connectTimeoutMs=*/0,
                                                /*responseTimeoutMs=*/200,
                                                /*maxQueueSize=*/4,
                                                /*workerThreads=*/1);

    ResultWaiter inFlight;
    ResultWaiter queued;
    client->addAgent(makeRequest(), inFlight.callback());
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    client->addAgent(makeRequest(), queued.callback());

    client->stop();
    client->stop(); // must not crash or double-join

    const auto queuedResult = queued.wait();
    EXPECT_EQ(queuedResult.errorCode, -1);
    EXPECT_NE(queuedResult.message.find("stopping"), std::string::npos);

    inFlight.wait(); // times out on the drop-response server; just must not hang the fixture
}

TEST(AuthdClientTest, WorkerPoolProcessesRequestsConcurrently)
{
    // Proves the pool actually parallelizes: FakeUdsServer serves each connection on its own
    // thread already (see its class comment), so an artificial per-request delay here measures
    // AuthdClient's OWN concurrency, not anything the fake server would have serialized for it.
    const std::string path = makeUniqueSocketPath("authd_client_pool_concurrency");
    constexpr auto kPerRequestDelay = std::chrono::milliseconds(150);
    FakeUdsServer server(path,
                         [kPerRequestDelay](const std::string&)
                         {
                             std::this_thread::sleep_for(kPerRequestDelay);
                             return std::string(R"({"error":0,"data":{"id":"1","name":"n","ip":"i","key":"k"}})");
                         });
    // Without this, AuthdClient's read() loop would sit waiting on a second, never-coming frame
    // until the 5 s response timeout below elapses -- dwarfing the artificial per-request delay
    // this test is actually trying to measure concurrency against.
    server.setCloseAfterReply(true);

    constexpr std::uint32_t kWorkers = 4;
    AuthdClient client(path,
                       /*isWorkerNode=*/false,
                       /*connectTimeoutMs=*/0,
                       /*responseTimeoutMs=*/5000,
                       /*maxQueueSize=*/0,
                       /*workerThreads=*/kWorkers);

    std::vector<std::unique_ptr<ResultWaiter>> waiters;
    const auto start = std::chrono::steady_clock::now();
    for (std::uint32_t i = 0; i < kWorkers; ++i)
    {
        waiters.push_back(std::make_unique<ResultWaiter>());
        client.addAgent(makeRequest(), waiters.back()->callback());
    }
    for (auto& waiter : waiters)
    {
        const auto result = waiter->wait(std::chrono::seconds(2));
        EXPECT_EQ(result.errorCode, 0);
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;

    // Serialized (one worker), kWorkers requests at kPerRequestDelay each would take roughly
    // kWorkers * kPerRequestDelay (~600 ms here). Run concurrently across kWorkers workers, they
    // should all finish close to a SINGLE request's delay. A comfortable margin below 2x one
    // request's delay is enough to distinguish "ran in parallel" from "ran serialized" without
    // being flaky under scheduling jitter.
    EXPECT_LT(elapsed, kPerRequestDelay * 2);
}
