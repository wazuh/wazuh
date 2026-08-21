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
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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
    // No FakeUdsServer bound at this path at all: connect() itself fails synchronously with
    // ENOENT (a real failure, not "would block"), so this never reaches the connect-timeout
    // poll() at all -- it fails FAST, distinct from ServerDroppingTheResponseTimesOut below,
    // which genuinely waits out the response timeout.
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

TEST(AuthdClientTest, SaturatedAcceptBacklogIsAFastConnectFailureNotAHang)
{
    // A real listener exists at this path, but its accept() backlog is fully saturated by other
    // (never-accepted) connections -- the one scenario connectTimeoutMs/the POLLHUP check in
    // performRequest() exist for. Verified against the real kernel (see authdClient.cpp's comment
    // at the POLLHUP/POLLERR check): AF_UNIX's non-blocking connect() fails synchronously with
    // EAGAIN when the backlog is full -- there's no async "still connecting" state -- so poll()
    // comes back immediately with POLLHUP set, and SO_ERROR alone would misleadingly read 0.
    const std::string path = makeUniqueSocketPath("authd_client_backlog_full");

    const int listenFd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(listenFd, 0);
    sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    ASSERT_EQ(::bind(listenFd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), 0);
    ASSERT_EQ(::listen(listenFd, 1), 0); // tiny backlog, saturated below

    // Never accept() any of these: fills the listen backlog and keeps it full for the whole test.
    std::vector<int> fillers;
    for (int i = 0; i < 8; ++i)
    {
        const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        ASSERT_GE(fd, 0);
        ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)); // may succeed or EAGAIN; either is fine
        fillers.push_back(fd);
    }

    // Generous timeouts on both axes: the assertion below (well under either) is what proves this
    // resolves via the fast POLLHUP-detected failure, not by waiting either deadline out.
    AuthdClient client(path,
                       /*isWorkerNode=*/false,
                       /*connectTimeoutMs=*/2000,
                       /*responseTimeoutMs=*/5000,
                       /*maxQueueSize=*/0,
                       /*workerThreads=*/1);
    ResultWaiter waiter;
    client.addAgent(makeRequest(), waiter.callback());

    const auto result = waiter.wait(std::chrono::milliseconds(500));
    EXPECT_EQ(result.errorCode, -1);
    EXPECT_NE(result.message.find("Could not connect"), std::string::npos);

    for (const int fd : fillers)
    {
        ::close(fd);
    }
    ::close(listenFd);
    ::unlink(path.c_str());
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

    // The queue diagnostics behind remoted.enroll.authd.queue.*: capacity is what was configured,
    // depth is what is actually waiting, and the counter isolates the saturation share of
    // remoted.enroll.authd_unavailable (which also fires for an unreachable authd).
    const auto diag = client.queueDiagnostics();
    EXPECT_EQ(diag.capacity, 1U);
    EXPECT_EQ(diag.depth, 1U);         // "second" is still queued behind the busy worker
    EXPECT_EQ(diag.rejectedTotal, 1U); // exactly the one refused above

    // Both first and second eventually fail on the drop-response timeout -- not the assertion
    // of this test, but must still complete so the fixture can tear down cleanly.
    first.wait();
    second.wait();
}

// The saturation counter must stay clean when the client is merely stopping: addAgent() rejects
// through the SAME branch in both cases, so counting the shutdown drain would make
// remoted.enroll.authd.queue.rejected.total report saturation on every module stop.
TEST(AuthdClientTest, StoppingRejectionsAreNotCountedAsSaturation)
{
    const std::string path = makeUniqueSocketPath("authd_client_stop_not_saturation");
    FakeUdsServer server(path, [](const std::string&) { return "{}"; });

    AuthdClient client(path,
                       /*isWorkerNode=*/false,
                       /*connectTimeoutMs=*/0,
                       /*responseTimeoutMs=*/300,
                       /*maxQueueSize=*/8,
                       /*workerThreads=*/1);

    ResultWaiter accepted;
    client.addAgent(makeRequest(), accepted.callback());
    accepted.wait();

    // Drained: nothing is waiting, and nothing was ever refused.
    auto diag = client.queueDiagnostics();
    EXPECT_EQ(diag.depth, 0U);
    EXPECT_EQ(diag.rejectedTotal, 0U);

    client.stop();

    ResultWaiter afterStop;
    client.addAgent(makeRequest(), afterStop.callback());
    const auto result = afterStop.wait();
    EXPECT_EQ(result.errorCode, -1); // refused, like a full queue...

    diag = client.queueDiagnostics();
    EXPECT_EQ(diag.rejectedTotal, 0U); // ...but NOT as saturation
    EXPECT_EQ(diag.depth, 0U);
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

TEST(AuthdClientTest, WorkerThreadSurvivesACallbackThatThrows)
{
    // Regression guard: workerLoop() runs req.callback(performRequest(...)) with no try/catch of
    // its own, on a bare std::thread RestinioHttpServer's per-request exception guard never sees
    // (that guard only covers the synchronous handler call; this callback fires later, from a
    // different thread entirely). An uncaught exception escaping a std::thread's entry function
    // terminates the whole process -- this proves the worker instead survives and keeps serving
    // later requests, which it could only do if the exception was caught inside the loop.
    const std::string path = makeUniqueSocketPath("authd_client_callback_throws");
    FakeUdsServer server(
        path, [](const std::string&) { return R"({"error":0,"data":{"id":"1","name":"n","ip":"i","key":"k"}})"; });
    server.setCloseAfterReply(true);

    // workerThreads=1: guarantees the SAME worker thread that ran the throwing callback is the one
    // that must still be alive and looping to pick up the second request below.
    AuthdClient client(path,
                       /*isWorkerNode=*/false,
                       /*connectTimeoutMs=*/0,
                       /*responseTimeoutMs=*/2000,
                       /*maxQueueSize=*/0,
                       /*workerThreads=*/1);

    client.addAgent(makeRequest(), [](AuthdResult) { throw std::runtime_error("boom"); });

    ResultWaiter waiter;
    client.addAgent(makeRequest(), waiter.callback());
    const auto result = waiter.wait(std::chrono::seconds(2));
    EXPECT_EQ(result.errorCode, 0);
}
