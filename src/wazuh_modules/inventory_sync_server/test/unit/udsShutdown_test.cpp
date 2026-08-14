/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * SHUTDOWN TESTS. Several of these are only real regression checks under a sanitizer: without
 * -DFSANITIZE=ON a broken teardown ORDER (an asio I/O object destroyed while the reactor is being
 * torn down around it, or a responder touching a freed session) usually still passes. Run this file
 * under ASan and TSan before trusting a change to the shutdown protocol.
 */

#include "http_server/IUdsHttpServer.hpp"
#include "http_server/udsHttpServerFactory.hpp"
#include "udsTestClient.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
using invsync::http::IUdsHttpServer;
using invsync::http::makeUdsHttpServer;
using invsync::http::Method;
using invsync::http::UdsHttpServerConfig;
using invsync::test::peerRequest;
using invsync::test::sendRaw;
using invsync::test::uniqueSocketPath;

namespace
{
    UdsHttpServerConfig configFor(const std::string& socketPath)
    {
        UdsHttpServerConfig config;
        config.socketPath = socketPath;
        config.ioThreads = 2;
        config.headerTimeoutSec = 5;
        config.bodyTimeoutSec = 5;
        config.responseTimeoutSec = 30;
        config.drainTimeoutSec = 2;
        return config;
    }

    /// Parks every responder so the test controls exactly when (and whether) each request is answered.
    struct Parking
    {
        std::mutex mutex;
        std::vector<std::shared_ptr<IHttpResponder>> responders;
        std::atomic<int> dispatched {0};

        invsync::http::RouteHandler handler()
        {
            return [this](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
            {
                {
                    std::lock_guard<std::mutex> lock {mutex};
                    responders.push_back(std::move(responder));
                }
                dispatched.fetch_add(1);
            };
        }

        bool waitFor(int count, std::chrono::seconds timeout = std::chrono::seconds {10})
        {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (dispatched.load() < count && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds {5});
            }
            return dispatched.load() >= count;
        }

        std::vector<std::shared_ptr<IHttpResponder>> take()
        {
            std::lock_guard<std::mutex> lock {mutex};
            auto taken = std::move(responders);
            responders.clear();
            return taken;
        }
    };
} // namespace

/**
 * INVARIANT S2. The reason the API has two phases at all: after stopAccepting() the I/O runtime is
 * still alive, so a response for a request that was already handed to the pipeline still reaches the
 * wire. If this fails, the facade's ordered teardown silently drops in-flight work.
 */
TEST(UdsShutdownTest, DeferredReplyIsDeliveredBetweenStopAcceptingAndStop)
{
    const auto path = uniqueSocketPath("s2");
    Parking parking;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", parking.handler());
    server->start(configFor(path));

    auto pending = std::async(
        std::launch::async,
        [&path] { return sendRaw(path, peerRequest("POST", "/inventory/sync", "x"), std::chrono::seconds {30}); });

    ASSERT_TRUE(parking.waitFor(1));

    // Phase 1 only.
    server->stopAccepting();

    // The response is produced AFTER stopAccepting() returned, from a thread that is not an I/O
    // thread -- and it must still arrive.
    for (auto& responder : parking.take())
    {
        responder->send(HttpResponse::json(202, R"({"late":true})"));
    }

    const auto response = pending.get();
    EXPECT_EQ(202, response.status);
    EXPECT_EQ(R"({"late":true})", response.body);

    server->stop();
}

/**
 * INVARIANT S1, half one. stopAccepting() must WAIT for the acceptor to actually be closed, not
 * merely post the close. Posting would leave "no new connection is accepted" scheduled rather than
 * true, and a connect() right afterwards would succeed.
 */
TEST(UdsShutdownTest, StopAcceptingRejectsNewConnectionsOnceItReturns)
{
    const auto path = uniqueSocketPath("s1a");

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { responder->send(HttpResponse::json(200, "{}")); });
    server->start(configFor(path));

    // Sanity: it serves before phase 1.
    ASSERT_EQ(200, sendRaw(path, peerRequest("POST", "/inventory/sync", "x")).status);

    server->stopAccepting();

    const auto refused = sendRaw(path, peerRequest("POST", "/inventory/sync", "x"));
    EXPECT_FALSE(refused.connected) << "the socket must be gone the moment stopAccepting() returns";

    server->stop();
}

/**
 * INVARIANT S1, half two. A connection that had not yet reached a handler must never reach one, and
 * must be answered rather than dropped. The counter is read AFTER stopAccepting() returns, which is
 * precisely when the guarantee is supposed to hold.
 */
TEST(UdsShutdownTest, StopAcceptingGuaranteesNoFurtherHandlerInvocation)
{
    const auto path = uniqueSocketPath("s1b");
    std::atomic<int> handlerCalls {0};

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [&handlerCalls](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         handlerCalls.fetch_add(1);
                         responder->send(HttpResponse::json(200, "{}"));
                     });
    server->start(configFor(path));

    // A connection that sends only part of a request: it is mid-parse, so it has not reached the
    // handler and never will.
    asio::io_context ioc;
    invsync::test::stream_protocol::socket socket {ioc};
    std::error_code ec;
    socket.connect(invsync::test::stream_protocol::endpoint {path}, ec);
    ASSERT_FALSE(ec);
    asio::write(socket, asio::buffer(std::string {"POST /inventory/sync HTTP/1.1\r\nHost: h\r\n"}), ec);
    ASSERT_FALSE(ec);
    std::this_thread::sleep_for(std::chrono::milliseconds {100});

    ASSERT_EQ(0, handlerCalls.load());
    server->stopAccepting();
    const auto callsAfterPhaseOne = handlerCalls.load();

    // Finish the request now. It must NOT be handled.
    asio::write(socket, asio::buffer(std::string {"Content-Length: 1\r\n\r\nx"}), ec);
    std::this_thread::sleep_for(std::chrono::milliseconds {200});

    EXPECT_EQ(callsAfterPhaseOne, handlerCalls.load()) << "no handler may run after stopAccepting() returns";
    EXPECT_EQ(0, handlerCalls.load());

    server->stop();
}

/**
 * INVARIANT S3. Calling send() after a full stop() is a well-defined no-op -- the guarantee remoted's
 * RESTinio server explicitly declines to make. Only meaningful under ASan, where a use-after-free
 * here would be reported instead of silently working.
 */
TEST(UdsShutdownTest, SendAfterFullStopIsASafeNoOp)
{
    const auto path = uniqueSocketPath("s3");
    Parking parking;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", parking.handler());
    server->start(configFor(path));

    auto pending = std::async(
        std::launch::async,
        [&path] { return sendRaw(path, peerRequest("POST", "/inventory/sync", "x"), std::chrono::seconds {20}); });
    ASSERT_TRUE(parking.waitFor(1));

    auto responders = parking.take();
    server->stop();
    pending.get();

    // From another thread, after the server is fully stopped.
    std::thread late {[&responders]
                      {
                          for (auto& responder : responders)
                          {
                              EXPECT_NO_THROW(responder->send(HttpResponse::json(202, "{}")));
                          }
                      }};
    late.join();
}

/**
 * INVARIANT S3, the harder half. The server object itself is destroyed while a responder is still
 * held, so the only thing keeping the I/O runtime alive is the responder's own share of it. This is
 * what the shared_ptr<Runtime> co-ownership exists for.
 */
TEST(UdsShutdownTest, SendAfterTheServerIsDestroyedIsASafeNoOp)
{
    const auto path = uniqueSocketPath("s3b");
    Parking parking;
    std::vector<std::shared_ptr<IHttpResponder>> responders;

    // Declared out here so the request is still outstanding when the server is destroyed: it is the
    // destructor's force-close, not a response timeout, that has to end this connection.
    std::future<invsync::test::Response> pending;
    {
        auto config = configFor(path);
        config.drainTimeoutSec = 1;

        auto server = makeUdsHttpServer();
        server->addRoute(Method::Post, "/inventory/sync", parking.handler());
        server->start(config);

        pending = std::async(
            std::launch::async,
            [&path] { return sendRaw(path, peerRequest("POST", "/inventory/sync", "x"), std::chrono::seconds {20}); });
        ASSERT_TRUE(parking.waitFor(1));
        responders = parking.take();
    } // server destroyed here; its destructor runs both phases and force-closes the connection

    pending.get();

    std::thread late {[&responders]
                      {
                          for (auto& responder : responders)
                          {
                              EXPECT_NO_THROW(responder->send(HttpResponse::json(202, "{}")));
                          }
                      }};
    late.join();
}

/// A reply that lands inside the drain window is delivered, and stop() still returns.
TEST(UdsShutdownTest, StopWaitsForAnInFlightDeferralWithinTheDrainWindow)
{
    const auto path = uniqueSocketPath("drain");
    auto config = configFor(path);
    config.drainTimeoutSec = 5;

    Parking parking;
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", parking.handler());
    server->start(config);

    auto pending = std::async(
        std::launch::async,
        [&path] { return sendRaw(path, peerRequest("POST", "/inventory/sync", "x"), std::chrono::seconds {30}); });
    ASSERT_TRUE(parking.waitFor(1));

    // Answer shortly after stop() begins, comfortably inside the window.
    std::thread answerer {[&parking]
                          {
                              std::this_thread::sleep_for(std::chrono::milliseconds {200});
                              for (auto& responder : parking.take())
                              {
                                  responder->send(HttpResponse::json(202, R"({"drained":true})"));
                              }
                          }};

    const auto start = std::chrono::steady_clock::now();
    server->stop();
    const auto elapsed = std::chrono::steady_clock::now() - start;
    answerer.join();

    const auto response = pending.get();
    EXPECT_EQ(202, response.status) << "a reply inside the drain window must still be delivered";
    EXPECT_LT(elapsed, std::chrono::seconds {10}) << "stop() must still return";
}

/**
 * Past the drain window the remaining connections are force-closed, so the peer observes EOF
 * promptly instead of waiting out its own response deadline. Bounding shutdown matters: modulesd
 * calls every module's stop() sequentially before joining them under one shared budget.
 */
TEST(UdsShutdownTest, StopForceClosesNeverAnsweredSessionsSoThePeerSeesEofPromptly)
{
    const auto path = uniqueSocketPath("force");
    auto config = configFor(path);
    config.drainTimeoutSec = 1;
    config.responseTimeoutSec = 600; // the response timer must NOT be what saves us here

    Parking parking;
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", parking.handler());
    server->start(config);

    auto pending = std::async(
        std::launch::async,
        [&path] { return sendRaw(path, peerRequest("POST", "/inventory/sync", "x"), std::chrono::seconds {60}); });
    ASSERT_TRUE(parking.waitFor(1));

    // Keep the responder, never answer it.
    auto responders = parking.take();

    const auto start = std::chrono::steady_clock::now();
    server->stop();
    const auto stopElapsed = std::chrono::steady_clock::now() - start;

    pending.get();
    const auto totalElapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(stopElapsed, std::chrono::seconds {10}) << "stop() must be bounded by the drain window";
    EXPECT_LT(totalElapsed, std::chrono::seconds {15}) << "the peer must see EOF, not wait out its own timeout";
}

/**
 * INVARIANT I2, asserted as directly as it can be without a sanitizer: every I/O thread has left
 * run() before the runtime is released, which is what keeps ~socket and ~steady_timer out of
 * ~io_context().
 */
TEST(UdsShutdownTest, StopCompletesWithAllIoThreadsJoined)
{
    const auto path = uniqueSocketPath("i2");
    auto config = configFor(path);
    config.ioThreads = 4;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { responder->send(HttpResponse::json(200, "{}")); });
    server->start(config);

    for (int i = 0; i < 20; ++i)
    {
        ASSERT_EQ(200, sendRaw(path, peerRequest("POST", "/inventory/sync", "x")).status);
    }

    // If a thread were still inside run() when the runtime was released, this would deadlock or
    // crash rather than return.
    EXPECT_NO_THROW(server->stop());
}

/// The destructor must perform both phases, with work still in flight.
TEST(UdsShutdownTest, DestructorPerformsBothPhasesWithADeferralInFlight)
{
    const auto path = uniqueSocketPath("dtor");
    Parking parking;
    std::vector<std::shared_ptr<IHttpResponder>> responders;

    auto pending = std::future<invsync::test::Response> {};
    {
        auto config = configFor(path);
        config.drainTimeoutSec = 1;

        auto server = makeUdsHttpServer();
        server->addRoute(Method::Post, "/inventory/sync", parking.handler());
        server->start(config);

        pending = std::async(
            std::launch::async,
            [&path] { return sendRaw(path, peerRequest("POST", "/inventory/sync", "x"), std::chrono::seconds {30}); });
        ASSERT_TRUE(parking.waitFor(1));
        responders = parking.take();
        // No stop(): the destructor has to do it.
    }

    EXPECT_NO_THROW(pending.get());
}

/// The data-race surface of send(): many threads racing a concurrent stop(). A TSan test.
TEST(UdsShutdownTest, ConcurrentSendAndStopFromManyThreads)
{
    constexpr int CONCURRENCY {64};

    const auto path = uniqueSocketPath("race");
    auto config = configFor(path);
    config.drainTimeoutSec = 1;
    config.maxConnections = 256;

    Parking parking;
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", parking.handler());
    server->start(config);

    std::vector<std::future<invsync::test::Response>> pending;
    pending.reserve(CONCURRENCY);
    for (int i = 0; i < CONCURRENCY; ++i)
    {
        pending.push_back(std::async(
            std::launch::async,
            [&path] { return sendRaw(path, peerRequest("POST", "/inventory/sync", "x"), std::chrono::seconds {60}); }));
    }
    ASSERT_TRUE(parking.waitFor(CONCURRENCY, std::chrono::seconds {30}));

    auto responders = parking.take();

    // Every responder answers while stop() runs concurrently. Whichever order wins, nothing may
    // race on freed memory and nothing may hang.
    std::vector<std::thread> senders;
    senders.reserve(responders.size());
    for (auto& responder : responders)
    {
        senders.emplace_back([responder] { responder->send(HttpResponse::json(202, "{}")); });
    }

    server->stop();

    for (auto& sender : senders)
    {
        sender.join();
    }
    for (auto& future : pending)
    {
        EXPECT_NO_THROW(future.get());
    }
}

/// The whole protocol at scale: many live deferrals through both phases. Every request must either
/// be answered or see its connection closed -- none may hang.
TEST(UdsShutdownTest, StopAcceptingThenStopUnderManyLiveDeferrals)
{
    constexpr int CONCURRENCY {200};

    const auto path = uniqueSocketPath("scale");
    auto config = configFor(path);
    config.maxConnections = 512;
    // 10 s, not the module's production 2: with 200 client threads on a loaded test box, the last
    // few response READS can straddle a short drain window and the tail reply gets force-closed --
    // at 5 s the suite still flaked right at the boundary (~5.03 s observed) as it grew. What this
    // test pins is "every reply SENT is DELIVERED", not the window size.
    config.drainTimeoutSec = 10;

    Parking parking;
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", parking.handler());
    server->start(config);

    std::vector<std::future<invsync::test::Response>> pending;
    pending.reserve(CONCURRENCY);
    for (int i = 0; i < CONCURRENCY; ++i)
    {
        pending.push_back(std::async(
            std::launch::async,
            [&path] { return sendRaw(path, peerRequest("POST", "/inventory/sync", "x"), std::chrono::seconds {60}); }));
    }
    ASSERT_TRUE(parking.waitFor(CONCURRENCY, std::chrono::seconds {30}));

    server->stopAccepting();

    // Answer half of them; the rest are abandoned and must be force-closed by phase 2.
    auto responders = parking.take();
    for (std::size_t i = 0; i < responders.size() / 2; ++i)
    {
        responders[i]->send(HttpResponse::json(202, "{}"));
    }

    server->stop();

    int answered {0};
    for (auto& future : pending)
    {
        const auto response = future.get(); // must not hang
        if (response.status == 202)
        {
            ++answered;
        }
    }
    EXPECT_GE(answered, CONCURRENCY / 2) << "every reply that was sent must have been delivered";
}
