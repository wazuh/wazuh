/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/IUdsHttpServer.hpp"
#include "http_server/udsHttpServerFactory.hpp"
#include "udsTestClient.hpp"

#include <gtest/gtest.h>

#include <sys/stat.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using invsync::http::HttpRequest;
using invsync::http::HttpResponse;
using invsync::http::IHttpResponder;
using invsync::http::makeUdsHttpServer;
using invsync::http::Method;
using invsync::http::UdsHttpServerConfig;
using invsync::test::peerRequest;
using invsync::test::sendRaw;
using invsync::test::uniqueSocketPath;

namespace
{
    /// Answers 200 with a fixed body, inline.
    invsync::http::RouteHandler echoHandler(std::string body = R"({"ok":true})")
    {
        return [body](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            responder->send(HttpResponse::json(200, body));
        };
    }

    UdsHttpServerConfig configFor(const std::string& socketPath)
    {
        UdsHttpServerConfig config;
        config.socketPath = socketPath;
        config.ioThreads = 2;
        // Keep the tests quick; the production defaults are minutes.
        config.headerTimeoutSec = 2;
        config.bodyTimeoutSec = 2;
        config.responseTimeoutSec = 5;
        config.drainTimeoutSec = 1;
        return config;
    }
} // namespace

TEST(UdsHttpServerTest, RegisteredRouteAnswers200)
{
    const auto path = uniqueSocketPath("ok");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(configFor(path));

    const auto response = sendRaw(path, peerRequest("POST", "/inventory/sync", "payload"));

    ASSERT_TRUE(response.connected);
    EXPECT_EQ(200, response.status);
    EXPECT_EQ(R"({"ok":true})", response.body);
    EXPECT_EQ("application/json", response.header("Content-Type"));
    EXPECT_EQ("close", response.header("Connection"));
    EXPECT_EQ(std::to_string(response.body.size()), response.header("Content-Length"));
}

// The handler must see exactly what the peer sent, byte for byte.
TEST(UdsHttpServerTest, HandlerReceivesTheRequestVerbatim)
{
    const auto path = uniqueSocketPath("verbatim");
    std::string seenTarget;
    std::string seenBody;
    std::string seenContentType;
    Method seenMethod {Method::Get};

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [&](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
                     {
                         seenTarget = request->target;
                         seenBody = request->body;
                         seenMethod = request->method;
                         const auto it = request->headers.find("content-type");
                         seenContentType = it == request->headers.end() ? "" : it->second;
                         responder->send(HttpResponse::json(200, "{}"));
                     });
    server->start(configFor(path));

    const std::string body(5000, 'x');
    const auto response = sendRaw(path, peerRequest("POST", "/inventory/sync?m=fim", body));

    ASSERT_EQ(200, response.status);
    EXPECT_EQ("/inventory/sync?m=fim", seenTarget) << "the raw target, query included";
    EXPECT_EQ(body, seenBody);
    EXPECT_EQ(Method::Post, seenMethod);
    EXPECT_EQ("application/octet-stream", seenContentType);
}

TEST(UdsHttpServerTest, UnknownPathAnswers404)
{
    const auto path = uniqueSocketPath("404");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(configFor(path));

    const auto response = sendRaw(path, peerRequest("POST", "/nope", "x"));
    EXPECT_EQ(404, response.status);
}

// A path that exists under a different verb gets 405 with Allow, not a misleading 404.
TEST(UdsHttpServerTest, WrongMethodAnswers405WithAllowHeader)
{
    const auto path = uniqueSocketPath("405");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(configFor(path));

    const auto response = sendRaw(path, peerRequest("PUT", "/inventory/sync", "x"));
    EXPECT_EQ(405, response.status);
    EXPECT_EQ("POST", response.header("Allow"));
}

TEST(UdsHttpServerTest, RoutingIgnoresTheQueryString)
{
    const auto path = uniqueSocketPath("query");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(configFor(path));

    const auto response = sendRaw(path, peerRequest("POST", "/inventory/sync?a=1&b=2", "x"));
    EXPECT_EQ(200, response.status);
}

// bind() applies the umask, so without an explicit chmod the peer -- a different user in the same
// group -- can get EACCES on a socket that looks fine. Run under a hostile umask to make the point.
TEST(UdsHttpServerTest, SocketIsCreatedWithTheConfiguredMode)
{
    const auto path = uniqueSocketPath("mode");
    const auto previousUmask = ::umask(0077);

    {
        auto server = makeUdsHttpServer();
        server->addRoute(Method::Get, "/", echoHandler());
        server->start(configFor(path));

        struct stat info
        {
        };
        ASSERT_EQ(0, ::stat(path.c_str(), &info));
        EXPECT_TRUE(S_ISSOCK(info.st_mode));
        EXPECT_EQ(0660U, info.st_mode & 07777U);
    }

    ::umask(previousUmask);
}

// A stale socket file from an unclean shutdown must not wedge the module forever with EADDRINUSE.
TEST(UdsHttpServerTest, StartUnlinksAStaleSocketFile)
{
    const auto path = uniqueSocketPath("stale");

    // Reproduce what a kill -9 leaves behind: a bound socket file whose owner is gone. Closing the
    // descriptor does not remove the file, so this is exactly the on-disk state after a hard kill.
    {
        asio::io_context ioc;
        invsync::test::stream_protocol::acceptor acceptor {ioc};
        const invsync::test::stream_protocol::endpoint endpoint {path};
        acceptor.open(endpoint.protocol());
        acceptor.bind(endpoint);
        acceptor.listen();
    }
    ASSERT_TRUE(std::filesystem::exists(path)) << "the stale socket file must survive its owner";

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get, "/", echoHandler());
    ASSERT_NO_THROW(server->start(configFor(path)));

    const auto response = sendRaw(path, peerRequest("GET", "/", ""));
    EXPECT_EQ(200, response.status);
}

// Deliberately stricter than cpp-httplib, which unlinks whatever is in the way: a typo in the
// configured path must not delete an operator's file.
TEST(UdsHttpServerTest, StartRefusesToUnlinkANonSocketPath)
{
    const auto path = uniqueSocketPath("regular");
    {
        std::ofstream file {path};
        file << "important";
    }

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get, "/", echoHandler());
    EXPECT_THROW(server->start(configFor(path)), std::runtime_error);
    EXPECT_TRUE(std::filesystem::exists(path)) << "the operator's file must survive";

    std::filesystem::remove(path);
}

// asio's own failure for an overlong path is opaque, so the message has to name the path and the cap.
TEST(UdsHttpServerTest, StartThrowsOnAnOverlongSocketPath)
{
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get, "/", echoHandler());

    auto config = configFor("/tmp/" + std::string(200, 'p') + ".sock");
    try
    {
        server->start(config);
        FAIL() << "an overlong socket path must be refused";
    }
    catch (const std::runtime_error& e)
    {
        const std::string message {e.what()};
        EXPECT_NE(std::string::npos, message.find("socket path")) << message;
        EXPECT_NE(std::string::npos, message.find("limit")) << message;
    }
}

TEST(UdsHttpServerTest, StopUnlinksTheSocketFile)
{
    const auto path = uniqueSocketPath("unlink");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get, "/", echoHandler());
    server->start(configFor(path));
    ASSERT_TRUE(std::filesystem::exists(path));

    server->stop();
    EXPECT_FALSE(std::filesystem::exists(path));
}

/**
 * An oversized body is refused with 413 decided from the DECLARED Content-Length, before a body byte
 * is read. The body here is small enough to fit in the socket buffer, so the peer's write completes
 * and it reads the status normally -- which is the realistic case.
 *
 * See the INTEROP NOTE in asioUdsHttpServer.cpp for what happens when the rejected body is large
 * enough that the peer is still writing when we close: it sees a transport failure instead of this
 * status. That is deliberate, and it is why remoted caps the body on its own inbound side.
 */
TEST(UdsHttpServerTest, OversizedBodyAnswers413)
{
    const auto path = uniqueSocketPath("413");
    auto config = configFor(path);
    config.maxBodySize = 1024;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(config);

    const auto response = sendRaw(path, peerRequest("POST", "/inventory/sync", std::string(4096, 'x')));
    EXPECT_EQ(413, response.status);
    EXPECT_EQ("close", response.header("Connection"));
}

// Same for the other rejections decided at the head: a modest body still lets the peer read the
// status, which is what a mis-routed request looks like in practice.
TEST(UdsHttpServerTest, MisroutedRequestWithABodyStillReadsIts404)
{
    const auto path = uniqueSocketPath("404body");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(configFor(path));

    const auto response = sendRaw(path, peerRequest("POST", "/nope", std::string(4096, 'x')));

    ASSERT_TRUE(response.connected);
    EXPECT_EQ(404, response.status);
}

/**
 * The documented consequence, pinned so it is a known behaviour rather than a surprise: when the
 * rejected body is far larger than the socket buffer, the peer is still writing when we close, so it
 * observes a truncated connection instead of the status. If a future change makes the server drain
 * rejected bodies, this test is the one that should be rewritten to expect 413.
 */
TEST(UdsHttpServerTest, ALargeRejectedBodyTruncatesTheConnectionRatherThanDelivering413)
{
    const auto path = uniqueSocketPath("413big");
    auto config = configFor(path);
    config.maxBodySize = 4096;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(config);

    // Far larger than one socket buffer, so the peer cannot finish writing before we reject.
    const auto response = sendRaw(
        path, peerRequest("POST", "/inventory/sync", std::string(2 * 1024 * 1024, 'x')), std::chrono::seconds {5});

    ASSERT_TRUE(response.connected);
    EXPECT_NE(413, response.status) << "if this now delivers 413, the server started draining -- update this test";
}

TEST(UdsHttpServerTest, ChunkedRequestAnswers411)
{
    const auto path = uniqueSocketPath("411");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(configFor(path));

    const std::string request {"POST /inventory/sync HTTP/1.1\r\n"
                               "Host: localhost\r\n"
                               "Transfer-Encoding: chunked\r\n"
                               "\r\n"
                               "5\r\nhello\r\n0\r\n\r\n"};
    const auto response = sendRaw(path, request);
    EXPECT_EQ(411, response.status);
}

TEST(UdsHttpServerTest, MalformedHttpAnswers400)
{
    const auto path = uniqueSocketPath("400");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(configFor(path));

    const auto response = sendRaw(path, "GARBAGE NOT HTTP\r\n\r\n");
    EXPECT_EQ(400, response.status);
}

// Half a request line and then silence: the connection must be reclaimed, not held.
TEST(UdsHttpServerTest, HeaderTimeoutClosesASlowloris)
{
    const auto path = uniqueSocketPath("slow");
    auto config = configFor(path);
    config.headerTimeoutSec = 1;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(config);

    const auto start = std::chrono::steady_clock::now();
    const auto response = sendRaw(path, "POST /inventory/sync HTT", std::chrono::seconds {8});
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_TRUE(response.connected);
    EXPECT_LT(elapsed, std::chrono::seconds {6}) << "the server must close it, not wait for the client";
}

// The whole reason this transport exists: the handler returns without answering, and the reply is
// produced later from a different thread.
TEST(UdsHttpServerTest, DeferredReplyFromAnotherThreadArrivesAfterTheHandlerReturned)
{
    const auto path = uniqueSocketPath("defer");
    // Set by the handler itself, as its very last statement -- so the worker below can prove the
    // handler had already returned when the reply was produced.
    std::atomic_bool handlerReturned {false};
    std::thread worker;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [&](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         // Move the responder off the I/O thread and reply much later.
                         worker = std::thread {[responder, &handlerReturned]
                                               {
                                                   std::this_thread::sleep_for(std::chrono::milliseconds {300});
                                                   EXPECT_TRUE(handlerReturned.load())
                                                       << "the handler must have returned before the reply is sent";
                                                   responder->send(HttpResponse::json(202, R"({"deferred":true})"));
                                               }};
                         handlerReturned.store(true);
                     });
    server->start(configFor(path));

    const auto response = sendRaw(path, peerRequest("POST", "/inventory/sync", "payload"));

    if (worker.joinable())
    {
        worker.join();
    }

    // The reply arrives even though the handler had long since returned.
    EXPECT_EQ(202, response.status);
    EXPECT_EQ(R"({"deferred":true})", response.body);
}

/**
 * @brief The headline requirement, stated so it can fail: hundreds of concurrent deferrals on two
 *        I/O threads.
 *
 * This is the test a blocking thread-per-request server cannot pass. With cpp-httplib's fixed pool
 * (max(2, nproc-1)) all but a handful of these would sit in the accept backlog until the earlier
 * ones finished, and the whole run would serialize.
 */
TEST(UdsHttpServerTest, ThreeHundredConcurrentDeferralsOnTwoIoThreads)
{
    constexpr int CONCURRENCY {300};

    const auto path = uniqueSocketPath("many");
    auto config = configFor(path);
    config.ioThreads = 2;
    config.maxConnections = 1024;
    config.responseTimeoutSec = 30;
    config.drainTimeoutSec = 5;

    std::mutex parkedMutex;
    std::vector<std::shared_ptr<IHttpResponder>> parked;
    std::atomic<int> dispatched {0};

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [&](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         {
                             std::lock_guard<std::mutex> lock {parkedMutex};
                             parked.push_back(std::move(responder));
                         }
                         dispatched.fetch_add(1);
                     });
    server->start(config);

    // Fire every request concurrently; each blocks in its own thread waiting for a reply that only
    // comes once ALL of them are parked, so they genuinely overlap.
    std::vector<std::future<invsync::test::Response>> pending;
    pending.reserve(CONCURRENCY);
    for (int i = 0; i < CONCURRENCY; ++i)
    {
        pending.push_back(std::async(
            std::launch::async,
            [&path]
            { return sendRaw(path, peerRequest("POST", "/inventory/sync", "payload"), std::chrono::seconds {60}); }));
    }

    // Wait for all of them to be sitting in the parked list at the same time.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {30};
    while (dispatched.load() < CONCURRENCY && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {10});
    }
    ASSERT_EQ(CONCURRENCY, dispatched.load()) << "all requests must be in flight simultaneously";

    // Now release them all.
    {
        std::lock_guard<std::mutex> lock {parkedMutex};
        for (auto& responder : parked)
        {
            responder->send(HttpResponse::json(202, R"({"released":true})"));
        }
        parked.clear();
    }

    int answered {0};
    for (auto& future : pending)
    {
        const auto response = future.get();
        if (response.status == 202)
        {
            ++answered;
        }
    }
    EXPECT_EQ(CONCURRENCY, answered) << "every deferred reply must reach its own connection";
}

// The payload is released when the handler drops the request, independently of -- and usually long
// before -- the reply. That is what keeps the byte budget honest under deep deferral.
TEST(UdsHttpServerTest, DroppingTheRequestReleasesItsBudgetBeforeTheReplyIsSent)
{
    const auto path = uniqueSocketPath("release");
    auto config = configFor(path);
    config.maxBodySize = 64 * 1024;
    // Room for exactly one in-flight request; a second would be shed with 503 while the first is
    // still resident.
    config.maxInFlightBytes = config.maxBodySize + (16U * 1024U);

    // A vector, not a single slot: overwriting one responder would drop it, and a dropped responder
    // is answered 503 by the abandonment backstop -- which would make this test pass for the wrong
    // reason.
    std::mutex parkedMutex;
    std::vector<std::shared_ptr<IHttpResponder>> parked;
    std::atomic<int> dropped {0};

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [&](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
                     {
                         {
                             std::lock_guard<std::mutex> lock {parkedMutex};
                             parked.push_back(std::move(responder));
                         }
                         request.reset(); // release the payload and its reservation now
                         dropped.fetch_add(1);
                     });
    server->start(config);

    auto first = std::async(std::launch::async,
                            [&path]
                            {
                                return sendRaw(path,
                                               peerRequest("POST", "/inventory/sync", std::string(32 * 1024, 'x')),
                                               std::chrono::seconds {30});
                            });

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {10};
    while (dropped.load() < 1 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {5});
    }
    ASSERT_EQ(1, dropped.load());

    // The first reply has NOT been sent yet, but its payload is gone -- so a second request of the
    // same size must be admitted rather than shed with 503.
    auto second = std::async(std::launch::async,
                             [&path]
                             {
                                 return sendRaw(path,
                                                peerRequest("POST", "/inventory/sync", std::string(32 * 1024, 'y')),
                                                std::chrono::seconds {30});
                             });

    deadline = std::chrono::steady_clock::now() + std::chrono::seconds {10};
    while (dropped.load() < 2 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {5});
    }
    EXPECT_EQ(2, dropped.load()) << "the second request must reach the handler, not be shed with 503";

    // Answer both explicitly, so neither status comes from a timeout or the abandonment backstop.
    {
        std::lock_guard<std::mutex> lock {parkedMutex};
        for (auto& responder : parked)
        {
            responder->send(HttpResponse::json(202, "{}"));
        }
        parked.clear();
    }

    EXPECT_EQ(202, first.get().status);
    EXPECT_EQ(202, second.get().status);
}

// Over the connection cap the server answers explicitly instead of closing silently, so the peer
// classifies it as "out of capacity" rather than as a transport failure.
TEST(UdsHttpServerTest, ConnectionCapAnswersAnExplicit503)
{
    const auto path = uniqueSocketPath("cap");
    auto config = configFor(path);
    config.maxConnections = 1;
    config.responseTimeoutSec = 20;

    std::shared_ptr<IHttpResponder> parked;
    std::atomic_bool parkedReady {false};

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [&](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         parked = std::move(responder);
                         parkedReady.store(true);
                     });
    server->start(config);

    auto held = std::async(
        std::launch::async,
        [&path] { return sendRaw(path, peerRequest("POST", "/inventory/sync", "held"), std::chrono::seconds {30}); });

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {10};
    while (!parkedReady.load() && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {5});
    }
    ASSERT_TRUE(parkedReady.load());

    const auto refused = sendRaw(path, peerRequest("POST", "/inventory/sync", "refused"));
    EXPECT_EQ(503, refused.status);

    if (parked)
    {
        parked->send(HttpResponse::json(202, "{}"));
    }
    held.get();
}

// A handler bug must produce a status, never take the I/O thread -- and therefore the daemon -- down.
// The non-std throw is the dangerous case; a std::exception was never the exposure.
TEST(UdsHttpServerTest, HandlerThrowingANonStandardExceptionAnswers500AndTheServerKeepsServing)
{
    const auto path = uniqueSocketPath("throw");
    auto server = makeUdsHttpServer();
    server->addRoute(
        Method::Post, "/boom", [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>) { throw 42; });
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(configFor(path));

    const auto failed = sendRaw(path, peerRequest("POST", "/boom", "x"));
    EXPECT_EQ(500, failed.status);

    // The load-bearing half: the reactor is still at full width afterwards.
    const auto after = sendRaw(path, peerRequest("POST", "/inventory/sync", "x"));
    EXPECT_EQ(200, after.status);
}

// A handler that drops its responder without answering is a bug, but the peer must not hang for it.
TEST(UdsHttpServerTest, DroppedResponderAnswers503Immediately)
{
    const auto path = uniqueSocketPath("dropped");
    auto config = configFor(path);
    config.responseTimeoutSec = 30; // far longer than this test may take

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>)
                     {
                         // Responder goes out of scope unsent.
                     });
    server->start(config);

    const auto start = std::chrono::steady_clock::now();
    const auto response = sendRaw(path, peerRequest("POST", "/inventory/sync", "x"));
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(503, response.status);
    EXPECT_LT(elapsed, std::chrono::seconds {5}) << "the destructor backstop must fire, not the timeout";
}

// The slower backstop: a responder that is retained and never used.
TEST(UdsHttpServerTest, NeverAnsweredResponderTimesOutWith504)
{
    const auto path = uniqueSocketPath("504");
    auto config = configFor(path);
    config.responseTimeoutSec = 1;

    // Held for the process's lifetime on purpose, so the destructor backstop cannot fire and the
    // timer is the only thing left to save the connection.
    static std::vector<std::shared_ptr<IHttpResponder>> forever;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { forever.push_back(std::move(responder)); });
    server->start(config);

    const auto response = sendRaw(path, peerRequest("POST", "/inventory/sync", "x"), std::chrono::seconds {10});
    EXPECT_EQ(504, response.status);
}

TEST(UdsHttpServerTest, AddRouteAfterStartThrows)
{
    const auto path = uniqueSocketPath("late");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get, "/", echoHandler());
    server->start(configFor(path));

    EXPECT_THROW(server->addRoute(Method::Post, "/late", echoHandler()), std::logic_error);
}

TEST(UdsHttpServerTest, StartTwiceThrows)
{
    const auto path = uniqueSocketPath("twice");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get, "/", echoHandler());
    server->start(configFor(path));

    EXPECT_THROW(server->start(configFor(uniqueSocketPath("twice2"))), std::logic_error);
}

TEST(UdsHttpServerTest, StopWithoutStartIsSafe)
{
    auto server = makeUdsHttpServer();
    EXPECT_NO_THROW(server->stop());
    EXPECT_NO_THROW(server->stopAccepting());
}

TEST(UdsHttpServerTest, StopIsIdempotent)
{
    const auto path = uniqueSocketPath("idem");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get, "/", echoHandler());
    server->start(configFor(path));

    EXPECT_NO_THROW(server->stop());
    EXPECT_NO_THROW(server->stop());
    EXPECT_NO_THROW(server->stopAccepting());
}

// The budget is clamped up rather than left to reject everything silently.
TEST(UdsHttpServerTest, ATooSmallInFlightBudgetIsClampedRatherThanRejectingEverything)
{
    const auto path = uniqueSocketPath("clamp");
    auto config = configFor(path);
    config.maxBodySize = 1024 * 1024;
    config.maxInFlightBytes = 16; // absurdly below one maximum-size request

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(config);

    const auto response = sendRaw(path, peerRequest("POST", "/inventory/sync", "small"));
    EXPECT_EQ(200, response.status);
}
