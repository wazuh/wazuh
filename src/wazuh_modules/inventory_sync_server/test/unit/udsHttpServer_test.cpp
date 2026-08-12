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
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
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

        struct stat info {};
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
    std::condition_variable parkedCv;
    std::vector<std::shared_ptr<IHttpResponder>> parked;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [&](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         {
                             std::lock_guard<std::mutex> lock {parkedMutex};
                             parked.push_back(std::move(responder));
                         }
                         parkedCv.notify_one();
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

    // Wait for all of them to be sitting in the parked list at the same time. The 120s cap is a
    // deadlock guard only; the condition variable resolves the wait as soon as the last request
    // lands, so this no longer races against CPU availability under ASan/CI load.
    {
        std::unique_lock<std::mutex> lock {parkedMutex};
        parkedCv.wait_for(
            lock, std::chrono::seconds {120}, [&] { return parked.size() >= static_cast<size_t>(CONCURRENCY); });
        ASSERT_EQ(static_cast<size_t>(CONCURRENCY), parked.size()) << "all requests must be in flight simultaneously";
    }

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
    std::condition_variable parkedCv;
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
                         {
                             std::lock_guard<std::mutex> lock {parkedMutex};
                             dropped.fetch_add(1);
                         }
                         parkedCv.notify_one();
                     });
    server->start(config);

    auto first = std::async(std::launch::async,
                            [&path]
                            {
                                return sendRaw(path,
                                               peerRequest("POST", "/inventory/sync", std::string(32 * 1024, 'x')),
                                               std::chrono::seconds {30});
                            });

    {
        std::unique_lock<std::mutex> lock {parkedMutex};
        parkedCv.wait_for(lock, std::chrono::seconds {10}, [&] { return dropped.load() >= 1; });
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

    {
        std::unique_lock<std::mutex> lock {parkedMutex};
        parkedCv.wait_for(lock, std::chrono::seconds {10}, [&] { return dropped.load() >= 2; });
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

    std::mutex parkedMutex;
    std::condition_variable parkedCv;
    std::shared_ptr<IHttpResponder> parked;
    std::atomic_bool parkedReady {false};

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [&](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         {
                             std::lock_guard<std::mutex> lock {parkedMutex};
                             parked = std::move(responder);
                             parkedReady.store(true);
                         }
                         parkedCv.notify_one();
                     });
    server->start(config);

    auto held = std::async(
        std::launch::async,
        [&path] { return sendRaw(path, peerRequest("POST", "/inventory/sync", "held"), std::chrono::seconds {30}); });

    {
        std::unique_lock<std::mutex> lock {parkedMutex};
        parkedCv.wait_for(lock, std::chrono::seconds {10}, [&] { return parkedReady.load(); });
    }
    ASSERT_TRUE(parkedReady.load());

    const auto refused = sendRaw(path, peerRequest("POST", "/inventory/sync", "refused"));
    EXPECT_EQ(503, refused.status);

    {
        std::lock_guard<std::mutex> lock {parkedMutex};
        if (parked)
        {
            parked->send(HttpResponse::json(202, "{}"));
        }
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

/**
 * @brief One blocked handler must not stall the other connections.
 *
 * This is the test that fails when a Session's socket handlers are not bound to its own strand. An
 * accepted socket inherits the acceptor's executor, and the acceptor lives on ONE shared strand, so
 * without asio::bind_executor every connection's read handler -- and therefore every route handler,
 * which is invoked from it -- serializes onto that single strand no matter how many I/O threads are
 * configured. A dependency that blocks inside a handler then freezes the whole transport, including
 * the liveness route.
 *
 * A blocking handler is not hypothetical: the /stats and /config handlers call the indexer's
 * isAvailable(), which takes a lock the monitoring thread holds for the whole health-check round.
 */
TEST(UdsHttpServerTest, ASlowHandlerOnOneConnectionDoesNotStallAnother)
{
    constexpr auto SLOW_HANDLER_BLOCK = std::chrono::milliseconds {2000};

    const auto path = uniqueSocketPath("strand");
    auto config = configFor(path);
    config.ioThreads = 2;
    config.responseTimeoutSec = 30;

    std::mutex slowMutex;
    std::condition_variable slowCv;
    std::atomic_bool insideSlowHandler {false};

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/slow",
                     [&](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         {
                             std::lock_guard<std::mutex> lock {slowMutex};
                             insideSlowHandler.store(true);
                         }
                         slowCv.notify_one();
                         // Blocks the I/O thread on purpose, exactly like a lock held elsewhere.
                         std::this_thread::sleep_for(SLOW_HANDLER_BLOCK);
                         responder->send(HttpResponse::json(200, R"({"slow":true})"));
                     });
    server->addRoute(Method::Get, "/", echoHandler(R"({"status":"ok"})"));
    server->start(config);

    auto slow =
        std::async(std::launch::async,
                   [&path] { return sendRaw(path, peerRequest("POST", "/slow", "x"), std::chrono::seconds {30}); });

    // Only measure once the slow handler is genuinely occupying an I/O thread.
    {
        std::unique_lock<std::mutex> lock {slowMutex};
        slowCv.wait_for(lock, std::chrono::seconds {5}, [&] { return insideSlowHandler.load(); });
    }
    ASSERT_TRUE(insideSlowHandler.load()) << "the slow handler never ran";

    const auto before = std::chrono::steady_clock::now();
    const auto liveness = sendRaw(path, peerRequest("GET", "/", ""), std::chrono::seconds {30});
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - before);

    EXPECT_EQ(200, liveness.status);
    // Generous: the point is "not serialized behind the 2 s block", not a latency budget.
    EXPECT_LT(elapsed, SLOW_HANDLER_BLOCK / 2)
        << "the liveness route waited " << elapsed.count()
        << " ms behind a blocked handler on another connection; its socket handlers are running on the "
           "shared acceptor strand instead of the session's own";

    EXPECT_EQ(200, slow.get().status);
}

/**
 * @brief A request the handler keeps past the server's own lifetime must still release cleanly.
 *
 * The contract lets a handler hold the request "so it can travel across deferred queues", and the
 * reservation that travels with it holds a RAW pointer into ServerState::budget. Without the
 * RequestContext co-owning the ServerState, releasing the request after the server is gone runs
 * ~Reservation against a destroyed budget.
 *
 * Reaches for the defect rather than proving its absence: it is a use-after-free, so the ASAN job is
 * what turns this into a real check. Without a sanitizer it usually passes either way.
 */
TEST(UdsHttpServerTest, ARequestOutlivingTheServerReleasesItsReservationSafely)
{
    const auto path = uniqueSocketPath("outlive");

    std::shared_ptr<const HttpRequest> escaped;
    {
        auto server = makeUdsHttpServer();
        server->addRoute(
            Method::Post,
            "/inventory/sync",
            [&escaped](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
            {
                escaped = std::move(request); // deliberately outlives the server
                responder->send(HttpResponse::json(200, "{}"));
            });
        server->start(configFor(path));

        ASSERT_EQ(200, sendRaw(path, peerRequest("POST", "/inventory/sync", std::string(4096, 'z'))).status);
        ASSERT_NE(nullptr, escaped);

        server->stop();
    } // the server, its ServerState and its budget are gone here

    EXPECT_EQ(4096U, escaped->body.size()) << "the payload must still be readable";
    EXPECT_NO_THROW(escaped.reset()) << "releasing it must not touch the destroyed budget";
}

// Two concurrent shutdowns must not race on the thread pool: the loser of the lifecycle CAS used to
// walk into joinThreads() while the winner was still reading threads.size() and clearing the vector.
// The facade calls stop() and then destroys the server, so both really can overlap.
TEST(UdsHttpServerTest, ConcurrentStopCallsDoNotRaceOnTheThreadPool)
{
    constexpr int STOPPERS {4};

    const auto path = uniqueSocketPath("racestop");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(configFor(path));

    ASSERT_EQ(200, sendRaw(path, peerRequest("POST", "/inventory/sync", "x")).status);

    std::vector<std::thread> stoppers;
    stoppers.reserve(STOPPERS);
    for (int i = 0; i < STOPPERS; ++i)
    {
        stoppers.emplace_back([&server, i] { (i % 2 == 0) ? server->stop() : server->stopAccepting(); });
    }
    for (auto& thread : stoppers)
    {
        thread.join();
    }

    // Destroying afterwards runs doStop() one more time, from yet another path.
    EXPECT_NO_THROW(server.reset());
}

// Teardown unlinks only the socket this server bound. bindAcceptor() removes any stale socket it
// finds at the path, so two servers racing for one path can swap inodes -- and unconditionally
// unlinking on the way out would silently take down whoever bound it second.
TEST(UdsHttpServerTest, StopDoesNotUnlinkAFileThatReplacedItsSocket)
{
    const auto path = uniqueSocketPath("inode");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get, "/", echoHandler());
    server->start(configFor(path));

    ASSERT_TRUE(std::filesystem::exists(path));

    // Stand in for "another process rebound this path": a different inode, same name.
    std::filesystem::remove(path);
    {
        std::ofstream replacement {path};
        replacement << "not ours";
    }
    ASSERT_TRUE(std::filesystem::exists(path));

    server->stop();

    EXPECT_TRUE(std::filesystem::exists(path)) << "teardown removed a file it did not create";
    std::filesystem::remove(path);
}

// The rejections decided at headers-complete must produce their real status line, not a default "OK".
// The parser already gets these right in isolation; nothing checked them end to end through the
// transport's own status-line and body serialization.
TEST(UdsHttpServerTest, AnOverlongTargetAnswers414AndOversizedHeadersAnswer431)
{
    const auto path = uniqueSocketPath("limits");
    auto config = configFor(path);
    config.maxUrlSize = 64;
    config.maxHeaderValueSize = 64;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(config);

    const std::string longTarget = "/inventory/sync?" + std::string(200, 'q');
    const auto tooLongUrl = sendRaw(path, "POST " + longTarget + " HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
    EXPECT_EQ(414, tooLongUrl.status) << tooLongUrl.body;

    const auto bigHeader = sendRaw(path,
                                   "POST /inventory/sync HTTP/1.1\r\nHost: x\r\nX-Big: " + std::string(200, 'v') +
                                       "\r\nContent-Length: 0\r\n\r\n");
    EXPECT_EQ(431, bigHeader.status) << bigHeader.body;
}

// The Allow header has to list the verbs registered on THAT path only -- listing another path's verbs
// would send the peer to retry with a method this endpoint does not accept.
TEST(UdsHttpServerTest, The405AllowHeaderListsEveryVerbRegisteredOnThatPathOnly)
{
    const auto path = uniqueSocketPath("allow");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get, "/multi", echoHandler());
    server->addRoute(Method::Post, "/multi", echoHandler());
    server->addRoute(Method::Delete, "/other", echoHandler());
    server->start(configFor(path));

    const auto response = sendRaw(path, peerRequest("PUT", "/multi", ""));

    ASSERT_EQ(405, response.status);
    const auto allow = response.header("Allow");
    EXPECT_NE(std::string::npos, allow.find("GET")) << allow;
    EXPECT_NE(std::string::npos, allow.find("POST")) << allow;
    EXPECT_EQ(std::string::npos, allow.find("DELETE")) << "another path's verb leaked into Allow: " << allow;
}

// The std::exception half of the handler exception barrier -- the one that logs e.what(), which is the
// only text an operator gets. Only the non-standard half was covered.
TEST(UdsHttpServerTest, HandlerThrowingAStandardExceptionAnswers500AndTheServerKeepsServing)
{
    const auto path = uniqueSocketPath("throwstd");
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>)
                     { throw std::runtime_error {"handler blew up"}; });
    server->addRoute(Method::Get, "/", echoHandler());
    server->start(configFor(path));

    EXPECT_EQ(500, sendRaw(path, peerRequest("POST", "/inventory/sync", "x")).status);
    EXPECT_EQ(200, sendRaw(path, peerRequest("GET", "/", "")).status) << "one bad handler must not end the server";
}

// 0 means "size the reactor from the host/cgroup", which is the production default. Pinned through the
// transport, not just the config builder.
TEST(UdsHttpServerTest, ZeroIoThreadsStillServes)
{
    const auto path = uniqueSocketPath("zerothreads");
    auto config = configFor(path);
    config.ioThreads = 0;

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Get, "/", echoHandler());
    server->start(config);

    EXPECT_EQ(200, sendRaw(path, peerRequest("GET", "/", "")).status);
}

// A peer that disappears mid-head must release its session immediately rather than pinning a
// descriptor until the header deadline expires. Uses a raw socket so the close is unambiguous, rather
// than relying on a client-side timeout.
TEST(UdsHttpServerTest, APeerThatClosesMidRequestReleasesItsSessionPromptly)
{
    const auto path = uniqueSocketPath("midclose");
    auto config = configFor(path);
    config.headerTimeoutSec = 30; // long, so a prompt stop() cannot be the header timeout doing the work

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post, "/inventory/sync", echoHandler());
    server->start(config);

    for (int i = 0; i < 5; ++i)
    {
        asio::io_context ioc;
        invsync::test::stream_protocol::socket socket {ioc};
        socket.connect(invsync::test::stream_protocol::endpoint {path});
        const std::string partial {"POST /inventory/sync HTTP/1.1\r\nHost: local"};
        asio::write(socket, asio::buffer(partial));
        socket.close(); // EOF, mid-head
    }

    // If those sessions were still resident, stop() would sit out its whole drain window instead.
    const auto before = std::chrono::steady_clock::now();
    server->stop();
    const auto elapsed = std::chrono::steady_clock::now() - before;

    EXPECT_LT(elapsed, std::chrono::seconds {3}) << "abandoned sessions were not released on EOF";
}

/**
 * @brief The overload brake: a second request while the budget is held is shed with an explicit 503.
 *
 * inFlightBudget_test covers the accounting class; this is the transport actually applying it, which was
 * never exercised -- the existing budget test proves a reservation is RELEASED, not that exhausting one
 * rejects anything.
 *
 * The budget is deliberately set to 1: start() clamps it up to exactly one maximum-size request, so a
 * first request of maxBodySize consumes all of it and a second has nowhere to go.
 */
TEST(UdsHttpServerTest, ASecondRequestIsShedWith503WhileTheBudgetIsHeldByADeferral)
{
    const auto path = uniqueSocketPath("shed");
    auto config = configFor(path);
    config.maxBodySize = 32 * 1024;
    config.maxInFlightBytes = 1;
    config.responseTimeoutSec = 30;

    std::mutex parkedMutex;
    std::condition_variable parkedCv;
    std::vector<std::shared_ptr<IHttpResponder>> parked;
    std::vector<std::shared_ptr<const HttpRequest>> held;
    std::atomic<int> dispatched {0};

    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/inventory/sync",
                     [&](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
                     {
                         {
                             std::lock_guard<std::mutex> lock {parkedMutex};
                             parked.push_back(std::move(responder));
                             // Holding the request is what keeps its reservation outstanding.
                             held.push_back(std::move(request));
                             dispatched.fetch_add(1);
                         }
                         parkedCv.notify_one();
                     });
    server->start(config);

    const std::string body(32 * 1024, 'x');
    auto first =
        std::async(std::launch::async,
                   [&path, &body]
                   { return sendRaw(path, peerRequest("POST", "/inventory/sync", body), std::chrono::seconds {30}); });

    {
        std::unique_lock<std::mutex> lock {parkedMutex};
        parkedCv.wait_for(lock, std::chrono::seconds {10}, [&] { return dispatched.load() >= 1; });
    }
    ASSERT_EQ(1, dispatched.load()) << "the first request never reached the handler";

    const auto shed = sendRaw(path, peerRequest("POST", "/inventory/sync", body), std::chrono::seconds {10});
    EXPECT_EQ(503, shed.status) << "the second request must be shed explicitly, not queued: " << shed.body;
    EXPECT_EQ(1, dispatched.load()) << "the shed request must never reach the handler";

    {
        std::lock_guard<std::mutex> lock {parkedMutex};
        for (auto& responder : parked)
        {
            responder->send(HttpResponse::json(202, R"({"released":true})"));
        }
        parked.clear();
        held.clear();
    }

    EXPECT_EQ(202, first.get().status);
}
