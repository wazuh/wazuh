/*
 * Wazuh shared UDS HTTP server library - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// A final response that becomes ready while the interim "100 Continue" is still being written must be
// parked and written after it: two writes in flight on one socket would interleave their bytes. On a
// local socket that 25-byte write completes at once, so these tests hold it open through the test seam
// (test/unit/testHooks.hpp, a link-time override of the library default) and drive each kind of final
// response into that window.

#include "testHooks.hpp"
#include "udsTestClient.hpp"
#include <uds_http_server/IUdsHttpServer.hpp>
#include <uds_http_server/udsHttpServerFactory.hpp>

#include <gtest/gtest.h>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

using wazuh::uds_http::HttpRequest;
using wazuh::uds_http::HttpResponse;
using wazuh::uds_http::IHttpResponder;
using wazuh::uds_http::makeUdsHttpServer;
using wazuh::uds_http::Method;
using wazuh::uds_http::UdsHttpServerConfig;
using wazuh::uds_http::test::uniqueSocketPath;

namespace
{
    constexpr auto INTERIM_CONTINUE = "HTTP/1.1 100 Continue\r\n\r\n";

    UdsHttpServerConfig configFor(const std::string& socketPath)
    {
        UdsHttpServerConfig config;
        config.socketPath = socketPath;
        config.ioThreads = 2;
        config.headerTimeoutSec = 5;
        config.bodyTimeoutSec = 5;
        config.responseTimeoutSec = 5;
        config.drainTimeoutSec = 1;
        config.expectContinue = true;
        return config;
    }

    std::string headExpecting(std::size_t length)
    {
        return "POST /events HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\nContent-Length: " +
               std::to_string(length) + "\r\nConnection: close\r\n\r\n";
    }

    /// Holds every interim write in flight until release(). Declare it AFTER the server: its
    /// destructor releases a write still held, which needs the server alive.
    class HeldInterimWrite
    {
    public:
        HeldInterimWrite()
        {
            wazuh::uds_http::test_hooks::setInterimWriteHook(
                [this](std::function<void()> startWrite)
                {
                    std::lock_guard lock {m_mutex};
                    m_startWrite = std::move(startWrite);
                    m_held.notify_all();
                });
        }

        ~HeldInterimWrite()
        {
            wazuh::uds_http::test_hooks::setInterimWriteHook({});
            release();
        }

        HeldInterimWrite(const HeldInterimWrite&) = delete;
        HeldInterimWrite& operator=(const HeldInterimWrite&) = delete;

        bool waitHeld(std::chrono::milliseconds timeout = std::chrono::seconds {5})
        {
            std::unique_lock lock {m_mutex};
            return m_held.wait_for(lock, timeout, [this] { return static_cast<bool>(m_startWrite); });
        }

        void release()
        {
            std::function<void()> startWrite;
            {
                std::lock_guard lock {m_mutex};
                startWrite = std::move(m_startWrite);
                m_startWrite = nullptr;
            }
            if (startWrite)
            {
                startWrite();
            }
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_held;
        std::function<void()> m_startWrite;
    };

    /// A blocking POSIX client: the test decides exactly when each part of the request is sent.
    class Peer
    {
    public:
        explicit Peer(const std::string& path)
        {
            m_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
            sockaddr_un addr {};
            addr.sun_family = AF_UNIX;
            std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
            if (::connect(m_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
            {
                ::close(m_fd);
                m_fd = -1;
            }
        }

        ~Peer()
        {
            close();
        }

        Peer(const Peer&) = delete;
        Peer& operator=(const Peer&) = delete;

        bool connected() const
        {
            return m_fd >= 0;
        }

        void send(const std::string& bytes)
        {
            ASSERT_EQ(static_cast<ssize_t>(bytes.size()), ::send(m_fd, bytes.data(), bytes.size(), MSG_NOSIGNAL));
        }

        /// Whatever arrives within @p window, without waiting for EOF.
        std::string receivedWithin(std::chrono::milliseconds window)
        {
            std::string out;
            const auto deadline = std::chrono::steady_clock::now() + window;
            for (auto now = std::chrono::steady_clock::now(); now < deadline; now = std::chrono::steady_clock::now())
            {
                pollfd pfd {m_fd, POLLIN, 0};
                const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
                if (::poll(&pfd, 1, static_cast<int>(left)) <= 0)
                {
                    break;
                }
                char buffer[4096];
                const auto n = ::recv(m_fd, buffer, sizeof(buffer), 0);
                if (n <= 0)
                {
                    break;
                }
                out.append(buffer, static_cast<std::size_t>(n));
            }
            return out;
        }

        /// Everything until the server closes the connection.
        std::string readToEof(std::chrono::milliseconds timeout = std::chrono::seconds {10})
        {
            timeval tv {static_cast<time_t>(timeout.count() / 1000), 0};
            ::setsockopt(m_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            std::string out;
            char buffer[4096];
            for (ssize_t n; (n = ::recv(m_fd, buffer, sizeof(buffer), 0)) > 0;)
            {
                out.append(buffer, static_cast<std::size_t>(n));
            }
            return out;
        }

        void close()
        {
            if (m_fd >= 0)
            {
                ::close(m_fd);
                m_fd = -1;
            }
        }

    private:
        int m_fd {-1};
    };

    std::size_t occurrences(const std::string& haystack, const std::string& needle)
    {
        std::size_t count {0};
        for (auto at = haystack.find(needle); at != std::string::npos; at = haystack.find(needle, at + 1))
        {
            ++count;
        }
        return count;
    }

    /// The whole stream is the interim answer, then exactly one final answer with status @p status whose
    /// body is exactly its Content-Length.
    void expectInterimThenOneFinal(const std::string& stream, int status)
    {
        const std::string interim {INTERIM_CONTINUE};
        ASSERT_EQ(0U, stream.rfind(interim, 0)) << "the interim answer is written first:\n" << stream;
        const auto final = stream.substr(interim.size());
        const auto statusLine = "HTTP/1.1 " + std::to_string(status) + " ";
        EXPECT_EQ(0U, final.rfind(statusLine, 0)) << final;
        EXPECT_EQ(1U, occurrences(stream, "HTTP/1.1 100 ")) << stream;
        EXPECT_EQ(1U, occurrences(final, "HTTP/1.1 ")) << "exactly one final answer:\n" << final;

        const auto headEnd = final.find("\r\n\r\n");
        ASSERT_NE(std::string::npos, headEnd) << final;
        const auto lengthAt = final.find("Content-Length: ");
        ASSERT_LT(lengthAt, headEnd) << final;
        const auto length = std::stoul(final.substr(lengthAt + 16));
        EXPECT_EQ(length, final.size() - headEnd - 4) << "the final body is not cut or followed by stray bytes";
    }

    bool waitFor(const std::function<bool()>& condition, std::chrono::milliseconds timeout = std::chrono::seconds {5})
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!condition())
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {5});
        }
        return true;
    }
} // namespace

// The peer sends the body without waiting and the handler answers inline: the final answer is ready
// while the interim write is in flight, so it waits for it instead of being written alongside.
TEST(ExpectContinueOverlapTest, AnInlineAnswerDuringTheInterimWriteIsWrittenAfterIt)
{
    const auto path = uniqueSocketPath("ovinline");
    std::atomic<int> handled {0};
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/events",
                     [&](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
                     {
                         responder->send(HttpResponse::json(200, request->body));
                         ++handled;
                     });
    server->start(configFor(path));
    HeldInterimWrite held;

    const std::string body {R"({"inline":true})"};
    Peer peer {path};
    ASSERT_TRUE(peer.connected());
    peer.send(headExpecting(body.size()));
    ASSERT_TRUE(held.waitHeld()) << "the request was admitted and its interim write started";
    peer.send(body);
    ASSERT_TRUE(waitFor([&] { return handled.load() == 1; }));

    EXPECT_EQ("", peer.receivedWithin(std::chrono::milliseconds {200}))
        << "nothing is written while the interim write is in flight";

    held.release();
    const auto stream = peer.readToEof();
    expectInterimThenOneFinal(stream, 200);
    EXPECT_NE(std::string::npos, stream.find("\r\n\r\n" + body, stream.find("HTTP/1.1 200 "))) << stream;
}

// A deferred answer sent from another thread lands in the same window.
TEST(ExpectContinueOverlapTest, ADeferredAnswerFromAnotherThreadDuringTheInterimWriteIsWrittenAfterIt)
{
    const auto path = uniqueSocketPath("ovdeferred");
    std::mutex mutex;
    std::shared_ptr<IHttpResponder> pending;
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/events",
                     [&](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         std::lock_guard lock {mutex};
                         pending = std::move(responder);
                     });
    server->start(configFor(path));
    HeldInterimWrite held;

    const std::string body {R"({"deferred":true})"};
    Peer peer {path};
    ASSERT_TRUE(peer.connected());
    peer.send(headExpecting(body.size()));
    ASSERT_TRUE(held.waitHeld());
    peer.send(body);
    ASSERT_TRUE(waitFor(
        [&]
        {
            std::lock_guard lock {mutex};
            return static_cast<bool>(pending);
        }));

    std::thread worker {[&]
                        {
                            std::lock_guard lock {mutex};
                            pending->send(HttpResponse::json(202, R"({"queued":1})"));
                        }};
    worker.join();
    EXPECT_EQ("", peer.receivedWithin(std::chrono::milliseconds {200}));

    held.release();
    expectInterimThenOneFinal(peer.readToEof(), 202);
}

// stopAccepting() answers a request that has not reached its handler; while that request's interim
// write is in flight, the shutdown answer waits for it too. stopAccepting() itself waits until no
// request is left before its handler, so it returns once the held write is released.
TEST(ExpectContinueOverlapTest, AShutdownAnswerDuringTheInterimWriteIsWrittenAfterIt)
{
    const auto path = uniqueSocketPath("ovshutdown");
    std::atomic<int> handled {0};
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/events",
                     [&](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         ++handled;
                         responder->send(HttpResponse::json(200, "{}"));
                     });
    server->start(configFor(path));
    HeldInterimWrite held;

    Peer peer {path};
    ASSERT_TRUE(peer.connected());
    peer.send(headExpecting(1024)); // the body never comes: the request stays before its handler
    ASSERT_TRUE(held.waitHeld());

    std::atomic_bool stopped {false};
    std::thread stopper {[&]
                         {
                             server->stopAccepting();
                             stopped.store(true);
                         }};
    ASSERT_TRUE(waitFor([&] { return server->diagnostics().rejectedShutdown == 1; }))
        << "the request before its handler is answered 503";
    EXPECT_EQ("", peer.receivedWithin(std::chrono::milliseconds {200}));
    EXPECT_FALSE(stopped.load()) << "stopAccepting() waits for that answer to go out";

    const auto released = std::chrono::steady_clock::now();
    held.release();
    const auto stream = peer.readToEof();
    stopper.join();
    EXPECT_LT(std::chrono::steady_clock::now() - released, std::chrono::seconds {2})
        << "stopAccepting() returns once the parked answer is written, not at its timeout";

    expectInterimThenOneFinal(stream, 503);
    EXPECT_EQ(0, handled.load());
    server->stop();
}

// The peer leaves while its answer is parked: the interim write fails, the parked answer is dropped
// and the session is freed rather than kept waiting.
TEST(ExpectContinueOverlapTest, APeerLeavingDuringTheInterimWriteFreesTheSession)
{
    const auto path = uniqueSocketPath("ovgone");
    std::atomic<int> handled {0};
    auto server = makeUdsHttpServer();
    server->addRoute(Method::Post,
                     "/events",
                     [&](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         responder->send(HttpResponse::json(200, "{}"));
                         ++handled;
                     });
    server->start(configFor(path));
    HeldInterimWrite held;

    const std::string body {"{}"};
    {
        Peer peer {path};
        ASSERT_TRUE(peer.connected());
        peer.send(headExpecting(body.size()));
        ASSERT_TRUE(held.waitHeld());
        peer.send(body);
        ASSERT_TRUE(waitFor([&] { return handled.load() == 1; }));
        EXPECT_EQ(1U, server->diagnostics().liveSessions);
    }

    held.release();
    EXPECT_TRUE(waitFor([&] { return server->diagnostics().liveSessions == 0; }))
        << "a session whose peer left is freed, not kept with its parked answer";
    EXPECT_EQ(1, handled.load());
}
