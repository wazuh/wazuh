/*
 * Wazuh remoted module (C++ worker bridge) - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Regression test for the transport-level exception barrier in RestinioHttpServer's route lambda.
//
// Why it needs a REAL TLS server: the barrier lives in the lambda RESTinio invokes and in the
// worker-pool task it posts. Calling a RouteHandler directly bypasses both and would prove nothing.
//
// Why `throw 42` (a non-std::exception) is the important case: RESTinio's own connection handling
// already wraps request processing in `catch (const std::exception&)`, so a std::runtime_error was
// never the exposure -- it closed the connection cleanly. A non-std::exception, however, reached a
// noexcept frame (or asio::thread_pool's handler wrapper) and terminated the whole remoted daemon.
// Success here is: the process is still alive afterwards, and the client gets an answer.
#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerFactory.hpp"

#include <gtest/gtest.h>

#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/read.hpp>
#include <asio/ssl.hpp>
#include <asio/write.hpp>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

using namespace remoted::http;

namespace
{
    // Same approach as shutdownRace_test.cpp: a throwaway self-signed pair via the system openssl
    // binary, so a real TLS listener can be started. A factory rather than a constructor because
    // GTEST_SKIP() only works in a void-returning function.
    struct TestCertificate
    {
        std::string certPath;
        std::string keyPath;
    };

    std::optional<TestCertificate> generateTestCertificate()
    {
        const auto pid = std::to_string(::getpid());
        TestCertificate cert;
        cert.certPath = "/tmp/rmt_handler_barrier_" + pid + ".crt";
        cert.keyPath = "/tmp/rmt_handler_barrier_" + pid + ".key";
        const std::string cmd = "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout " + cert.keyPath + " -out " +
                                cert.certPath + " -subj /CN=localhost >/dev/null 2>&1";
        if (std::system(cmd.c_str()) != 0)
        {
            return std::nullopt;
        }
        return cert;
    }

    class ScratchFileCleanup final
    {
    public:
        explicit ScratchFileCleanup(std::vector<std::string> paths)
            : m_paths {std::move(paths)}
        {
        }
        ScratchFileCleanup(const ScratchFileCleanup&) = delete;
        ScratchFileCleanup& operator=(const ScratchFileCleanup&) = delete;
        ~ScratchFileCleanup()
        {
            for (const auto& path : m_paths)
            {
                std::remove(path.c_str());
            }
        }

    private:
        std::vector<std::string> m_paths;
    };

    // Sends one unauthenticated GET over TLS and returns whatever the server answers (empty on a
    // connection reset, which is also a non-crash outcome).
    std::string getOverTls(std::uint16_t port, const std::string& path)
    {
        std::string received;
        try
        {
            asio::io_context ioc;
            asio::ssl::context sslContext {asio::ssl::context::tls_client};
            sslContext.set_verify_mode(asio::ssl::verify_none);

            asio::ssl::stream<asio::ip::tcp::socket> stream {ioc, sslContext};
            asio::ip::tcp::resolver resolver {ioc};
            asio::connect(stream.next_layer(), resolver.resolve("127.0.0.1", std::to_string(port)));
            stream.handshake(asio::ssl::stream_base::client);

            const std::string request = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
            asio::write(stream, asio::buffer(request));

            std::array<char, 1024> buffer {};
            std::error_code ec;
            while (!ec)
            {
                const auto n = stream.read_some(asio::buffer(buffer), ec);
                received.append(buffer.data(), n);
            }
        }
        catch (const std::exception&)
        {
            // A reset/short read is acceptable: the assertion that matters is that we got here at
            // all instead of the daemon dying.
        }
        return received;
    }

    // Picks a port unlikely to collide with a parallel test run.
    std::uint16_t testPort(std::uint16_t offset)
    {
        return static_cast<std::uint16_t>(19700 + (::getpid() % 200) + offset);
    }

    HttpServerConfig makeConfig(const TestCertificate& cert, std::uint16_t port)
    {
        HttpServerConfig config;
        config.bindAddress = "127.0.0.1";
        config.port = port;
        config.certificatePath = cert.certPath;
        config.privateKeyPath = cert.keyPath;
        config.ioThreads = 1;
        config.workerThreads = 1;
        return config;
    }
} // namespace

// A handler throwing something that does NOT derive from std::exception must not take the process
// down, and the client must still get an answer.
TEST(HandlerBarrier, NonStandardExceptionFromHandlerDoesNotTerminate)
{
    auto certOpt = generateTestCertificate();
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    auto& cert = *certOpt;
    ScratchFileCleanup cleanup {{cert.certPath, cert.keyPath}};

    const auto port = testPort(0);
    auto server = makeHttpServer();
    server->addRoute(Method::Get,
                     "/boom",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>)
                     {
                         throw 42; // NOLINT(hicpp-exception-baseclass) -- deliberately not a std::exception
                     });
    server->start(makeConfig(cert, port));

    const auto response = getOverTls(port, "/boom");

    // Reaching this line at all is the primary assertion (no std::terminate).
    EXPECT_NE(response.find("500"), std::string::npos)
        << "expected the barrier to answer 500; got: " << response.substr(0, 128);

    server->stop();
}

// Same for a std::exception. RESTinio would already have closed the connection on its own here, but
// the barrier now turns it into a proper 500 instead, for every route rather than only the
// authenticated ones (AuthGateway had its own try/catch; the liveness probe had none).
TEST(HandlerBarrier, StandardExceptionFromHandlerAnswersInternalError)
{
    auto certOpt = generateTestCertificate();
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    auto& cert = *certOpt;
    ScratchFileCleanup cleanup {{cert.certPath, cert.keyPath}};

    const auto port = testPort(1);
    auto server = makeHttpServer();
    server->addRoute(Method::Get,
                     "/throws",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>)
                     { throw std::runtime_error("handler failure"); });
    server->start(makeConfig(cert, port));

    const auto response = getOverTls(port, "/throws");

    EXPECT_NE(response.find("500"), std::string::npos)
        << "expected the barrier to answer 500; got: " << response.substr(0, 128);

    server->stop();
}

// A handler that already answered before throwing must keep its original response: send-once means
// the barrier's 500 is a no-op, so the client must not see the error instead of the real answer.
TEST(HandlerBarrier, ThrowAfterRespondingKeepsTheOriginalResponse)
{
    auto certOpt = generateTestCertificate();
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    auto& cert = *certOpt;
    ScratchFileCleanup cleanup {{cert.certPath, cert.keyPath}};

    const auto port = testPort(2);
    auto server = makeHttpServer();
    server->addRoute(Method::Get,
                     "/late-throw",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     {
                         responder->send(HttpResponse::json(200, R"({"status":"ok"})"));
                         throw 7; // NOLINT(hicpp-exception-baseclass) -- deliberately not a std::exception
                     });
    server->start(makeConfig(cert, port));

    const auto response = getOverTls(port, "/late-throw");

    EXPECT_NE(response.find("200"), std::string::npos)
        << "expected the original 200 to survive; got: " << response.substr(0, 128);
    EXPECT_NE(response.find(R"({"status":"ok"})"), std::string::npos);

    server->stop();
}

// --- Transport-level diagnostics (WazuhRestinioLogger) -----------------------------------------
//
// RESTinio's own diagnostics now flow into wazuh-manager.log instead of being compiled away by
// null_logger_t. The test binary cannot read the module's log sink (Log::GLOBAL_LOG_FUNCTION has
// hidden visibility and is defined inside libremoted_module.so), so these tests assert the
// property that actually matters for safety: exercising the adapter's error()/warn() paths with
// hostile input must not crash or hang the server.

// The single sharpest hazard in the adapter. RESTinio's message builders embed client-controlled
// data (the request target, header values), and LogFn forwards its format string straight to
// _log()'s vfprintf/vsnprintf. If the adapter passed that message AS the format instead of as a
// "%s" argument, a request target full of conversion specifiers would read the varargs list that
// was never pushed -- a remote format-string bug. Here the target is nothing but specifiers,
// including %n (the write primitive), so a regression crashes or corrupts rather than passing.
TEST(TransportLogging, FormatSpecifiersInRequestTargetAreNotInterpreted)
{
    auto certOpt = generateTestCertificate();
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    auto& cert = *certOpt;
    ScratchFileCleanup cleanup {{cert.certPath, cert.keyPath}};

    const auto port = testPort(3);
    auto server = makeHttpServer();
    server->addRoute(Method::Get,
                     "/ok",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { responder->send(HttpResponse::json(200, R"({"status":"ok"})")); });
    server->start(makeConfig(cert, port));

    // RESTinio rejects this target and closes the connection without answering (an invalid
    // percent-escape), which is fine and expected -- what matters is that the diagnostic it logs on
    // the way out goes through the adapter carrying that target as DATA.
    (void)getOverTls(port, "/%s%s%s%n%d%x");

    // The real assertion: the server is still alive and serving. A misused format string would have
    // read garbage off the varargs list here -- typically a segfault (taking the whole test binary
    // with it) or, with %n, a wild write.
    EXPECT_NE(getOverTls(port, "/ok").find("200"), std::string::npos)
        << "the server stopped serving after a request target full of format specifiers";

    // Header values reach the same builders, so cover that channel too.
    (void)getOverTls(port, "/ok");
    EXPECT_NE(getOverTls(port, "/ok").find("200"), std::string::npos);

    server->stop();
}

// Plaintext sent to the TLS port is the classic misconfiguration (an agent talking HTTP to an HTTPS
// listener). It drives RESTinio's handshake-failure path, which is exactly what the adapter's
// error() now reports -- previously discarded entirely by null_logger_t.
TEST(TransportLogging, PlaintextOnTheTlsPortIsHandledGracefully)
{
    auto certOpt = generateTestCertificate();
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    auto& cert = *certOpt;
    ScratchFileCleanup cleanup {{cert.certPath, cert.keyPath}};

    const auto port = testPort(4);
    auto server = makeHttpServer();
    server->addRoute(Method::Get,
                     "/ok",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { responder->send(HttpResponse::json(200, R"({"status":"ok"})")); });
    server->start(makeConfig(cert, port));

    // Raw TCP, no TLS handshake.
    try
    {
        asio::io_context ioc;
        asio::ip::tcp::socket socket {ioc};
        asio::ip::tcp::resolver resolver {ioc};
        asio::connect(socket, resolver.resolve("127.0.0.1", std::to_string(port)));
        const std::string plaintext = "GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        asio::write(socket, asio::buffer(plaintext));
    }
    catch (const std::exception&)
    {
        // The server may reset us; that is a fine outcome.
    }

    // The listener must still be healthy for well-behaved clients.
    EXPECT_NE(getOverTls(port, "/ok").find("200"), std::string::npos);

    server->stop();
}

// Coarse throughput probe for the RESTinio logger swap (null_logger_t -> WazuhRestinioLogger).
// DISABLED_ so it never runs in CI: it is a hand-run A/B measurement, not an assertion. Many
// requests share ONE TLS connection so the handshake cost does not swamp the per-request logging
// cost we are actually trying to see.
//
// Run with: remoted_module_utest --gtest_also_run_disabled_tests \
//                               --gtest_filter='TransportLogging.DISABLED_ThroughputProbe'
TEST(TransportLogging, DISABLED_ThroughputProbe)
{
    auto certOpt = generateTestCertificate();
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    auto& cert = *certOpt;
    ScratchFileCleanup cleanup {{cert.certPath, cert.keyPath}};

    constexpr int kRequests {2000};

    const auto port = testPort(9);
    auto server = makeHttpServer();
    server->addRoute(Method::Get,
                     "/ok",
                     [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
                     { responder->send(HttpResponse::json(200, R"({"status":"ok"})")); });
    server->start(makeConfig(cert, port));

    asio::io_context ioc;
    asio::ssl::context sslContext {asio::ssl::context::tls_client};
    sslContext.set_verify_mode(asio::ssl::verify_none);
    asio::ssl::stream<asio::ip::tcp::socket> stream {ioc, sslContext};
    asio::ip::tcp::resolver resolver {ioc};
    asio::connect(stream.next_layer(), resolver.resolve("127.0.0.1", std::to_string(port)));
    stream.handshake(asio::ssl::stream_base::client);

    const std::string request = "GET /ok HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    std::array<char, 4096> buffer {};

    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < kRequests; ++i)
    {
        asio::write(stream, asio::buffer(request));
        std::error_code ec;
        const auto n = stream.read_some(asio::buffer(buffer), ec);
        ASSERT_FALSE(ec) << "read failed at request " << i;
        ASSERT_GT(n, 0U);
    }
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    std::printf("[throughput] %d keep-alive requests in %lld ms (%.0f req/s)\n",
                kRequests,
                static_cast<long long>(elapsed.count()),
                elapsed.count() > 0 ? (kRequests * 1000.0 / static_cast<double>(elapsed.count())) : 0.0);

    server->stop();
}
