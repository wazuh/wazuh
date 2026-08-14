/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// End-to-end regression test for the shutdown use-after-free fix. A real RestinioHttpServer (TLS)
// + AuthGateway + DeferredForwarder + AsioUdsHttpClient are wired together exactly as
// RemotedModuleFacade does; a request is authenticated and forwarded to a downstream stub that
// delays its response, and the exact stopAccepting() -> client->stop() -> forwarder.reset() ->
// client.reset() -> limiter.reset() -> server->stop() sequence from RemotedModuleFacade::stop() is
// run while that request is still mid-flight (its Session hasn't completed yet).
//
// Success is the absence of a crash/hang. This test is only a meaningful regression check when
// built with -DFSANITIZE=ON (ASan): without a sanitizer, the freed io_context memory may not be
// detectably corrupted within this test's short window, so it can "pass" even against the
// unfixed ordering. Run it under the ASan job, not just a plain Debug/Release build.
#include "auth/cmac.hpp"
#include "downstream/asioUdsHttpClient.hpp"
#include "downstream/deferredForwarder.hpp"
#include "downstream/deferredWorkLimiter.hpp"
#include "downstream/downstreamConfig.hpp"
#include "endpoints/authGateway.hpp"
#include "decoding/bodyDecoder.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerFactory.hpp"

#include "testTlsServer.hpp"

#include <gtest/gtest.h>

#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/local/stream_protocol.hpp>
#include <asio/ssl.hpp>
#include <asio/steady_timer.hpp>
#include <asio/write.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace remoted::http;
using namespace remoted::downstream;
using namespace remoted::endpoints;

namespace
{
    using stream_protocol = asio::local::stream_protocol;

    // Keystore stub: one agent, numeric id 7.
    class FakeKeystore final : public remoted::auth::IAgentKeystore
    {
    public:
        std::optional<std::vector<std::uint8_t>> keyFor(remoted::auth::AgentId agentId) const override
        {
            if (agentId == 7)
            {
                return std::vector<std::uint8_t>(16, 0x0B);
            }
            return std::nullopt;
        }
    };

    // Downstream UDS stub: accepts, drains one read (signalling "the forward reached the
    // downstream"), waits a bit, then answers -- creating a reliable "mid-flight" window for the
    // test to shut down into.
    class DelayedUdsServer final
    {
    public:
        DelayedUdsServer(std::string path, std::chrono::milliseconds delay)
            : m_path {std::move(path)}
            , m_delay {delay}
            , m_acceptor {m_ioc}
        {
            ::unlink(m_path.c_str());
            stream_protocol::endpoint endpoint {m_path};
            m_acceptor.open(endpoint.protocol());
            m_acceptor.bind(endpoint);
            m_acceptor.listen();
            doAccept();
            m_thread = std::thread([this] { m_ioc.run(); });
        }

        ~DelayedUdsServer()
        {
            m_ioc.stop();
            if (m_thread.joinable())
            {
                m_thread.join();
            }
            ::unlink(m_path.c_str());
        }

        const std::string& path() const
        {
            return m_path;
        }

        bool waitForRequest(std::chrono::milliseconds timeout)
        {
            auto fut = m_received.get_future();
            return fut.wait_for(timeout) == std::future_status::ready;
        }

    private:
        void doAccept()
        {
            m_acceptor.async_accept(
                [this](const std::error_code& ec, stream_protocol::socket socket)
                {
                    if (ec)
                    {
                        return;
                    }
                    auto conn = std::make_shared<stream_protocol::socket>(std::move(socket));
                    auto buffer = std::make_shared<std::array<char, 4096>>();
                    conn->async_read_some(
                        asio::buffer(*buffer),
                        [this, conn, buffer](const std::error_code& readEc, std::size_t)
                        {
                            if (readEc)
                            {
                                return;
                            }
                            m_received.set_value(); // signal: the forward reached the downstream

                            auto timer = std::make_shared<asio::steady_timer>(m_ioc, m_delay);
                            timer->async_wait(
                                [conn, timer](const std::error_code&)
                                {
                                    static const std::string kResponse = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                                    asio::async_write(*conn,
                                                      asio::buffer(kResponse),
                                                      [conn](const std::error_code&, std::size_t)
                                                      {
                                                          std::error_code ignore;
                                                          conn->shutdown(stream_protocol::socket::shutdown_both,
                                                                         ignore);
                                                          conn->close(ignore);
                                                      });
                                });
                        });
                });
        }

        std::string m_path;
        std::chrono::milliseconds m_delay;
        asio::io_context m_ioc;
        stream_protocol::acceptor m_acceptor;
        std::thread m_thread;
        std::promise<void> m_received;
    };

    // Builds the canonical AES-CMAC exactly as AuthMiddleware verifies it.
    std::string canonicalMac(const std::vector<std::uint8_t>& key,
                             const std::string& protocolVersion,
                             const std::string& method,
                             const std::string& target,
                             const std::string& agentId,
                             std::int64_t ts,
                             const std::string& body)
    {
        remoted::auth::Cmac cmac(key);
        cmac.update("WAZUH-REQUEST\n");
        cmac.update(protocolVersion);
        cmac.update("\n");
        cmac.update(method);
        cmac.update("\n");
        cmac.update(target);
        cmac.update("\n");
        cmac.update(agentId);
        cmac.update("\n");
        cmac.update(std::to_string(ts));
        cmac.update("\n");
        cmac.update(body);
        const auto mac = cmac.finalize();
        return remoted::auth::toLowerHex(mac.data(), mac.size());
    }

    // Generates a throwaway self-signed cert/key pair via the system openssl binary (a hard
    // dependency of this module already), so the test can start a REAL TLS RestinioHttpServer.
    // A factory (not a constructor) because GTEST_SKIP() needs a void-returning function -- the
    // caller (the TEST body) handles a generation failure by skipping. Deliberately no destructor
    // here (returned by value through std::optional -- since the implicit move ctor would be
    // suppressed by a user-declared destructor, the local would fall back to a copy, and the
    // ORIGINAL's destructor would delete the files out from under the copy the caller keeps). File
    // cleanup is a separate, never-returned RAII guard constructed directly in the test body.
    struct TestCertificate
    {
        std::string certPath;
        std::string keyPath;
    };

    std::optional<TestCertificate> generateTestCertificate()
    {
        const auto pid = std::to_string(::getpid());
        TestCertificate cert;
        cert.certPath = "/tmp/rmt_shutdown_race_" + pid + ".crt";
        cert.keyPath = "/tmp/rmt_shutdown_race_" + pid + ".key";
        const std::string cmd = "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout " + cert.keyPath + " -out " +
                                cert.certPath + " -subj /CN=localhost >/dev/null 2>&1";
        if (std::system(cmd.c_str()) != 0)
        {
            return std::nullopt;
        }
        return cert;
    }

    // Connects over TLS, sends one signed /stateless request, and returns without waiting for a
    // reply -- fire-and-forget, exactly what an agent's connection looks like from the server's
    // perspective at the moment shutdown begins.
    void
    sendSignedRequestFireAndForget(std::uint16_t port, const std::vector<std::uint8_t>& key, const std::string& body)
    {
        try
        {
            asio::io_context ioc;
            asio::ssl::context sslContext {asio::ssl::context::tls_client};
            sslContext.set_verify_mode(asio::ssl::verify_none);

            asio::ssl::stream<asio::ip::tcp::socket> stream {ioc, sslContext};
            asio::ip::tcp::resolver resolver {ioc};
            const auto endpoints = resolver.resolve("127.0.0.1", std::to_string(port));
            asio::connect(stream.next_layer(), endpoints);
            stream.handshake(asio::ssl::stream_base::client);

            const auto ts = static_cast<std::int64_t>(std::time(nullptr));
            const std::string mac = canonicalMac(key, "1", "POST", "/stateless", "7", ts, body);

            std::string request = "POST /stateless HTTP/1.1\r\n";
            request += "Host: 127.0.0.1\r\n";
            request += "protocol-version: 1\r\n";
            request += "Authorization: Wazuh 7:" + std::to_string(ts) + ":" + mac + "\r\n";
            request += "Content-Length: " + std::to_string(body.size()) + "\r\n";
            request += "Connection: close\r\n\r\n";
            request += body;

            asio::write(stream, asio::buffer(request));
        }
        catch (const std::exception&)
        {
            // Best-effort: the connection may be reset once the server starts shutting down --
            // what matters for this test is what happens SERVER-side, not a successful reply.
        }
    }

    // Removes a fixed set of scratch files on scope exit. Never copied/moved/returned, unlike
    // TestCertificate -- safe to give this one a destructor.
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
} // namespace

TEST(ShutdownRace, StopSequenceSurvivesAnInFlightForward)
{
    auto certOpt = generateTestCertificate();
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    auto& cert = *certOpt;
    ScratchFileCleanup certCleanup {{cert.certPath, cert.keyPath}};

    const std::string udsPath = "/tmp/rmt_shutdown_race_uds_" + std::to_string(::getpid()) + ".sock";
    DelayedUdsServer udsServer {udsPath, std::chrono::milliseconds {300}};

    auto limiter = std::make_shared<DeferredWorkLimiter>(4);
    auto client = std::make_shared<AsioUdsHttpClient>(DownstreamConfig {});
    client->start();
    auto forwarder = std::make_unique<DeferredForwarder>(client, limiter, 2);

    auto server = makeHttpServer();
    AuthGateway gateway {remoted::auth::AuthConfig {},
                         std::make_shared<FakeKeystore>(),
                         std::make_shared<const remoted::decoding::BodyDecoder>(*server, /*enabled=*/true)};

    auto* forwarderPtr = forwarder.get();
    gateway.addAuthenticatedRoute(
        *server,
        Method::Post,
        "/stateless",
        [forwarderPtr, udsPath](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                                std::shared_ptr<IHttpResponder> responder)
        {
            DownstreamTarget target {udsPath, Method::Post, "/events/enriched", "application/x-ndjson"};
            forwarderPtr->forward(std::move(authReq),
                                  std::move(responder),
                                  target,
                                  [](DownstreamError, const DownstreamResponse&)
                                  { return HttpResponse {202, "", {}}; });
        });

    HttpServerConfig config;
    config.port = static_cast<std::uint16_t>(20000 + (::getpid() % 10000));
    config.certificatePath = cert.certPath;
    config.privateKeyPath = cert.keyPath;
    server->start(config);

    const std::vector<std::uint8_t> key(16, 0x0B); // matches FakeKeystore::keyFor(7)
    std::thread clientThread([&] { sendSignedRequestFireAndForget(config.port, key, "H {}\nE test\n"); });

    // Wait until the request has genuinely reached the downstream -- i.e. it is sitting exactly in
    // the mid-flight window this fix must make safe -- before tearing down.
    ASSERT_TRUE(udsServer.waitForRequest(std::chrono::seconds {2}));

    // The exact sequence from RemotedModuleFacade::stop(): must not crash/hang even though a
    // forward is still in flight and will only complete ~300ms from now.
    server->stopAccepting();
    client->stop();
    forwarder.reset();
    client.reset();
    limiter.reset();
    server->stop();

    if (clientThread.joinable())
    {
        clientThread.join();
    }

    SUCCEED();
}

// A streamed response is the one path that bounces worker-pool <-> connection-strand OUTSIDE the
// DeferredForwarder that the four-phase shutdown drains. stopAccepting() drains the handler pool,
// but a StreamPump that has already handed a chunk to the strand has its continuation queued
// somewhere neither phase 1 nor phase 3 knows about -- so teardown with a live transfer is exactly
// the use-after-free shape this file exists to catch. Until now it was only argued for in a comment
// ("RESTinio guarantees the write callback always fires"), never executed under ASan.
namespace
{
    /// Never-ending source: guarantees the transfer is still mid-flight when shutdown begins.
    ///
    /// Progress and destruction are reported through SHARED counters rather than by the test
    /// holding the source: the pump must be its only owner, or "was it released?" would really be
    /// measuring the test's own reference.
    class EndlessByteSource final : public IByteSource
    {
    public:
        EndlessByteSource(std::shared_ptr<std::atomic_int> reads, std::shared_ptr<std::atomic_bool> destroyed)
            : m_reads {std::move(reads)}
            , m_destroyed {std::move(destroyed)}
        {
        }

        ~EndlessByteSource() override
        {
            m_destroyed->store(true);
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            m_reads->fetch_add(1);
            std::memset(buffer, 'Z', capacity);
            return capacity; // never EOF
        }

    private:
        std::shared_ptr<std::atomic_int> m_reads;
        std::shared_ptr<std::atomic_bool> m_destroyed;
    };
} // namespace

TEST(ShutdownRace, StopSequenceSurvivesAnInFlightStream)
{
    auto certOpt = remoted::test::generateTestCertificate("rmt_shutdown_stream");
    if (!certOpt)
    {
        GTEST_SKIP() << "openssl not available to generate a test certificate";
    }
    remoted::test::ScratchFileCleanup certCleanup {{certOpt->certPath, certOpt->keyPath}};

    auto destroyed = std::make_shared<std::atomic_bool>(false);
    auto reads = std::make_shared<std::atomic_int>(0);

    auto server = makeHttpServer();
    AuthGateway gateway {remoted::auth::AuthConfig {},
                         std::make_shared<remoted::test::FakeKeystore>(),
                         std::make_shared<const remoted::decoding::BodyDecoder>(*server, /*enabled=*/true)};

    gateway.addAuthenticatedRoute(
        *server,
        Method::Post,
        "/stream",
        [reads, destroyed](std::shared_ptr<const remoted::auth::AuthenticatedRequest>,
                           std::shared_ptr<IHttpResponder> responder)
        {
            StreamResponse response;
            // Built here and handed straight over, so the pump ends up the sole owner.
            response.source = std::make_shared<EndlessByteSource>(reads, destroyed);
            responder->stream(std::move(response));
        },
        remoted::http::ResponseMode::Streamable);

    HttpServerConfig config;
    config.port = static_cast<std::uint16_t>(24000 + (::getpid() % 5000));
    config.certificatePath = certOpt->certPath;
    config.privateKeyPath = certOpt->keyPath;
    server->start(config);

    // Read a little and then hold the connection open, so the pump keeps cycling
    // pool -> strand -> pool while the teardown below runs.
    std::thread clientThread(
        [&]
        {
            remoted::test::sendSignedRequest(
                config.port, remoted::test::testAgentKey(), "/stream", "{}", 256 * 1024);
        });

    // Wait until the pump has genuinely started cycling: that is the mid-flight window.
    for (int i = 0; i < 200 && reads->load() < 2; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {10});
    }
    ASSERT_GE(reads->load(), 2) << "the stream never started; the test would prove nothing";

    // The exact facade sequence, run against a transfer that is still advancing.
    server->stopAccepting();
    server->stop();

    if (clientThread.joinable())
    {
        clientThread.join();
    }

    // Success is the absence of a crash/hang under ASan. Additionally, releasing the server must
    // release the source rather than strand it in a queued continuation -- the route table (and any
    // handler-captured state) only goes away when the server object itself does.
    server.reset();
    for (int i = 0; i < 100 && !destroyed->load(); ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {20});
    }
    EXPECT_TRUE(destroyed->load()) << "the byte source outlived server teardown";
}
