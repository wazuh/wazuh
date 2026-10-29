/*
 * Wazuh remoted module - zstd-compressed /download end-to-end test (issue #38506)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Drives a REAL TLS RestinioHttpServer with the real AuthGateway and the real /download handler
 * over real files, so the pieces that only meet in the transport are exercised together: the
 * negotiation in the route lambda, the order of the responder decorators, the in-flight budget and
 * what an agent finally reads off the wire.
 */

#include "auth/authTypes.hpp"
#include "common/zstdDecoder.hpp"
#include "common/zstdEncoder.hpp"
#include "decoding/bodyDecoder.hpp"
#include "endpoints/authGateway.hpp"
#include "endpoints/downloadEndpoint.hpp"
#include "endpoints/iAgentGroupSource.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerFactory.hpp"
#include "http_server/zstdResponseEncoding.hpp"

#include "testTlsServer.hpp"
#include "zstdTestHelper.hpp"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using namespace remoted::http;
using remoted::common::zstdDecode;
using remoted::common::ZstdDecodeError;
using remoted::common::ZstdEncoder;
using remoted::endpoints::AuthGateway;
using remoted::testutil::alwaysReserve;
using remoted::testutil::configLikeText;

namespace
{
    constexpr auto kConfigBody {R"({"resource_type":"config","resource_id":"web-servers"})"};
    constexpr auto kWpkBody {R"({"resource_type":"wpk","resource_id":"pkg.wpk"})"};
    constexpr auto kOfferZstd {"Accept-Encoding: zstd\r\n"};

    std::uint16_t findFreePort()
    {
        const int probe = ::socket(AF_INET, SOCK_STREAM, 0);
        if (probe < 0)
        {
            return 0;
        }

        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;

        std::uint16_t port = 0;
        if (::bind(probe, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0)
        {
            socklen_t length = sizeof(address);
            if (::getsockname(probe, reinterpret_cast<sockaddr*>(&address), &length) == 0)
            {
                port = ntohs(address.sin_port);
            }
        }

        ::close(probe);
        return port;
    }

    int statusOf(const std::string& rawResponse)
    {
        const auto space = rawResponse.find(' ');
        if (space == std::string::npos || space + 4 > rawResponse.size())
        {
            return 0;
        }
        return std::atoi(rawResponse.c_str() + space + 1);
    }

    bool headPresent(const std::string& head, std::string needle)
    {
        std::string lowered = head;
        std::transform(
            lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) { return std::tolower(c); });
        std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char c) { return std::tolower(c); });
        return lowered.find(needle) != std::string::npos;
    }

    /// Everything an agent can read off one response.
    struct Wire
    {
        int status {0};
        std::string head;
        std::string body;        ///< Body as sent: chunk-decoded, but still compressed if it was.
        bool terminated {false}; ///< The terminating 0-length chunk arrived.
        std::vector<std::size_t> chunkSizes;
        bool zstd {false};
    };

    Wire parse(const std::string& raw)
    {
        Wire wire;
        wire.status = statusOf(raw);
        auto [head, body] = remoted::test::splitResponse(raw);
        wire.head = std::move(head);
        wire.zstd = headPresent(wire.head, "content-encoding: zstd");
        if (headPresent(wire.head, "transfer-encoding: chunked"))
        {
            wire.body = remoted::test::decodeChunked(body, wire.chunkSizes, wire.terminated);
        }
        else
        {
            wire.body = std::move(body);
            wire.terminated = true;
        }
        return wire;
    }

    /// Decodes @p frame; empty optional when it is not one complete frame.
    std::optional<std::string> decode(const std::string& frame)
    {
        const auto result = zstdDecode(frame, alwaysReserve, alwaysReserve);
        if (const auto* text = std::get_if<std::string>(&result))
        {
            return *text;
        }
        return std::nullopt;
    }

    class FixedGroupSource final : public remoted::endpoints::IAgentGroupSource
    {
    public:
        void resolveSelector(const std::string&,
                             std::function<void(remoted::endpoints::GroupVerdict)> done) const override
        {
            done(remoted::endpoints::GroupVerdict {remoted::endpoints::GroupVerdictKind::Selector, "web-servers"});
        }
    };

    class CompressedDownloadE2ETest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            if (std::system("openssl version >/dev/null 2>&1") != 0)
            {
                GTEST_SKIP() << "openssl not available to generate the test certificate";
            }
            m_cert = remoted::test::generateTestCertificate("compressed_download_e2e");
            if (!m_cert)
            {
                GTEST_SKIP() << "could not generate a throwaway TLS certificate";
            }
            m_cleanup = std::make_unique<remoted::test::ScratchFileCleanup>(
                std::vector<std::string> {m_cert->certPath, m_cert->keyPath});

            m_root = std::filesystem::temp_directory_path() /
                     ("compressed_download_e2e_" + std::to_string(::getpid()) + "_" +
                      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
            std::filesystem::create_directories(m_root / "shared" / "web-servers");
            std::filesystem::create_directories(m_root / "upgrade");

            m_config = configLikeText(900U * 1024U);
            m_wpk = configLikeText(300U * 1024U);
            write(m_root / "shared" / "web-servers" / "merged.mg", m_config);
            write(m_root / "upgrade" / "pkg.wpk", m_wpk);
        }

        void TearDown() override
        {
            if (m_server)
            {
                m_server->stop();
            }
            std::error_code ignored;
            std::filesystem::remove_all(m_root, ignored);
        }

        static void write(const std::filesystem::path& path, const std::string& contents)
        {
            std::ofstream out {path, std::ios::binary};
            out << contents;
        }

        void startServer(bool contentEncodingEnabled = true)
        {
            m_port = findFreePort();
            ASSERT_NE(m_port, 0);

            m_server = makeHttpServer();
            m_gateway = std::make_unique<AuthGateway>(
                remoted::auth::AuthConfig {},
                std::make_shared<remoted::test::FakeKeystore>(),
                std::make_shared<const remoted::decoding::BodyDecoder>(*m_server, /*enabled=*/true));

            remoted::endpoints::download::ResourcePaths paths;
            paths.sharedDir = (m_root / "shared").string();
            paths.wpkDir = (m_root / "upgrade").string();
            m_gateway->addAuthenticatedRoute(
                *m_server,
                Method::Post,
                "/download",
                remoted::endpoints::download::makeHandler(paths, {}, std::make_shared<const FixedGroupSource>()),
                ResponseMode::Streamable);

            HttpServerConfig config;
            config.port = m_port;
            config.certificatePath = m_cert->certPath;
            config.privateKeyPath = m_cert->keyPath;
            config.caPublicationRecordPath = "";
            if (contentEncodingEnabled)
            {
                config.decorateStreamResponder = remoted::http::makeZstdResponseDecorator();
            }
            ASSERT_NO_THROW(m_server->start(config));
        }

        Wire download(const std::string& body, const std::string& extraHeaders = {})
        {
            return parse(remoted::test::sendSignedRequest(
                m_port, remoted::test::testAgentKey(), "/download", body, 0, extraHeaders));
        }

        /// The budget returns to @p expected once the transfer's pump is gone; that happens just
        /// after the client has read the last byte, so give it a moment.
        bool budgetSettlesAt(std::size_t expected)
        {
            for (int i = 0; i < 200; ++i)
            {
                if (m_server->diagnostics().budgetAvailableBytes == expected)
                {
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds {10});
            }
            return false;
        }

        std::filesystem::path m_root;
        std::string m_config;
        std::string m_wpk;
        std::uint16_t m_port {0};
        std::shared_ptr<IHttpServer> m_server;
        std::unique_ptr<AuthGateway> m_gateway;
        std::optional<remoted::test::TestCertificate> m_cert;
        std::unique_ptr<remoted::test::ScratchFileCleanup> m_cleanup;
    };
} // namespace

TEST_F(CompressedDownloadE2ETest, ACompressibleConfigIsSentCompressedWhenTheAgentOffersZstd)
{
    startServer();
    const auto before = m_server->diagnostics().budgetAvailableBytes;

    const auto wire = download(kConfigBody, kOfferZstd);

    ASSERT_EQ(wire.status, 200) << wire.head;
    EXPECT_TRUE(wire.zstd) << wire.head;
    EXPECT_TRUE(headPresent(wire.head, "transfer-encoding: chunked")) << wire.head;
    EXPECT_FALSE(headPresent(wire.head, "content-length:")) << wire.head;
    EXPECT_TRUE(headPresent(wire.head, "content-type: application/octet-stream")) << wire.head;
    EXPECT_TRUE(wire.terminated) << "the terminating 0-length chunk is missing";
    EXPECT_LT(wire.body.size(), m_config.size() / 10) << "the body was not compressed";

    const auto decoded = decode(wire.body);
    ASSERT_TRUE(decoded.has_value()) << "what arrived is not one complete zstd frame";
    EXPECT_EQ(*decoded, m_config);

    EXPECT_TRUE(budgetSettlesAt(before)) << "the compressor's memory was not released with the transfer";
}

TEST_F(CompressedDownloadE2ETest, EveryChunkOnTheWireIsWithinTheConfiguredChunkSize)
{
    // Content-Encoding is applied before Transfer-Encoding, so the chunk size bounds the COMPRESSED bytes.
    startServer();

    const auto wire = download(kConfigBody, kOfferZstd);

    ASSERT_EQ(wire.status, 200) << wire.head;
    ASSERT_FALSE(wire.chunkSizes.empty());
    for (const auto size : wire.chunkSizes)
    {
        EXPECT_LE(size, HttpServerConfig {}.streamChunkSize);
    }
}

TEST_F(CompressedDownloadE2ETest, WithoutTheOfferTheBodyIsPlainAsBefore)
{
    startServer();

    for (const std::string offer : {std::string {},
                                    std::string {"Accept-Encoding: gzip\r\n"},
                                    std::string {"Accept-Encoding: identity\r\n"},
                                    std::string {"Accept-Encoding: zstd;q=0\r\n"}})
    {
        const auto wire = download(kConfigBody, offer);

        ASSERT_EQ(wire.status, 200) << offer << wire.head;
        EXPECT_FALSE(wire.zstd) << "offer: '" << offer << "'\n" << wire.head;
        EXPECT_TRUE(wire.terminated);
        EXPECT_EQ(wire.body, m_config) << "offer: '" << offer << "'";
    }
}

TEST_F(CompressedDownloadE2ETest, WithTheGateOffTheBodyIsPlainEvenIfTheAgentOffersZstd)
{
    startServer(/*contentEncodingEnabled=*/false);

    const auto wire = download(kConfigBody, kOfferZstd);

    ASSERT_EQ(wire.status, 200) << wire.head;
    EXPECT_FALSE(wire.zstd) << wire.head;
    EXPECT_EQ(wire.body, m_config);
}

TEST_F(CompressedDownloadE2ETest, AWpkIsNeverCompressedEvenIfTheAgentOffersZstd)
{
    startServer();

    const auto wire = download(kWpkBody, kOfferZstd);

    ASSERT_EQ(wire.status, 200) << wire.head;
    EXPECT_FALSE(wire.zstd) << wire.head;
    EXPECT_TRUE(wire.terminated);
    EXPECT_EQ(wire.body, m_wpk);
}

TEST_F(CompressedDownloadE2ETest, ErrorBodiesStayPlainAndIdenticalWhenTheAgentOffersZstd)
{
    startServer();

    // 404: the group's merged.mg does not exist. A buffered JSON answer, never compressed.
    std::filesystem::remove(m_root / "shared" / "web-servers" / "merged.mg");
    const auto offered = download(kConfigBody, kOfferZstd);
    const auto plain = download(kConfigBody);

    ASSERT_EQ(offered.status, 404) << offered.head;
    EXPECT_EQ(plain.status, 404);
    EXPECT_FALSE(offered.zstd) << offered.head;
    EXPECT_EQ(offered.body, plain.body);
    EXPECT_NE(offered.body.find("Resource not found"), std::string::npos) << offered.body;

    // 400: a malformed request body.
    const auto badOffered = download("not json", kOfferZstd);
    const auto badPlain = download("not json");
    ASSERT_EQ(badOffered.status, 400) << badOffered.head;
    EXPECT_FALSE(badOffered.zstd);
    EXPECT_EQ(badOffered.body, badPlain.body);
}

TEST_F(CompressedDownloadE2ETest, WhenThereIsNoRoomForACompressorTheBodyIsServedPlain)
{
    startServer();

    // Leave room for the request and for nothing like a compressor.
    const auto available = m_server->diagnostics().budgetAvailableBytes;
    ASSERT_GT(ZstdEncoder::memoryRequired(), 512U * 1024U);
    auto hold = m_server->tryReserveInFlightBytes(available - 512U * 1024U);
    ASSERT_TRUE(hold.has_value());

    const auto wire = download(kConfigBody, kOfferZstd);

    ASSERT_EQ(wire.status, 200) << wire.head;
    EXPECT_FALSE(wire.zstd) << wire.head;
    EXPECT_TRUE(wire.terminated);
    EXPECT_EQ(wire.body, m_config) << "a refused reservation must serve exactly what an agent that did not ask gets";

    // Once the room is back the same request compresses again: nothing was left in a degraded state.
    hold.reset();
    const auto again = download(kConfigBody, kOfferZstd);
    ASSERT_EQ(again.status, 200) << again.head;
    EXPECT_TRUE(again.zstd);
}

TEST_F(CompressedDownloadE2ETest, TheCompressorIsChargedToTheBudgetWhileTheTransferRuns)
{
    // A bare streamable route whose source looks at the budget from inside the transfer: the
    // moment its first read() runs, the compressor has already been reserved.
    m_port = findFreePort();
    ASSERT_NE(m_port, 0);
    m_server = makeHttpServer();

    std::atomic<std::size_t> availableMidTransfer {0};
    IHttpServer* server = m_server.get();

    class ProbeSource final : public IByteSource
    {
    public:
        explicit ProbeSource(std::function<void()> onFirstRead)
            : m_onFirstRead {std::move(onFirstRead)}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            if (m_onFirstRead)
            {
                m_onFirstRead();
                m_onFirstRead = nullptr;
            }
            const auto count = std::min<std::size_t>(capacity, m_remaining);
            std::memset(buffer, 'z', count);
            m_remaining -= count;
            return count;
        }

    private:
        std::function<void()> m_onFirstRead;
        std::size_t m_remaining {200000};
    };

    m_server->addRoute(
        Method::Post,
        "/stream",
        [&availableMidTransfer, server](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            StreamResponse response;
            response.source = std::make_shared<ProbeSource>(
                [&availableMidTransfer, server] { availableMidTransfer = server->diagnostics().budgetAvailableBytes; });
            responder->stream(std::move(response));
        },
        /*countAgainstBudget=*/true,
        ResponseMode::Streamable);

    HttpServerConfig config;
    config.port = m_port;
    config.certificatePath = m_cert->certPath;
    config.privateKeyPath = m_cert->keyPath;
    config.caPublicationRecordPath = "";
    config.decorateStreamResponder = remoted::http::makeZstdResponseDecorator();
    ASSERT_NO_THROW(m_server->start(config));
    const auto before = m_server->diagnostics().budgetAvailableBytes;

    const auto wire =
        parse(remoted::test::sendSignedRequest(m_port, remoted::test::testAgentKey(), "/stream", "{}", 0, kOfferZstd));

    ASSERT_EQ(wire.status, 200) << wire.head;
    ASSERT_TRUE(wire.zstd) << wire.head;
    EXPECT_LE(availableMidTransfer.load(), before - ZstdEncoder::memoryRequired())
        << "the compressor's memory was not charged while the transfer ran";
    EXPECT_TRUE(budgetSettlesAt(before)) << "and it was not released afterwards";
}

TEST_F(CompressedDownloadE2ETest, ASourceThatFailsMidTransferLeavesATruncatedFrameAndNoTerminator)
{
    // The abort path of a file modified under the transfer: the source throws, the pump emits no
    // terminating chunk, and the agent is left with bytes that are not a complete frame.
    m_port = findFreePort();
    ASSERT_NE(m_port, 0);
    m_server = makeHttpServer();

    class FailingSource final : public IByteSource
    {
    public:
        std::size_t read(char* buffer, std::size_t capacity) override
        {
            if (++m_reads > 12)
            {
                throw std::runtime_error {"the resource was modified while it was being streamed"};
            }
            // Bytes zstd cannot shrink, so output is emitted before the failure.
            const auto count = std::min<std::size_t>(capacity, 64U * 1024U);
            for (std::size_t i = 0; i < count; ++i)
            {
                m_state = m_state * 1664525U + 1013904223U;
                buffer[i] = static_cast<char>(m_state >> 24);
            }
            return count;
        }

    private:
        std::uint32_t m_state {0x9E3779B9U};
        int m_reads {0};
    };

    m_server->addRoute(
        Method::Post,
        "/stream",
        [](std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder> responder)
        {
            StreamResponse response;
            response.source = std::make_shared<FailingSource>();
            responder->stream(std::move(response));
        },
        /*countAgainstBudget=*/true,
        ResponseMode::Streamable);

    HttpServerConfig config;
    config.port = m_port;
    config.certificatePath = m_cert->certPath;
    config.privateKeyPath = m_cert->keyPath;
    config.caPublicationRecordPath = "";
    config.decorateStreamResponder = remoted::http::makeZstdResponseDecorator();
    config.writeTimeoutSec = 2;
    config.requestTimeoutSec = 2;
    ASSERT_NO_THROW(m_server->start(config));
    const auto before = m_server->diagnostics().budgetAvailableBytes;

    const auto wire =
        parse(remoted::test::sendSignedRequest(m_port, remoted::test::testAgentKey(), "/stream", "{}", 0, kOfferZstd));

    ASSERT_EQ(wire.status, 200) << wire.head;
    EXPECT_TRUE(wire.zstd);
    EXPECT_FALSE(wire.terminated) << "an aborted transfer must not carry the terminating 0-length chunk";
    ASSERT_FALSE(wire.body.empty());
    EXPECT_FALSE(decode(wire.body).has_value()) << "the agent must not be able to decode a truncated frame";
    EXPECT_TRUE(budgetSettlesAt(before)) << "an aborted transfer must still release the compressor's memory";
}
