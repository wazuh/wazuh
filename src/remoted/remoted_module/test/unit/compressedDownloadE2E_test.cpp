/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// End-to-end tests of the zstd-compressed POST /download over TLS: a real server with the real
// AuthGateway, BodyDecoder and download handler, serving real files.

#include "common/zstdDecoder.hpp"
#include "common/zstdEncoder.hpp"
#include "decoding/bodyDecoder.hpp"
#include "endpoints/authGateway.hpp"
#include "endpoints/downloadEndpoint.hpp"
#include "http_server/IHttpServer.hpp"
#include "http_server/httpServerFactory.hpp"
#include "testTlsServer.hpp"

#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <zstd.h>

#include <asio/connect.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/ssl.hpp>
#include <asio/write.hpp>

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <variant>
#include <vector>

using namespace remoted::http;
using namespace remoted::endpoints;
using remoted::common::zstdDecode;
using remoted::common::ZstdDecodeError;
using remoted::common::ZstdEncoder;

namespace
{
    using Clock = std::chrono::steady_clock;

    constexpr auto kClientDeadline = std::chrono::seconds {15};
    constexpr std::size_t kMiB = 1024U * 1024U;

    bool alwaysReserve(std::size_t)
    {
        return true;
    }

    // Pseudorandom bytes: zstd cannot shrink them, so the frame is as large as the file.
    std::string incompressible(std::size_t size, std::uint32_t seed)
    {
        std::mt19937 gen(seed);
        std::string data(size, '\0');
        for (auto& c : data)
        {
            c = static_cast<char>(gen() & 0xFF);
        }
        return data;
    }

    std::string patternPayload(std::size_t size)
    {
        const std::string unit = "wpk-package-bytes-0123456789-";
        std::string data;
        while (data.size() < size)
        {
            data += unit;
        }
        data.resize(size);
        return data;
    }

    std::string sha256Hex(const std::string& data)
    {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int length = 0;
        EXPECT_EQ(1,
                  EVP_Digest(data.data(), data.size(), digest, &length, EVP_sha256(), static_cast<ENGINE*>(nullptr)));
        static constexpr char kHex[] = "0123456789abcdef";
        std::string out;
        for (unsigned int i = 0; i < length; ++i)
        {
            out += kHex[digest[i] >> 4];
            out += kHex[digest[i] & 0x0F];
        }
        return out;
    }

    bool headerPresent(const std::string& head, const std::string& needle)
    {
        auto lower = [](std::string text)
        {
            std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return std::tolower(c); });
            return text;
        };
        return lower(head).find(lower(needle)) != std::string::npos;
    }

    std::size_t countHeader(const std::string& head, const std::string& name)
    {
        std::size_t count = 0;
        std::istringstream lines {head};
        std::string line;
        const auto prefix = name + ":";
        while (std::getline(lines, line))
        {
            if (line.size() >= prefix.size() && headerPresent(line.substr(0, prefix.size()), prefix))
            {
                ++count;
            }
        }
        return count;
    }

    // The head without its Date line, which differs between any two responses.
    std::string headWithoutDate(const std::string& head)
    {
        std::istringstream lines {head};
        std::string line;
        std::string out;
        while (std::getline(lines, line))
        {
            if (!(line.size() >= 5 && headerPresent(line.substr(0, 5), "date:")))
            {
                out += line + "\n";
            }
        }
        return out;
    }

    std::size_t zstdRequirement(std::uint64_t fileSize)
    {
        return ZstdEncoder::estimateMemory(fileSize) + ZstdEncoder::inputBufferSize(fileSize) +
               ZstdEncoder::outputBufferSize(fileSize);
    }

    constexpr const char* kConfigRequest = R"({"resource_type":"config","resource_id":"web-servers"})";
    constexpr const char* kWpkRequest = R"({"resource_type":"wpk","resource_id":"pkg.wpk"})";
    constexpr const char* kOffer = "Accept-Encoding: zstd\r\n";

    /// Every client that asks for a configuration is in the same group, so they all get the same file.
    class FixedGroupSource final : public IAgentGroupSource
    {
    public:
        explicit FixedGroupSource(bool allow)
            : m_allow(allow)
        {
        }

        void resolveSelector(const std::string&, std::function<void(GroupVerdict)> done) const override
        {
            done(m_allow ? GroupVerdict {GroupVerdictKind::Selector, "web-servers"}
                         : GroupVerdict {GroupVerdictKind::Deny, {}});
        }

    private:
        bool m_allow;
    };

    /// TLS client that reads on demand, so a transfer stays in flight while the test looks at the server.
    class SlowTlsClient
    {
    public:
        SlowTlsClient() = default;
        SlowTlsClient(const SlowTlsClient&) = delete;
        SlowTlsClient& operator=(const SlowTlsClient&) = delete;

        void connectAndSend(std::uint16_t port, const std::string& bytes)
        {
            m_context.set_verify_mode(asio::ssl::verify_none);
            m_stream = std::make_unique<asio::ssl::stream<asio::ip::tcp::socket>>(m_ioc, m_context);
            asio::ip::tcp::resolver resolver {m_ioc};
            asio::connect(m_stream->next_layer(), resolver.resolve("127.0.0.1", std::to_string(port)));
            m_stream->handshake(asio::ssl::stream_base::client);
            asio::write(*m_stream, asio::buffer(bytes));
        }

        /// Blocks until @p count bytes (head included) have arrived, the peer closes or the deadline passes.
        const std::string& readAtLeast(std::size_t count, std::chrono::seconds deadline = kClientDeadline)
        {
            pump(count, deadline);
            return m_received;
        }

        const std::string& readToEnd(std::chrono::seconds deadline = kClientDeadline)
        {
            pump(std::string::npos, deadline);
            return m_received;
        }

        void close()
        {
            m_stream.reset();
        }

        /// Whether the last read ended because the peer closed, as opposed to the deadline passing.
        bool closedByPeer() const
        {
            return m_closedByPeer;
        }

    private:
        void pump(std::size_t count, std::chrono::seconds deadline)
        {
            if (!m_stream)
            {
                return;
            }
            const auto end = Clock::now() + deadline;
            std::vector<char> buffer(64 * 1024);
            while (m_received.size() < count)
            {
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(end - Clock::now());
                if (remaining.count() <= 0)
                {
                    break;
                }
                timeval timeout {static_cast<time_t>(remaining.count() / 1000),
                                 static_cast<suseconds_t>((remaining.count() % 1000) * 1000)};
                ::setsockopt(
                    m_stream->next_layer().native_handle(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
                asio::error_code ec;
                const auto n = m_stream->read_some(asio::buffer(buffer), ec);
                if (ec)
                {
                    m_closedByPeer = ec == asio::error::eof || ec == asio::ssl::error::stream_truncated;
                    break;
                }
                m_received.append(buffer.data(), n);
            }
        }

        asio::io_context m_ioc;
        asio::ssl::context m_context {asio::ssl::context::tls_client};
        std::unique_ptr<asio::ssl::stream<asio::ip::tcp::socket>> m_stream;
        std::string m_received;
        bool m_closedByPeer {false};
    };

    struct Download
    {
        std::string head;
        std::string wire; // chunked body as received
        std::string body; // chunk-decoded body
        bool complete {false};
    };

    Download parse(const std::string& raw)
    {
        Download out;
        std::tie(out.head, out.wire) = remoted::test::splitResponse(raw);
        std::vector<std::size_t> sizes;
        out.body = remoted::test::decodeChunked(out.wire, sizes, out.complete);
        return out;
    }

    /// A real TLS server with the real gateway and download handler over a scratch directory.
    class DownloadServer
    {
    public:
        explicit DownloadServer(bool allowGroup = true, const std::function<void(HttpServerConfig&)>& tune = {})
        {
            m_cert = remoted::test::generateTestCertificate("rmt_compressed_download");
            if (!m_cert)
            {
                return;
            }
            char pattern[] = "/tmp/rmt_compressed_download_XXXXXX";
            const auto directory = ::mkdtemp(pattern);
            if (!directory)
            {
                throw std::runtime_error("could not create the scratch directory");
            }
            m_root = directory;
            std::filesystem::create_directories(m_root + "/shared/web-servers");
            std::filesystem::create_directories(m_root + "/multigroups");
            std::filesystem::create_directories(m_root + "/upgrade");

            HttpServerConfig config;
            static std::atomic<std::uint16_t> offset {1000};
            config.port = static_cast<std::uint16_t>(18000 + ::getpid() % 500 + offset++ % 500);
            config.certificatePath = m_cert->certPath;
            config.privateKeyPath = m_cert->keyPath;
            config.caPublicationRecordPath = "";
            // A client that stops reading keeps a write pending; the 10 s default timers would cut it.
            config.writeTimeoutSec = 120;
            config.requestTimeoutSec = 120;
            config.contentEncodingEnabled = true;
            if (tune)
            {
                tune(config);
            }
            m_config = config;

            m_server = makeHttpServer();
            m_gateway = std::make_unique<AuthGateway>(
                remoted::auth::AuthConfig {},
                std::make_shared<remoted::test::FakeKeystore>(),
                std::make_shared<const remoted::decoding::BodyDecoder>(*m_server, config.contentEncodingEnabled));
            m_gateway->addAuthenticatedRoute(
                *m_server,
                Method::Post,
                "/download",
                download::makeHandler(
                    download::ResourcePaths {m_root + "/shared", m_root + "/multigroups", m_root + "/upgrade"},
                    {},
                    std::make_shared<const FixedGroupSource>(allowGroup)),
                ResponseMode::Streamable);
            try
            {
                m_server->start(config);
            }
            catch (...)
            {
                // The destructor does not run for a constructor that throws.
                m_server.reset();
                cleanup();
                throw;
            }
            m_initialAvailable = m_server->diagnostics().budgetAvailableBytes;
        }

        DownloadServer(const DownloadServer&) = delete;
        DownloadServer& operator=(const DownloadServer&) = delete;

        // Stopping with a compressed transfer still in flight leaks its reservation, so wait for
        // every one to be released first. Plain transfers reserve nothing: tests read them to the end.
        ~DownloadServer()
        {
            if (m_server)
            {
                const auto end = Clock::now() + std::chrono::seconds {10};
                while ((m_server->diagnostics().budgetAvailableBytes != m_initialAvailable ||
                        m_server->diagnostics().connectionsOpen != 0) &&
                       Clock::now() < end)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds {20});
                }
                m_server->stop();
            }
            cleanup();
        }

        bool available() const
        {
            return m_cert.has_value();
        }

        std::uint16_t port() const
        {
            return m_config.port;
        }

        std::size_t availableBytes() const
        {
            return m_server->diagnostics().budgetAvailableBytes;
        }

        std::size_t initialAvailableBytes() const
        {
            return m_initialAvailable;
        }

        std::string configPath() const
        {
            return m_root + "/shared/web-servers/merged.mg";
        }

        std::string wpkPath() const
        {
            return m_root + "/upgrade/pkg.wpk";
        }

        void write(const std::string& path, const std::string& contents) const
        {
            std::ofstream out {path, std::ios::binary};
            out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        }

        std::string request(const std::string& body, const std::string& extraHeaders = {}) const
        {
            return remoted::test::signedRequest(remoted::test::testAgentKey(), "/download", body, extraHeaders);
        }

        Download fetch(const std::string& body, const std::string& extraHeaders = {}) const
        {
            return parse(remoted::test::sendRawOverTls(m_config.port, request(body, extraHeaders)));
        }

    private:
        void cleanup()
        {
            if (!m_root.empty())
            {
                std::error_code ec;
                std::filesystem::remove_all(m_root, ec);
            }
            if (m_cert)
            {
                std::remove(m_cert->certPath.c_str());
                std::remove(m_cert->keyPath.c_str());
            }
        }
        std::optional<remoted::test::TestCertificate> m_cert;
        std::string m_root;
        HttpServerConfig m_config;
        std::unique_ptr<IHttpServer> m_server;
        std::unique_ptr<AuthGateway> m_gateway;
        std::size_t m_initialAvailable {0};
    };

#define SKIP_WITHOUT_SERVER(server)                                                                                    \
    if (!(server).available())                                                                                         \
    {                                                                                                                  \
        GTEST_SKIP() << "openssl not available to generate a test certificate";                                        \
    }
} // namespace

TEST(CompressedDownloadE2E, DecodedBodyHashEqualsTheFile)
{
    DownloadServer server;
    SKIP_WITHOUT_SERVER(server);
    const auto file = incompressible(300 * 1024, 1);
    server.write(server.configPath(), file);

    const auto response = server.fetch(kConfigRequest, kOffer);

    EXPECT_NE(response.head.find("HTTP/1.1 200"), std::string::npos) << response.head;
    EXPECT_TRUE(headerPresent(response.head, "transfer-encoding: chunked")) << response.head;
    EXPECT_FALSE(headerPresent(response.head, "content-length:")) << response.head;
    EXPECT_EQ(countHeader(response.head, "content-encoding"), 1U) << response.head;
    EXPECT_TRUE(headerPresent(response.head, "content-encoding: zstd\r\n")) << response.head;
    ASSERT_TRUE(response.complete);

    const auto decoded = zstdDecode(response.body, alwaysReserve, alwaysReserve);
    ASSERT_TRUE(std::holds_alternative<std::string>(decoded));
    EXPECT_EQ(std::get<std::string>(decoded), file);
    EXPECT_EQ(sha256Hex(std::get<std::string>(decoded)), sha256Hex(file));
}

TEST(CompressedDownloadE2E, WithoutAnOfferTheResponseIsPlain)
{
    DownloadServer server;
    SKIP_WITHOUT_SERVER(server);
    const auto file = incompressible(300 * 1024, 2);
    server.write(server.configPath(), file);

    for (const std::string headers : {std::string {}, std::string {"Accept-Encoding: gzip\r\n"}})
    {
        const auto response = server.fetch(kConfigRequest, headers);
        EXPECT_NE(response.head.find("HTTP/1.1 200"), std::string::npos) << response.head;
        EXPECT_FALSE(headerPresent(response.head, "content-encoding:")) << response.head;
        EXPECT_TRUE(response.complete);
        EXPECT_EQ(response.body, file) << "offer: [" << headers << "]";
    }
}

TEST(CompressedDownloadE2E, WpkIsNeverCompressedEvenIfOffered)
{
    DownloadServer server;
    SKIP_WITHOUT_SERVER(server);
    const auto wpk = patternPayload(200000);
    server.write(server.wpkPath(), wpk);

    const auto response = server.fetch(kWpkRequest, kOffer);

    EXPECT_NE(response.head.find("HTTP/1.1 200"), std::string::npos) << response.head;
    EXPECT_FALSE(headerPresent(response.head, "content-encoding:")) << response.head;
    EXPECT_TRUE(response.complete);
    EXPECT_EQ(response.body, wpk);
}

TEST(CompressedDownloadE2E, ErrorBodiesAreIdenticalWithAndWithoutTheOffer)
{
    DownloadServer allowed;
    DownloadServer denied(/*allowGroup=*/false);
    SKIP_WITHOUT_SERVER(allowed);
    SKIP_WITHOUT_SERVER(denied);

    struct Case
    {
        const DownloadServer* server;
        std::string body;
        std::string status;
    };
    const std::vector<Case> cases {
        {&allowed, R"({"resource_type":"wpk","resource_id":"missing.wpk"})", "HTTP/1.1 404"},
        {&allowed, "this is not a download request", "HTTP/1.1 400"},
        {&denied, kConfigRequest, "HTTP/1.1 403"},
    };

    for (const auto& c : cases)
    {
        const auto plain = c.server->fetch(c.body);
        const auto offered = c.server->fetch(c.body, kOffer);

        EXPECT_EQ(plain.head.rfind(c.status, 0), 0U) << plain.head;
        EXPECT_EQ(headWithoutDate(offered.head), headWithoutDate(plain.head));
        EXPECT_EQ(offered.wire, plain.wire);
        EXPECT_FALSE(headerPresent(offered.head, "content-encoding:")) << offered.head;
        EXPECT_FALSE(headerPresent(plain.head, "content-encoding:")) << plain.head;
    }
}

TEST(CompressedDownloadE2E, AnEmptyConfigIsAValidEmptyFrame)
{
    DownloadServer server;
    SKIP_WITHOUT_SERVER(server);
    server.write(server.configPath(), "");

    const auto response = server.fetch(kConfigRequest, kOffer);

    EXPECT_NE(response.head.find("HTTP/1.1 200"), std::string::npos) << response.head;
    EXPECT_TRUE(headerPresent(response.head, "content-encoding: zstd\r\n")) << response.head;
    ASSERT_TRUE(response.complete);
    const auto decoded = zstdDecode(response.body, alwaysReserve, alwaysReserve);
    ASSERT_TRUE(std::holds_alternative<std::string>(decoded));
    EXPECT_EQ(std::get<std::string>(decoded), "");
}

TEST(CompressedDownloadE2E, GateOffServesPlainAndStillRejectsZstdRequests)
{
    DownloadServer server(true, [](HttpServerConfig& config) { config.contentEncodingEnabled = false; });
    SKIP_WITHOUT_SERVER(server);
    const auto file = incompressible(100 * 1024, 3);
    server.write(server.configPath(), file);

    const auto response = server.fetch(kConfigRequest, kOffer);
    EXPECT_NE(response.head.find("HTTP/1.1 200"), std::string::npos) << response.head;
    EXPECT_FALSE(headerPresent(response.head, "content-encoding:")) << response.head;
    EXPECT_TRUE(response.complete);
    EXPECT_EQ(response.body, file);

    const std::string json = kConfigRequest;
    std::string compressed(ZSTD_compressBound(json.size()), '\0');
    compressed.resize(ZSTD_compress(compressed.data(), compressed.size(), json.data(), json.size(), 3));
    const auto rejected = remoted::test::splitResponse(
        remoted::test::sendRawOverTls(server.port(), server.request(compressed, "Content-Encoding: zstd\r\n")));
    EXPECT_EQ(rejected.first.rfind("HTTP/1.1 415", 0), 0U) << rejected.first;
    EXPECT_EQ(rejected.second, R"({"error":"Unsupported Content-Encoding","code":415})");
}

TEST(CompressedDownloadE2E, TheCompressorMemoryIsChargedWhileStreamingAndReleasedAfter)
{
    DownloadServer server;
    SKIP_WITHOUT_SERVER(server);
    constexpr std::size_t kFileSize = 32 * kMiB;
    server.write(server.configPath(), incompressible(kFileSize, 4));
    const auto required = zstdRequirement(kFileSize);

    const auto before = server.availableBytes();
    SlowTlsClient client;
    client.connectAndSend(server.port(), server.request(kConfigRequest, kOffer));
    const auto& received = client.readAtLeast(128 * 1024);
    ASSERT_GE(received.size(), 128U * 1024U);
    EXPECT_TRUE(headerPresent(received.substr(0, received.find("\r\n\r\n")), "content-encoding: zstd\r\n"));

    const auto during = server.availableBytes();
    ASSERT_LE(during, before);
    EXPECT_GE(before - during, required);
    EXPECT_LE(before - during, required + 8192U);

    client.close();
    const auto end = Clock::now() + std::chrono::seconds {10};
    while (server.availableBytes() != before && Clock::now() < end)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {20});
    }
    EXPECT_EQ(server.availableBytes(), before);
}

TEST(CompressedDownloadE2E, ARequestStillFitsWhileCompressedDownloadsAreActive)
{
    constexpr std::size_t kFileSize = 32 * kMiB;
    constexpr std::size_t kMaxBody = 64 * 1024;
    constexpr std::size_t kFloor = kMaxBody + 4096;
    const auto required = zstdRequirement(kFileSize);
    DownloadServer server(true,
                          [&](HttpServerConfig& config)
                          {
                              config.maxBodySize = kMaxBody;
                              config.maxInFlightBytes = kFloor + 3 * required - 1;
                          });
    SKIP_WITHOUT_SERVER(server);
    const auto file = incompressible(kFileSize, 5);
    server.write(server.configPath(), file);

    std::vector<std::unique_ptr<SlowTlsClient>> clients;
    std::vector<std::string> heads;
    for (int i = 0; i < 3; ++i)
    {
        clients.push_back(std::make_unique<SlowTlsClient>());
        clients.back()->connectAndSend(server.port(), server.request(kConfigRequest, kOffer));
        const auto& received = clients.back()->readAtLeast(4096);
        ASSERT_NE(received.find("\r\n\r\n"), std::string::npos) << "client " << i << " got no response head";
        heads.push_back(received.substr(0, received.find("\r\n\r\n")));
    }
    EXPECT_TRUE(headerPresent(heads[0], "content-encoding: zstd\r\n")) << heads[0];
    EXPECT_TRUE(headerPresent(heads[1], "content-encoding: zstd\r\n")) << heads[1];
    EXPECT_FALSE(headerPresent(heads[2], "content-encoding:")) << heads[2];

    const auto fitting = remoted::test::sendSignedRequest(
        server.port(), remoted::test::testAgentKey(), "/download", std::string(kMaxBody, 'x'));
    EXPECT_EQ(fitting.rfind("HTTP/1.1 400", 0), 0U) << fitting.substr(0, 200);

    const auto third = parse(clients[2]->readToEnd());
    EXPECT_TRUE(third.complete);
    // A boolean, not EXPECT_EQ: on a failure gtest would print and diff two 32 MiB strings.
    EXPECT_TRUE(third.body == file) << "the plain download is not the file (" << third.body.size() << " bytes)";

    clients[0]->close();
    clients[1]->close();
}

TEST(CompressedDownloadE2E, AbortedTransferLeavesATruncatedFrame)
{
    constexpr std::size_t kFileSize = 32 * kMiB;
    DownloadServer server(true, [](HttpServerConfig& config) { config.requestTimeoutSec = 2; });
    SKIP_WITHOUT_SERVER(server);
    server.write(server.configPath(), incompressible(kFileSize, 6));

    SlowTlsClient client;
    client.connectAndSend(server.port(), server.request(kConfigRequest, kOffer));
    const auto& first = client.readAtLeast(256 * 1024);
    ASSERT_GE(first.size(), 256U * 1024U);
    EXPECT_TRUE(headerPresent(first.substr(0, first.find("\r\n\r\n")), "content-encoding: zstd\r\n"));

    std::filesystem::resize_file(server.configPath(), kFileSize / 2);
    const auto raw = client.readToEnd(std::chrono::seconds {15});

    const auto response = parse(raw);
    EXPECT_TRUE(client.closedByPeer()) << "the server did not close the connection before the deadline";
    // Half the file is what the transfer can carry before the truncation shows (plus framing and slack).
    EXPECT_LT(response.body.size(), kFileSize / 2 + kMiB);
    EXPECT_FALSE(response.complete) << "the terminating chunk arrived: " << raw.size() << " bytes";
    const auto decoded = zstdDecode(response.body, alwaysReserve, alwaysReserve);
    ASSERT_TRUE(std::holds_alternative<ZstdDecodeError>(decoded));
    EXPECT_EQ(std::get<ZstdDecodeError>(decoded), ZstdDecodeError::Malformed);
}
