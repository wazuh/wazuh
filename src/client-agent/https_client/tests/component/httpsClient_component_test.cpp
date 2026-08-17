/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
 * End-to-end over the REAL curl path (CurlPerformer + CurlHandle) against a
 * fork-based plaintext fake manager. This is what exercises curlHandle.cpp
 * for coverage and proves cross-implementation AES-CMAC interop: the server
 * recomputes the MAC with the shared key, so a 200 means the two independent
 * implementations agree. Plaintext + HC_VERIFY_NONE by design; the TLS matrix
 * is pinned at the option level in curlPerformer_test.
 */

#include "curlHandle.hpp"
#include "curlPerformer.hpp"
#include "fakeManager.hpp"
#include "fileCompressor.hpp"
#include "keyProvider.hpp"
#include "moduleConfig.hpp"
#include "retrySender.hpp"
#include "spoolFile.hpp"
#include "sysSeams.hpp"

#include <gtest/gtest.h>

#include <zstd.h>

#include <cstring>
#include <fstream>
#include <regex>
#include <string>
#include <vector>

#include <unistd.h>

namespace
{
    constexpr uint16_t FAKE_PORT = 44853; // Distinct from http-request's 44441.
    const std::string KEY_HEX = "000102030405060708090a0b0c0d0e0f";

    ModuleConfig componentConfig()
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = FAKE_PORT;
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        config.verify_mode = HC_VERIFY_NONE;
        config.request_timeout_ms = 3000;
        config.backoff_base_ms = 10;
        config.backoff_cap_ms = 50;
        auto typed = ModuleConfig::fromC(config);
        typed.scheme = "http"; // Plaintext for the fork server.
        return typed;
    }

    // Signs and sends one request through the real curl performer.
    HttpResponse sendSigned(CurlPerformer& performer, const CmacSigner& signer,
                            const std::string& target, const std::string& body,
                            const std::vector<std::string>& extraHeaders = {})
    {
        const auto headers = signer.sign("POST", target,
                                         reinterpret_cast<const uint8_t*>(body.data()), body.size(),
                                         SystemClock {}.wallSeconds());
        HttpRequestSpec spec;
        spec.target = target;
        spec.body = reinterpret_cast<const uint8_t*>(body.data());
        spec.bodyLength = body.size();
        spec.timeoutMs = 3000;
        spec.headers = extraHeaders;
        spec.headers.push_back(headers->protocolVersion);
        spec.headers.push_back(headers->authorization);
        return performer.perform(spec);
    }

    class ComponentTest : public ::testing::Test
    {
        protected:
            ComponentTest()
                : m_config(componentConfig())
                , m_keyProvider(KEY_HEX)
                , m_signer("001", m_keyProvider)
                , m_performer(m_config, defaultCurlHandleFactory())
            {
            }

            static void SetUpTestSuite()
            {
                s_manager = new FakeManager(FAKE_PORT, KEY_HEX);
            }

            static void TearDownTestSuite()
            {
                delete s_manager;
                s_manager = nullptr;
            }

            ModuleConfig m_config;
            ConfigKeyProvider m_keyProvider;
            CmacSigner m_signer;
            CurlPerformer m_performer;
            static FakeManager* s_manager;
    };

    FakeManager* ComponentTest::s_manager = nullptr;
} // namespace

TEST_F(ComponentTest, SignedStatelessBatchIsAcceptedAndEchoed)
{
    const std::string body = "H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\nE 1:loc:hello\n";
    const auto response = sendSigned(m_performer, m_signer, "/stateless", body);
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);
    // Server echoed the body: the H/E wire shape round-tripped intact.
    EXPECT_EQ(body, response.body);
}

TEST_F(ComponentTest, ResponseStreamsToAFileThroughTheRealCurlPath)
{
    // The /stateless echo, streamed to a file instead of memory: proves the
    // real WRITEFUNCTION-to-FILE path end to end (the /download leg).
    const std::string body = "H {\"wazuh\":{\"agent\":{\"id\":\"001\"}}}\nE 1:loc:echo-to-file\n";
    const std::string path = ::testing::TempDir() + "hc_component_response.tmp";

    const auto headers = m_signer.sign("POST", "/stateless",
                                       reinterpret_cast<const uint8_t*>(body.data()), body.size(),
                                       SystemClock {}.wallSeconds());
    HttpRequestSpec spec;
    spec.target = "/stateless";
    spec.body = reinterpret_cast<const uint8_t*>(body.data());
    spec.bodyLength = body.size();
    spec.timeoutMs = 3000;
    spec.responseFilePath = path;
    spec.headers = {headers->protocolVersion, headers->authorization};

    const auto response = m_performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);
    EXPECT_TRUE(response.body.empty()); // Bytes went to the file, not memory.

    std::ifstream file {path, std::ios::binary};
    const std::string content {std::istreambuf_iterator<char>(file),
                               std::istreambuf_iterator<char>()};
    EXPECT_EQ(body, content);
    std::remove(path.c_str());
}

TEST_F(ComponentTest, ResponseSizeCapAbortsAnOversizedTransfer)
{
    // The echo returns the request body; capping the response below it makes the
    // file-write trampoline abort the transfer instead of writing unbounded.
    const std::string body(4096, 'x');
    const std::string path = ::testing::TempDir() + "hc_component_capped.tmp";

    const auto headers = m_signer.sign("POST", "/stateless",
                                       reinterpret_cast<const uint8_t*>(body.data()), body.size(),
                                       SystemClock {}.wallSeconds());
    HttpRequestSpec spec;
    spec.target = "/stateless";
    spec.body = reinterpret_cast<const uint8_t*>(body.data());
    spec.bodyLength = body.size();
    spec.responseFilePath = path;
    spec.maxResponseBytes = 1024; // Below the echoed body.
    spec.timeoutMs = 3000;
    spec.headers = {headers->protocolVersion, headers->authorization};

    const auto response = m_performer.perform(spec);
    EXPECT_NE(TransportStatus::Ok, response.status); // The cap aborted the write.
    std::remove(path.c_str());
}

TEST_F(ComponentTest, ResponseFileOpenRefusesToFollowASymlink)
{
    // The /download target is pre-created owner-only by the spool factory; if
    // it is swapped for a symlink to a victim before curl reopens it, the open
    // must refuse (O_NOFOLLOW) rather than truncate the victim through the link.
    const std::string victim = ::testing::TempDir() + "hc_resp_victim_" + std::to_string(::getpid());
    {
        std::ofstream file {victim, std::ios::binary};
        file << "precious";
    }
    const std::string link = ::testing::TempDir() + "hc_resp_link_" + std::to_string(::getpid());
    ::unlink(link.c_str());
    ASSERT_EQ(0, ::symlink(victim.c_str(), link.c_str()));

    const std::string body = "H {}\nE 1:l:x\n";
    const auto headers = m_signer.sign("POST", "/stateless",
                                       reinterpret_cast<const uint8_t*>(body.data()), body.size(),
                                       SystemClock {}.wallSeconds());
    HttpRequestSpec spec;
    spec.target = "/stateless";
    spec.body = reinterpret_cast<const uint8_t*>(body.data());
    spec.bodyLength = body.size();
    spec.timeoutMs = 3000;
    spec.responseFilePath = link; // A symlink to the victim.
    spec.headers = {headers->protocolVersion, headers->authorization};

    const auto response = m_performer.perform(spec);
    EXPECT_NE(TransportStatus::Ok, response.status); // Open refused before any HTTP.

    std::ifstream check {victim, std::ios::binary};
    const std::string content {std::istreambuf_iterator<char> {check},
                               std::istreambuf_iterator<char> {}};
    EXPECT_EQ("precious", content); // Untouched through the link.

    ::unlink(link.c_str());
    ::unlink(victim.c_str());
}

TEST_F(ComponentTest, ServerRecomputesMacSoTamperingIsRejected)
{
    // A signer with the WRONG key produces a MAC the server will not match.
    ConfigKeyProvider wrongProvider {"ffffffffffffffffffffffffffffffff"};
    CmacSigner wrongSigner {"001", wrongProvider};
    const auto response = sendSigned(m_performer, wrongSigner, "/stateless", "H {}\nE 1:l:x\n");
    EXPECT_EQ(TransportStatus::Ok, response.status); // Transport fine...
    EXPECT_EQ(401, response.httpCode);               // ...but auth refused.
}

TEST_F(ComponentTest, AuthorizationHeaderMatchesTheContractFormat)
{
    const auto headers =
        m_signer.sign("POST", "/control", reinterpret_cast<const uint8_t*>("{}"), 2, 1700000000);
    ASSERT_TRUE(headers.has_value());
    EXPECT_EQ("protocol-version: 1", headers->protocolVersion);
    const std::regex expected {R"(^Authorization: Wazuh \d{1,}:\d+:[0-9a-f]{32}$)"};
    EXPECT_TRUE(std::regex_match(headers->authorization, expected));
}

TEST_F(ComponentTest, BackPressureIsHonoredAndEachRetryReSigns)
{
    SystemClock clock;
    Mt19937Random random;
    Backoff backoff {10, 50, random};
    RetrySender sender {m_performer, m_signer, clock, backoff, false};
    Waiter waiter;

    const std::string body = "H {}\nE 1:l:bp\n";
    HttpRequestSpec spec;
    spec.target = "/stateless";
    spec.body = reinterpret_cast<const uint8_t*>(body.data());
    spec.bodyLength = body.size();
    spec.timeoutMs = 3000;
    spec.headers = {"X-Arm-Backpressure: 1"}; // Server 503s once, then 200s.

    const auto result = sender.send(spec, waiter, 4);
    EXPECT_EQ(OutcomeClass::Ok, result.outcome);
    EXPECT_EQ(200, result.response.httpCode);
}

TEST_F(ComponentTest, StatefulSessionStreamsFromSpoolAndDedupsOnReplay)
{
    TempSpoolFactory factory {::testing::TempDir()};
    std::string payload(64 * 1024, 'D'); // Larger than one read chunk.
    std::memcpy(&payload[0], "FULLSESSION:syscollector:", 25);
    const auto spool = factory.spool(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
    ASSERT_NE(nullptr, spool);

    auto sendSession = [&](const std::string & sessionId)
    {
        const auto headers = m_signer.signFile("POST", "/stateful", spool->path(),
                                               SystemClock {}.wallSeconds());
        HttpRequestSpec spec;
        spec.target = "/stateful";
        spec.bodyFilePath = spool->path();
        spec.bodyFileSize = payload.size();
        spec.timeoutMs = 3000;
        spec.headers = {"X-Session-Id: " + sessionId, headers->protocolVersion,
                        headers->authorization
                       };
        return m_performer.perform(spec);
    };

    const auto first = sendSession("sess-cmp-1");
    EXPECT_EQ(200, first.httpCode);
    // The server saw the whole streamed body (65536 bytes).
    EXPECT_NE(std::string::npos, first.body.find("\"bytes\":65536"));
    EXPECT_NE(std::string::npos, first.body.find("\"cached\":false"));

    // Same session id replayed: the manager reports it as a cached/dedup hit.
    const auto replay = sendSession("sess-cmp-1");
    EXPECT_EQ(200, replay.httpCode);
    EXPECT_NE(std::string::npos, replay.body.find("\"cached\":true"));
}

TEST_F(ComponentTest, StatefulSessionCompressesToASmallerWireSizeAndDecompressesToTheOriginal)
{
    // Same shape as the uncompressed test above, but the session is
    // compressed first (as StatefulStream::sendSession() now does) and the
    // compressed sibling is what actually crosses the real curl path.
    TempSpoolFactory factory {::testing::TempDir()};
    std::string payload(64 * 1024, 'D'); // Larger than one read chunk.
    std::memcpy(&payload[0], "FULLSESSION:syscollector:", 25);
    const auto spool = factory.spool(reinterpret_cast<const uint8_t*>(payload.data()), payload.size());
    ASSERT_NE(nullptr, spool);

    ZstdFileCompressor compressor;
    const auto compressed = compressor.compress(spool->path(), payload.size(), ::testing::TempDir(), nullptr);
    ASSERT_TRUE(compressed.has_value());
    const auto& [compressedSpool, compressedSize] = *compressed;
    ASSERT_LT(compressedSize, payload.size()); // Actually shrank.

    const auto headers = m_signer.signFile("POST", "/stateful", compressedSpool->path(),
                                           SystemClock {}.wallSeconds());
    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = compressedSpool->path();
    spec.bodyFileSize = compressedSize;
    spec.timeoutMs = 3000;
    spec.headers =
    {
        "X-Session-Id: sess-cmp-zstd", "Content-Encoding: zstd", headers->protocolVersion,
        headers->authorization
    };

    const auto response = m_performer.perform(spec);

    EXPECT_EQ(200, response.httpCode);
    // This fake manager doesn't decode the body (see fakeManager.hpp) -- it
    // just reports how many bytes it received, so this proves the *wire*
    // request really did carry the smaller, compressed byte count.
    EXPECT_NE(std::string::npos, response.body.find("\"bytes\":" + std::to_string(compressedSize)));

    // Prove those wire bytes are what a real IBodyDecoder would accept: read
    // them back independently and decompress with zstd.
    std::ifstream compressedFile {compressedSpool->path(), std::ios::binary};
    const std::string compressedBytes {std::istreambuf_iterator<char> {compressedFile},
                                       std::istreambuf_iterator<char> {}};
    std::vector<char> decompressed(payload.size());
    const size_t decompressedSize = ZSTD_decompress(decompressed.data(), decompressed.size(),
                                                    compressedBytes.data(), compressedBytes.size());
    ASSERT_FALSE(ZSTD_isError(decompressedSize));
    ASSERT_EQ(payload.size(), decompressedSize);
    EXPECT_EQ(payload, std::string(decompressed.begin(), decompressed.end()));
}

TEST_F(ComponentTest, ControlStartupReturnsHandshakeJson)
{
    const auto response = sendSigned(m_performer, m_signer, "/control",
                                     R"({"type":"startup","version":"5.1.0"})");
    EXPECT_EQ(200, response.httpCode);
    EXPECT_NE(std::string::npos, response.body.find("\"limits\""));
}

TEST_F(ComponentTest, VersionRejectionSurfacesAs409)
{
    const auto response = sendSigned(m_performer, m_signer, "/control",
                                     R"({"type":"startup"})", {"X-Reject-Version: 1"});
    EXPECT_EQ(409, response.httpCode);
    EXPECT_EQ(OutcomeClass::VersionRejected, classifyOutcome(response));
}
