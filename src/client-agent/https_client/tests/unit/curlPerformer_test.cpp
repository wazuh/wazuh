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
 * Pins the spec-to-options mapping (the http-request mocking idiom): every
 * TLS mode, the always-on hardening options, memory vs streamed bodies and
 * the abort wiring are asserted as exact option calls with zero network.
 */

#include "curlPerformer.hpp"
#include "mockCurlHandle.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <fstream>

using ::testing::_;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::SaveArg;

namespace
{
    ModuleConfig makeConfig(hc_verify_mode_t mode)
    {
        hc_config_t config {};
        std::strncpy(config.server_host, "127.0.0.1", sizeof(config.server_host) - 1);
        config.server_port = 27840;
        std::strncpy(config.agent_id, "001", sizeof(config.agent_id) - 1);
        config.verify_mode = mode;
        auto typed = ModuleConfig::fromC(config);
        return typed;
    }

    /// Builds a performer whose factory hands out the given mock exactly once.
    CurlPerformer makePerformer(const ModuleConfig& config, std::unique_ptr<ICurlHandle> handle)
    {
        auto shared = std::make_shared<std::unique_ptr<ICurlHandle>>(std::move(handle));
        return CurlPerformer {config,
                              [shared]() -> std::unique_ptr<ICurlHandle> { return std::move(*shared); }};
    }

    /// Partial-expectation tests: absorb the option calls they do not assert
    /// (a method with any EXPECT_CALL treats non-matching calls as failures).
    void allowOtherOptions(MockCurlHandle& handle)
    {
        EXPECT_CALL(handle, setOptionLong(_, _)).Times(::testing::AnyNumber());
        EXPECT_CALL(handle, setOptionString(_, _)).Times(::testing::AnyNumber());
        EXPECT_CALL(handle, setOptionPtr(_, _)).Times(::testing::AnyNumber());
        EXPECT_CALL(handle, appendHeader(_)).Times(::testing::AnyNumber());
    }
} // namespace

TEST(CurlPerformerTest, MemoryBodyMapsToExactOptions)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    const auto config = makeConfig(HC_VERIFY_NONE);

    const uint8_t body[] = "H {}\nE 1:loc:msg\n";
    HttpRequestSpec spec;
    spec.target = "/stateless";
    spec.headers = {"protocol-version: 1", "Authorization: Wazuh 001:1:aa"};
    spec.body = body;
    spec.bodyLength = sizeof(body) - 1;
    spec.timeoutMs = 1234;

    EXPECT_CALL(*handle, setOptionString(CurlOption::Url, "https://127.0.0.1:27840/stateless"));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::Post, 1L));
    EXPECT_CALL(*handle, setOptionPtr(CurlOption::PostFields, body));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::PostFieldSize, static_cast<long>(sizeof(body) - 1)));
    EXPECT_CALL(*handle, appendHeader("protocol-version: 1"));
    EXPECT_CALL(*handle, appendHeader("Authorization: Wazuh 001:1:aa"));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::TimeoutMs, 1234L));
    EXPECT_CALL(*handle, captureResponseBody(NotNull()));
    EXPECT_CALL(*handle, captureRetryAfter(NotNull()));
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));
    EXPECT_CALL(*handle, responseCode()).WillOnce(Return(200));

    auto performer = makePerformer(config, std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_EQ(200, response.httpCode);
}

TEST(CurlPerformerTest, ContentTypeEmittedWhenSet)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    const auto config = makeConfig(HC_VERIFY_NONE);

    const uint8_t body[] = R"({"type":"notify"})";
    HttpRequestSpec spec;
    spec.target = "/control";
    spec.contentType = "application/json";
    spec.body = body;
    spec.bodyLength = sizeof(body) - 1;

    EXPECT_CALL(*handle, appendHeader("Content-Type: application/json"));
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(spec);
}

TEST(CurlPerformerTest, NoContentTypeWhenUnset)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    const auto config = makeConfig(HC_VERIFY_NONE);

    const uint8_t body[] = "H {}\n";
    HttpRequestSpec spec;
    spec.target = "/stateless"; // */* endpoint: keep libcurl's default.
    spec.body = body;
    spec.bodyLength = sizeof(body) - 1;

    EXPECT_CALL(*handle, appendHeader(::testing::StartsWith("Content-Type:"))).Times(0);
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(spec);
}

TEST(CurlPerformerTest, ResponseBodyAndRetryAfterFlowBack)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();

    std::string* bodyOut = nullptr;
    long* retryAfterOut = nullptr;
    EXPECT_CALL(*handle, captureResponseBody(_)).WillOnce(SaveArg<0>(&bodyOut));
    EXPECT_CALL(*handle, captureRetryAfter(_)).WillOnce(SaveArg<0>(&retryAfterOut));
    EXPECT_CALL(*handle, perform())
    .WillOnce(Invoke(
                  [&]() -> TransportStatus
    {
        *bodyOut = "{\"ok\":true}";
        *retryAfterOut = 7;
        return TransportStatus::Ok;
    }));
    EXPECT_CALL(*handle, responseCode()).WillOnce(Return(503));

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    HttpRequestSpec spec;
    spec.target = "/stateless";
    const auto response = performer.perform(spec);
    EXPECT_EQ("{\"ok\":true}", response.body);
    EXPECT_EQ(7, response.retryAfterSeconds);
    EXPECT_EQ(503, response.httpCode);
}

TEST(CurlPerformerTest, TlsFullMode)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_FULL);
    config.caPath = "/etc/ca.pem";

    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyPeer, 1L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyHost, 2L));
    EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ca.pem"));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::FollowLocation, 0L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::NoSignal, 1L));

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, TlsCertModeDisablesHostnameOnly)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_CERT);
    config.caPath = "/etc/ca.pem";

    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyPeer, 1L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyHost, 0L));

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, TlsNoneModeDisablesAllVerification)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyPeer, 0L));
    EXPECT_CALL(*handle, setOptionLong(CurlOption::VerifyHost, 0L));
    EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, _)).Times(0);
    EXPECT_CALL(*handle, setOptionString(CurlOption::SslCert, _)).Times(0);
    EXPECT_CALL(*handle, setOptionString(CurlOption::SslCiphers, _)).Times(0);

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, ClientCertAndCiphersApplied)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_NONE);
    config.clientCert = "/etc/agent.pem";
    config.clientKey = "/etc/agent.key";
    config.ciphers = "HIGH:!aNULL";

    EXPECT_CALL(*handle, setOptionString(CurlOption::SslCert, "/etc/agent.pem"));
    EXPECT_CALL(*handle, setOptionString(CurlOption::SslKey, "/etc/agent.key"));
    EXPECT_CALL(*handle, setOptionString(CurlOption::SslCiphers, "HIGH:!aNULL"));

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, RejectedTlsOptionAbortsBeforePerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    // What a backend that does not implement the option answers.
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SslVersion, _)).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);

    auto performer = makePerformer(makeConfig(HC_VERIFY_FULL), std::move(mock));
    const auto response = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
}

TEST(CurlPerformerTest, RejectedCipherListAbortsBeforePerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_FULL);
    config.ciphers = "TLS_AES_128_GCM_SHA256";

    EXPECT_CALL(*handle, setOptionString(CurlOption::SslCiphers, _)).WillOnce(Return(false));
    EXPECT_CALL(*handle, perform()).Times(0);

    auto performer = makePerformer(config, std::move(mock));
    const auto response = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::TlsFail, response.status);
}

TEST(CurlPerformerTest, ConfiguredCaIsTheWholeTrustSet)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    auto config = makeConfig(HC_VERIFY_FULL);
    config.caPath = "/etc/ca.pem";

    EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, "/etc/ca.pem"));
    // The machine's own stores are never added on top of it.
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SslOptions, _)).Times(0);

    auto performer = makePerformer(config, std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, TrustAnchorsWithoutConfiguredCa)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    EXPECT_CALL(*handle, setOptionString(CurlOption::CaInfo, _)).Times(0);
#ifdef WIN32
    // Our OpenSSL-backed Windows curl has no bundle of its own to fall back on.
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SslOptions, TLS_NATIVE_CA_STORE));
#else
    EXPECT_CALL(*handle, setOptionLong(CurlOption::SslOptions, _)).Times(0);
#endif

    auto performer = makePerformer(makeConfig(HC_VERIFY_FULL), std::move(mock));
    performer.perform(HttpRequestSpec {});
}

TEST(CurlPerformerTest, FileBodyStreamsInsteadOfPostFields)
{
    const std::string path = ::testing::TempDir() + "hc_curl_performer_body.tmp";
    {
        std::ofstream file {path, std::ios::binary};
        file << "SESSION-BYTES";
    }

    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = path;
    spec.bodyFileSize = 13;

    EXPECT_CALL(*handle, streamBodyFromFile(NotNull(), 13u));
    EXPECT_CALL(*handle, setOptionPtr(CurlOption::PostFields, _)).Times(0);
    EXPECT_CALL(*handle, perform()).WillOnce(Return(TransportStatus::Ok));

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, response.status);
    std::remove(path.c_str());
}

TEST(CurlPerformerTest, MissingBodyFileFailsWithoutPerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    EXPECT_CALL(*handle, perform()).Times(0);

    HttpRequestSpec spec;
    spec.target = "/stateful";
    spec.bodyFilePath = "/nonexistent/hc-spool/session.bin";

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::OtherError, response.status);
    EXPECT_EQ(0, response.httpCode);
}

TEST(CurlPerformerTest, FactoryFailureYieldsOtherError)
{
    CurlPerformer performer {makeConfig(HC_VERIFY_NONE),
                             []() -> std::unique_ptr<ICurlHandle> { return nullptr; }};
    const auto response = performer.perform(HttpRequestSpec {});
    EXPECT_EQ(TransportStatus::OtherError, response.status);
    EXPECT_EQ(0, response.httpCode);
}

TEST(CurlPerformerTest, ResponseFilePathStreamsToTheFileNotMemory)
{
    const std::string path = ::testing::TempDir() + "hc_curl_performer_response.tmp";
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);

    std::FILE* sink = nullptr;
    EXPECT_CALL(*handle, captureResponseToFile(NotNull(), _))
    .WillOnce(Invoke([&](std::FILE * file, uint64_t)
    {
        sink = file;
    }));
    EXPECT_CALL(*handle, captureResponseBody(_)).Times(0);
    EXPECT_CALL(*handle, perform())
    .WillOnce(Invoke(
                  [&]() -> TransportStatus
    {
        std::fwrite("CONFIG-BYTES", 1, 12, sink);
        return TransportStatus::Ok;
    }));
    EXPECT_CALL(*handle, responseCode()).WillOnce(Return(200));

    HttpRequestSpec spec;
    spec.target = "/download";
    spec.responseFilePath = path;

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::Ok, response.status);
    EXPECT_TRUE(response.body.empty()); // Bytes went to the file, not memory.

    std::ifstream file {path, std::ios::binary};
    std::string content {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    EXPECT_EQ("CONFIG-BYTES", content);
    std::remove(path.c_str());
}

TEST(CurlPerformerTest, UnopenableResponseFileFailsWithoutPerforming)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    EXPECT_CALL(*handle, perform()).Times(0);

    HttpRequestSpec spec;
    spec.target = "/download";
    spec.responseFilePath = "/nonexistent/hc-download/config.tmp";

    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    const auto response = performer.perform(spec);
    EXPECT_EQ(TransportStatus::OtherError, response.status);
    EXPECT_EQ(0, response.httpCode);
}

TEST(CurlPerformerTest, RetryTruncatesThePreviousAttemptsPartialBody)
{
    // Load-bearing for retry correctness: the response file is opened "wb"
    // per attempt, so a retry never mixes bytes with a failed attempt's
    // partial body.
    const std::string path = ::testing::TempDir() + "hc_curl_performer_retry.tmp";
    std::FILE* sink = nullptr;
    int attempt = 0;

    CurlHandleFactory factory = [&]() -> std::unique_ptr<ICurlHandle>
    {
        auto handle = std::make_unique<NiceMock<MockCurlHandle>>();
        ON_CALL(*handle, captureResponseToFile(_, _))
        .WillByDefault(Invoke([&](std::FILE * file, uint64_t)
        {
            sink = file;
        }));
        ON_CALL(*handle, perform())
        .WillByDefault(Invoke(
                           [&]() -> TransportStatus
        {
            attempt++;
            const char* bytes = (attempt == 1) ? "PARTIAL-GARBAGE" : "FULL";
            std::fwrite(bytes, 1, std::strlen(bytes), sink);
            return (attempt == 1) ? TransportStatus::Timeout : TransportStatus::Ok;
        }));
        ON_CALL(*handle, responseCode()).WillByDefault(Return(attempt == 1 ? 0 : 200));
        return handle;
    };

    const auto config = makeConfig(HC_VERIFY_NONE);
    CurlPerformer performer {config, factory};
    HttpRequestSpec spec;
    spec.target = "/download";
    spec.responseFilePath = path;

    EXPECT_EQ(TransportStatus::Timeout, performer.perform(spec).status);
    EXPECT_EQ(TransportStatus::Ok, performer.perform(spec).status);

    std::ifstream file {path, std::ios::binary};
    std::string content {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    EXPECT_EQ("FULL", content); // The second attempt truncated the first.
    std::remove(path.c_str());
}

TEST(CurlPerformerTest, AbortFlagIsWiredOnlyWhenPresent)
{
    auto mock = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* handle = mock.get();
    allowOtherOptions(*handle);
    std::atomic<bool> abortFlag {false};

    HttpRequestSpec spec;
    spec.abortFlag = &abortFlag;
    EXPECT_CALL(*handle, wireAbort(&abortFlag)).Times(1);
    auto performer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(mock));
    performer.perform(spec);

    auto second = std::make_unique<NiceMock<MockCurlHandle>>();
    auto* secondHandle = second.get();
    allowOtherOptions(*secondHandle);
    EXPECT_CALL(*secondHandle, wireAbort(_)).Times(0);
    auto secondPerformer = makePerformer(makeConfig(HC_VERIFY_NONE), std::move(second));
    secondPerformer.perform(HttpRequestSpec {});
}
