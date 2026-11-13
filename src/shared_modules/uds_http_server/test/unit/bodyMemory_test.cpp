/*
 * Wazuh shared UDS HTTP server library - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sanitizers.hpp"
#include "udsTestClient.hpp"
#include <uds_http_server/IUdsHttpServer.hpp>
#include <uds_http_server/udsHttpServerFactory.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <thread>

using wazuh::uds_http::HttpRequest;
using wazuh::uds_http::HttpResponse;
using wazuh::uds_http::IHttpResponder;
using wazuh::uds_http::IUdsHttpServer;
using wazuh::uds_http::makeUdsHttpServer;
using wazuh::uds_http::Method;
using wazuh::uds_http::UdsHttpServerConfig;
using wazuh::uds_http::test::peerRequest;
using wazuh::uds_http::test::sendRaw;
using wazuh::uds_http::test::uniqueSocketPath;

/*
 * What a server does with the memory of a request body when the declared Content-Length is extreme: refused
 * at the head when no buffer could hold it, reserved only as it arrives when the server has no body limit,
 * answered (not left to a timer) when an allocation fails, and in every case followed by a server that still
 * serves the next request with every counter released.
 */
namespace
{
    /// Configures a server with no in-flight byte budget and no body cap: bodies have no size limit.
    void withoutBodyLimit(UdsHttpServerConfig& config)
    {
        config.maxInFlightBytes = 0;
    }

    /// The head of a POST to /x declaring @p contentLength, written verbatim.
    std::string headDeclaring(const std::string& contentLength)
    {
        return "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: " + contentLength + "\r\n\r\n";
    }

    bool waitFor(const std::function<bool()>& condition, std::chrono::milliseconds timeout = std::chrono::seconds {5})
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline)
        {
            if (condition())
            {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds {10});
        }
        return condition();
    }
} // namespace

class BodyMemoryTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_socketPath = uniqueSocketPath("body");
        m_config.socketPath = m_socketPath;
        m_config.ioThreads = 2;
        m_config.headerTimeoutSec = 2;
        // Long on purpose: an answer that arrives well before it was decided, not by a timer.
        m_config.bodyTimeoutSec = 30;
        m_config.responseTimeoutSec = 5;
        m_config.drainTimeoutSec = 1;
    }

    void TearDown() override
    {
        if (m_server)
        {
            m_server->stop();
        }
        std::error_code ignored;
        std::filesystem::remove(m_socketPath, ignored);
    }

    /// Starts a server whose POST /x answers with the size of the body it received.
    void start()
    {
        m_server = makeUdsHttpServer();
        m_server->addRoute(Method::Post,
                           "/x",
                           [](std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
                           { responder->send(HttpResponse::json(200, std::to_string(request->body.size()))); });
        m_server->start(m_config);
    }

    /// The server still serves an ordinary request, and holds no session or byte reservation afterwards.
    void expectServesTheNextRequestWithEverythingReleased()
    {
        const auto next = sendRaw(m_socketPath, peerRequest("POST", "/x", "abc"));
        EXPECT_EQ(200, next.status);
        EXPECT_EQ("3", next.body);
        EXPECT_TRUE(waitFor([&] { return m_server->diagnostics().liveSessions == 0; })) << "every session was released";
        const auto diagnostics = m_server->diagnostics();
        EXPECT_EQ(0U, diagnostics.budgetInFlightBytes);
        EXPECT_EQ(0U, diagnostics.budgetInFlightCount);
    }

    std::string m_socketPath;
    UdsHttpServerConfig m_config;
    std::unique_ptr<IUdsHttpServer> m_server;
};

namespace
{
    struct ServerLengthCase
    {
        const char* name;
        bool bodyLimit;
        std::string contentLength;
    };
} // namespace

class BodyMemoryImpossibleLengthTest
    : public BodyMemoryTest
    , public ::testing::WithParamInterface<ServerLengthCase>
{
};

// A declared length no buffer could hold: an immediate 413, with or without a body limit, never a reserve that
// throws and leaves the connection to the body timer.
TEST_P(BodyMemoryImpossibleLengthTest, IsAnswered413AtOnce)
{
    if (!GetParam().bodyLimit)
    {
        withoutBodyLimit(m_config);
    }
    start();

    const auto started = std::chrono::steady_clock::now();
    const auto response = sendRaw(m_socketPath, headDeclaring(GetParam().contentLength));
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_EQ(413, response.status);
    EXPECT_LT(elapsed, std::chrono::seconds {5}) << "decided at the head, not by the body timer";
    expectServesTheNextRequestWithEverythingReleased();
}

INSTANTIATE_TEST_SUITE_P(
    DeclaredLengths,
    BodyMemoryImpossibleLengthTest,
    ::testing::Values(
        ServerLengthCase {"MaxUint64WithoutALimit", false, std::to_string(std::numeric_limits<std::uint64_t>::max())},
        ServerLengthCase {"OverMaxSizeWithoutALimit", false, std::to_string(std::string {}.max_size() + 1)},
        ServerLengthCase {
            "MaxUint64WithTheDefaultBudget", true, std::to_string(std::numeric_limits<std::uint64_t>::max())}),
    [](const ::testing::TestParamInfo<ServerLengthCase>& info) { return std::string {info.param.name}; });

// The bounded initial reserve is not a body limit: a body several times larger is served whole.
TEST_F(BodyMemoryTest, WithoutALimitABodyLargerThanTheInitialReserveIsServed)
{
    withoutBodyLimit(m_config);
    start();
    const std::string body(3U * 1024U * 1024U + 7U, 'b');

    const auto response = sendRaw(m_socketPath, peerRequest("POST", "/x", body));

    EXPECT_EQ(200, response.status);
    EXPECT_EQ(std::to_string(body.size()), response.body);
}

class BodyMemoryBodyTimeoutTest
    : public BodyMemoryTest
    , public ::testing::WithParamInterface<bool>
{
};

// A head declaring a terabyte with a few body bytes behind it, then silence: accepted without reserving the
// terabyte, and ended by the body timeout -- silently by default, with a 400 when the server opts in.
TEST_P(BodyMemoryBodyTimeoutTest, AStalledHugeBodyEndsAtTheBodyTimeout)
{
    const auto answer = GetParam();
    withoutBodyLimit(m_config);
    m_config.bodyTimeoutSec = 1;
    m_config.answerBodyTimeout = answer;
    start();

    const auto started = std::chrono::steady_clock::now();
    const auto response = sendRaw(m_socketPath, headDeclaring(std::to_string(std::uint64_t {1} << 40U)) + "0123456789");
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_TRUE(response.connected);
    EXPECT_LT(elapsed, std::chrono::seconds {5}) << "ended by the server, not by the client's deadline";
    if (answer)
    {
        EXPECT_EQ(400, response.status);
        EXPECT_EQ(R"({"error":"Request body not received in time","code":400})", response.body);
    }
    else
    {
        EXPECT_TRUE(response.raw.empty()) << "closed without a response";
    }
    expectServesTheNextRequestWithEverythingReleased();
}

INSTANTIATE_TEST_SUITE_P(AnswerBodyTimeout,
                         BodyMemoryBodyTimeoutTest,
                         ::testing::Bool(),
                         [](const ::testing::TestParamInfo<bool>& info)
                         { return info.param ? std::string {"Answered400"} : std::string {"SilentClose"}; });

// A budget so large it admits a length that can be represented but not allocated (what a consumer gets when it
// makes the budget "unlimited"): the failed reserve is a prompt 500, and the request's budget reservation and
// session are released with it.
TEST_F(BodyMemoryTest, AReserveThatCannotBeSatisfiedIsAnswered500AndReleased)
{
    if (wazuh::uds_http::test::UNDER_ADDRESS_SANITIZER)
    {
        GTEST_SKIP() << "AddressSanitizer aborts on the allocation instead of throwing std::bad_alloc";
    }
    m_config.maxInFlightBytes = std::numeric_limits<std::size_t>::max() - 1;
    start();

    const auto started = std::chrono::steady_clock::now();
    const auto response = sendRaw(m_socketPath, headDeclaring(std::to_string(std::string {}.max_size())));
    const auto elapsed = std::chrono::steady_clock::now() - started;

    EXPECT_EQ(500, response.status);
    EXPECT_LT(elapsed, std::chrono::seconds {5}) << "answered, not left to the body timer";
    expectServesTheNextRequestWithEverythingReleased();
}
