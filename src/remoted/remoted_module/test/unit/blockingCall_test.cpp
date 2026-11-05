/*
 * Wazuh remoted module - sendBlocking() unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "downstream/asioUdsHttpClient.hpp"
#include "downstream/blockingCall.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include <unistd.h>

using namespace std::chrono_literals;
using remoted::downstream::AsioUdsHttpClient;
using remoted::downstream::DownstreamCallback;
using remoted::downstream::DownstreamConfig;
using remoted::downstream::DownstreamError;
using remoted::downstream::DownstreamRequest;
using remoted::downstream::DownstreamResponse;
using remoted::downstream::IDownstreamClient;
using remoted::downstream::sendBlocking;

namespace
{
    /// A client whose behaviour on sendAsync() is the test's: answer, drop the callback, keep it, throw.
    class ScriptedClient final : public IDownstreamClient
    {
    public:
        using Script = std::function<void(DownstreamCallback&)>;

        explicit ScriptedClient(Script script)
            : m_script(std::move(script))
        {
        }

        void sendAsync(DownstreamRequest, std::shared_ptr<const void>, DownstreamCallback onComplete) override
        {
            m_script(onComplete);
        }

    private:
        Script m_script;
    };

    DownstreamRequest makeRequest(const std::string& socketPath)
    {
        DownstreamRequest request;
        request.socketPath = socketPath;
        request.method = remoted::http::Method::Get;
        request.path = "/vulnerability-detector/offset";
        return request;
    }

    std::string missingSocketPath(const std::string& tag)
    {
        auto path = (std::filesystem::temp_directory_path() /
                     ("remoted-blocking-" + tag + "-" + std::to_string(::getpid()) + ".sock"))
                        .string();
        std::filesystem::remove(path);
        return path;
    }
} // namespace

TEST(BlockingCallTest, ReturnsTheResponseOfASuccessfulCall)
{
    ScriptedClient client {[](DownstreamCallback& onComplete)
                           {
                               DownstreamResponse response;
                               response.status = 200;
                               response.body = R"({"offset":7})";
                               onComplete(DownstreamError::None, std::move(response));
                           }};

    const auto result = sendBlocking(client, makeRequest("unused"), nullptr, 1s);

    EXPECT_EQ(result.error, DownstreamError::None);
    EXPECT_EQ(result.response.status, 200);
    EXPECT_EQ(result.response.body, R"({"offset":7})");
}

TEST(BlockingCallTest, PassesTheClientErrorThrough)
{
    AsioUdsHttpClient client {DownstreamConfig {}};
    client.start();

    const auto result = sendBlocking(client, makeRequest(missingSocketPath("missing")), nullptr, 5s);

    EXPECT_EQ(result.error, DownstreamError::Connect) << "the client's own classification must reach the caller";
}

TEST(BlockingCallTest, ADroppedCallbackIsATransportFailure)
{
    // What a stopped client does with a queued request when it is destroyed: the callback goes away
    // without ever being called.
    ScriptedClient client {[](DownstreamCallback& onComplete) { onComplete = nullptr; }};

    const auto start = std::chrono::steady_clock::now();
    const auto result = sendBlocking(client, makeRequest("unused"), nullptr, 10s);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(result.error, DownstreamError::Transport);
    EXPECT_LT(elapsed, 1s) << "a dropped callback must end the wait at once, not at the backstop";
}

TEST(BlockingCallTest, TheBackstopBoundsACallbackThatNeverComes)
{
    DownstreamCallback kept;
    ScriptedClient client {[&kept](DownstreamCallback& onComplete) { kept = std::move(onComplete); }};

    const auto start = std::chrono::steady_clock::now();
    const auto result = sendBlocking(client, makeRequest("unused"), nullptr, 100ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(result.error, DownstreamError::Transport);
    EXPECT_GE(elapsed, 100ms);
    EXPECT_LT(elapsed, 1s);

    // The client completing after the caller gave up must be harmless.
    ASSERT_TRUE(kept);
    kept(DownstreamError::None, DownstreamResponse {});
}

TEST(BlockingCallTest, AFailureToSendIsATransportFailure)
{
    ScriptedClient client {[](DownstreamCallback&) { throw std::runtime_error("cannot send"); }};

    const auto result = sendBlocking(client, makeRequest("unused"), nullptr, 1s);

    EXPECT_EQ(result.error, DownstreamError::Transport);
}

TEST(BlockingCallTest, AStoppedClientDoesNotHangTheCaller)
{
    AsioUdsHttpClient client {DownstreamConfig {}};
    client.start();
    client.stop();

    // A stopped client never runs the request: only the backstop can end this wait.
    const auto start = std::chrono::steady_clock::now();
    const auto result = sendBlocking(client, makeRequest(missingSocketPath("stopped")), nullptr, 200ms);
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(result.error, DownstreamError::Transport);
    EXPECT_LT(elapsed, 2s);
}
