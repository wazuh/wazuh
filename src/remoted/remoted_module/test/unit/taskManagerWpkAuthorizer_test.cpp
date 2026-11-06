/*
 * Wazuh remoted module - TaskManagerWpkAuthorizer unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "endpoints/taskManagerWpkAuthorizer.hpp"
// fakeUdsServer.hpp is included ONLY for makeUniqueSocketPath.
#include "fakeTaskServer.hpp"
#include "fakeUdsServer.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <json.hpp>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using remoted::endpoints::TaskManagerWpkAuthorizer;
using remoted::endpoints::WpkAuthorization;
using remoted::test::FakeTaskServer;
using namespace std::chrono_literals;

namespace
{
    constexpr uint32_t kDeadlineMs = 200;
    constexpr uint32_t kConnectTimeoutMs = 200;
    constexpr auto kAnswerWait = 3000ms;

    // Shared with the callback so a late or repeated call never outlives the test's stack.
    struct Answers
    {
        std::mutex mu;
        std::condition_variable cv;
        std::vector<WpkAuthorization> values;

        bool waitFor(std::size_t count, std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(mu);
            return cv.wait_for(lock, timeout, [&] { return values.size() >= count; });
        }

        std::vector<WpkAuthorization> snapshot()
        {
            std::lock_guard<std::mutex> lock(mu);
            return values;
        }
    };

    std::shared_ptr<Answers>
    ask(const TaskManagerWpkAuthorizer& authorizer, const std::string& agentId, const std::string& wpkFile)
    {
        auto answers = std::make_shared<Answers>();
        authorizer.authorize(agentId,
                             wpkFile,
                             [answers](WpkAuthorization decision)
                             {
                                 std::lock_guard<std::mutex> lock(answers->mu);
                                 answers->values.push_back(decision);
                                 answers->cv.notify_all();
                             });
        return answers;
    }

    void expectOneAnswer(const std::shared_ptr<Answers>& answers, WpkAuthorization expected)
    {
        ASSERT_TRUE(answers->waitFor(1, kAnswerWait));
        const auto values = answers->snapshot();
        ASSERT_EQ(values.size(), 1U);
        EXPECT_EQ(values.front(), expected);
    }
} // namespace

TEST(TaskManagerWpkAuthorizerTest, SendsTheAgentIdAndTheWpkFile)
{
    const auto path = remoted::test::makeUniqueSocketPath("wpkauth_body");
    FakeTaskServer server(path);
    server.setBody(R"({"task_id":"t1"})");
    TaskManagerWpkAuthorizer authorizer(path, kDeadlineMs, kConnectTimeoutMs);

    expectOneAnswer(ask(authorizer, "001", "x.wpk"), WpkAuthorization::Granted);

    EXPECT_EQ(server.lastPath(), "/v1/tasks/wpk-authorization");
    const auto body = nlohmann::json::parse(server.lastWpkAuthorizationBody(), nullptr, false);
    EXPECT_EQ(body, (nlohmann::json {{"agent_id", "001"}, {"wpk_file", "x.wpk"}}));
}

TEST(TaskManagerWpkAuthorizerTest, GrantsOnATaskIdAndDeniesOnNull)
{
    const auto path = remoted::test::makeUniqueSocketPath("wpkauth_decide");
    FakeTaskServer server(path);
    TaskManagerWpkAuthorizer authorizer(path, kDeadlineMs, kConnectTimeoutMs);

    server.setBody(R"({"task_id":"3f2c9a"})");
    expectOneAnswer(ask(authorizer, "001", "x.wpk"), WpkAuthorization::Granted);

    server.setBody(R"({"task_id":null})");
    expectOneAnswer(ask(authorizer, "001", "x.wpk"), WpkAuthorization::Denied);
}

TEST(TaskManagerWpkAuthorizerTest, AnythingElseIsUnavailable)
{
    const auto path = remoted::test::makeUniqueSocketPath("wpkauth_other");
    FakeTaskServer server(path);
    TaskManagerWpkAuthorizer authorizer(path, kDeadlineMs, kConnectTimeoutMs);

    struct Reply
    {
        int status;
        std::string body;
    };
    // A non-200 carrying a null task_id is the case that must not read as Denied.
    const std::vector<Reply> replies {
        {404, R"({"task_id":null})"},
        {500, R"({"task_id":null})"},
        {503, R"({"task_id":null})"},
        {200, "not json"},
        {200, "{}"},
        {200, R"({"task_id":5})"},
        {200, R"({"task_id":""})"},
        {200, R"({"task_id":[]})"},
        {200, R"({"task_id":{}})"},
    };

    for (const auto& reply : replies)
    {
        SCOPED_TRACE(std::to_string(reply.status) + " " + reply.body);
        server.setBody(reply.body, reply.status);
        expectOneAnswer(ask(authorizer, "001", "x.wpk"), WpkAuthorization::Unavailable);
    }
}

TEST(TaskManagerWpkAuthorizerTest, AnAbsentOrStalledTaskManagerIsUnavailableOnce)
{
    constexpr auto kAfterAnswer = std::chrono::milliseconds(4 * kDeadlineMs);

    {
        SCOPED_TRACE("absent");
        const auto path = remoted::test::makeUniqueSocketPath("wpkauth_absent");
        std::filesystem::remove(path);
        TaskManagerWpkAuthorizer authorizer(path, kDeadlineMs, kConnectTimeoutMs);

        const auto answers = ask(authorizer, "001", "x.wpk");
        expectOneAnswer(answers, WpkAuthorization::Unavailable);
        EXPECT_FALSE(answers->waitFor(2, kAfterAnswer));
    }

    {
        SCOPED_TRACE("stalled");
        const auto path = remoted::test::makeUniqueSocketPath("wpkauth_stall");
        FakeTaskServer server(path);
        // Answers a grant after the deadline: a late reply must neither flip the decision nor
        // produce a second call.
        server.setHandler(
            [](const httplib::Request&, httplib::Response& res)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(2 * kDeadlineMs));
                res.set_content(R"({"task_id":"t1"})", "application/json");
            });
        TaskManagerWpkAuthorizer authorizer(path, kDeadlineMs, kConnectTimeoutMs);

        const auto answers = ask(authorizer, "001", "x.wpk");
        expectOneAnswer(answers, WpkAuthorization::Unavailable);
        EXPECT_FALSE(answers->waitFor(2, kAfterAnswer));
        EXPECT_EQ(answers->snapshot().size(), 1U);
        EXPECT_EQ(server.requestCount(), 1U);
    }
}

TEST(TaskManagerWpkAuthorizerTest, StopIsIdempotentAndLaterRequestsAreUnavailable)
{
    const auto path = remoted::test::makeUniqueSocketPath("wpkauth_stop");
    FakeTaskServer server(path);
    server.setBody(R"({"task_id":"t1"})");
    TaskManagerWpkAuthorizer authorizer(path, kDeadlineMs, kConnectTimeoutMs);

    authorizer.stop();
    authorizer.stop();

    // Inspected without waiting: the answer has to be there when authorize() returns.
    const auto answers = ask(authorizer, "001", "x.wpk");
    const auto values = answers->snapshot();
    ASSERT_EQ(values.size(), 1U);
    EXPECT_EQ(values.front(), WpkAuthorization::Unavailable);
    EXPECT_EQ(server.requestCount(), 0U);
}

TEST(TaskManagerWpkAuthorizerTest, StopWithARequestInFlightReleasesItsCallbackWithoutAnswering)
{
    const auto path = remoted::test::makeUniqueSocketPath("wpkauth_stop_inflight");
    FakeTaskServer server(path);
    server.setHandler(
        [](const httplib::Request&, httplib::Response& res)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(2 * kDeadlineMs));
            res.set_content(R"({"task_id":"t1"})", "application/json");
        });
    // A deadline far past the server's delay: only stop() can end this request.
    TaskManagerWpkAuthorizer authorizer(path, 10 * kDeadlineMs, kConnectTimeoutMs);

    auto sentinel = std::make_shared<int>(0);
    const std::weak_ptr<int> alive {sentinel};
    auto answers = std::make_shared<Answers>();
    authorizer.authorize("001",
                         "x.wpk",
                         [answers, sentinel = std::move(sentinel)](WpkAuthorization decision)
                         {
                             std::lock_guard<std::mutex> lock(answers->mu);
                             answers->values.push_back(decision);
                             answers->cv.notify_all();
                         });
    const auto deadline = std::chrono::steady_clock::now() + kAnswerWait;
    while (server.requestCount() == 0 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(10ms);
    }
    ASSERT_GE(server.requestCount(), 1U) << "the request must be in flight before stop()";

    authorizer.stop();

    EXPECT_TRUE(alive.expired()) << "stop() must release the queued session and what its callback holds";
    EXPECT_FALSE(answers->waitFor(1, std::chrono::milliseconds(4 * kDeadlineMs)));
}
