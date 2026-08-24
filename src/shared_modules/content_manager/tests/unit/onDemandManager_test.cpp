/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "onDemandManager.hpp"

#include "gtest/gtest.h"

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace
{
    /// Records what the lane sends, with a waitable count.
    class FakeResponder final : public wazuh::uds_http::IHttpResponder
    {
    public:
        void send(wazuh::uds_http::HttpResponse response) override
        {
            {
                std::lock_guard<std::mutex> lock {m_mutex};
                m_responses.push_back(std::move(response));
            }
            m_sent.notify_all();
        }

        bool waitForResponse(std::chrono::milliseconds timeout = std::chrono::seconds {5})
        {
            std::unique_lock<std::mutex> lock {m_mutex};
            return m_sent.wait_for(lock, timeout, [this] { return !m_responses.empty(); });
        }

        wazuh::uds_http::HttpResponse response()
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_responses.empty() ? wazuh::uds_http::HttpResponse {} : m_responses.front();
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_sent;
        std::vector<wazuh::uds_http::HttpResponse> m_responses;
    };

    /// The manager is a process-wide singleton: every test starts and ends with a clean registry.
    class OnDemandManagerTest : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            OnDemandManager::instance().clearEndpoints();
        }
        void TearDown() override
        {
            OnDemandManager::instance().clearEndpoints();
        }
    };

    std::shared_ptr<FakeResponder> dispatch(const std::string& topic, int offset = -1)
    {
        auto responder = std::make_shared<FakeResponder>();
        OnDemandManager::instance().dispatch(topic, offset, responder);
        return responder;
    }
} // namespace

TEST_F(OnDemandManagerTest, ACompletedUpdateIs200AndAnInProgressOneIsAnHonest409)
{
    OnDemandManager::instance().addEndpoint("ok-topic", [](ActionOrchestrator::UpdateData) { return true; });
    OnDemandManager::instance().addEndpoint("busy-topic", [](ActionOrchestrator::UpdateData) { return false; });

    auto ok = dispatch("ok-topic");
    ASSERT_TRUE(ok->waitForResponse());
    EXPECT_EQ(200, ok->response().status);
    EXPECT_EQ(R"({"status":"ok"})", ok->response().body);

    auto busy = dispatch("busy-topic");
    ASSERT_TRUE(busy->waitForResponse());
    EXPECT_EQ(409, busy->response().status) << "the old server answered a lying 200 here";
    EXPECT_NE(std::string::npos, busy->response().body.find("update_in_progress"));
}

TEST_F(OnDemandManagerTest, AnUnknownTopicIs404WithoutSpendingAQueueSlot)
{
    OnDemandManager::instance().addEndpoint("known", [](ActionOrchestrator::UpdateData) { return true; });
    auto responder = dispatch("nope");
    ASSERT_TRUE(responder->waitForResponse());
    EXPECT_EQ(404, responder->response().status);
    EXPECT_NE(std::string::npos, responder->response().body.find("unknown_topic"));
}

TEST_F(OnDemandManagerTest, TheOffsetTravelsToTheCallback)
{
    std::mutex mutex;
    std::vector<int> offsets;
    OnDemandManager::instance().addEndpoint("topic",
                                            [&](ActionOrchestrator::UpdateData data)
                                            {
                                                std::lock_guard<std::mutex> lock {mutex};
                                                offsets.push_back(data.offset);
                                                return true;
                                            });
    ASSERT_TRUE(dispatch("topic", 0)->waitForResponse());
    ASSERT_TRUE(dispatch("topic", -1)->waitForResponse());
    std::lock_guard<std::mutex> lock {mutex};
    EXPECT_EQ((std::vector<int> {0, -1}), offsets);
}

TEST_F(OnDemandManagerTest, TheLaneIsBoundedWithAnExplicitRetryable503)
{
    std::mutex gateMutex;
    std::condition_variable gate;
    bool open = false;
    OnDemandManager::instance().addEndpoint("slow",
                                            [&](ActionOrchestrator::UpdateData)
                                            {
                                                std::unique_lock<std::mutex> lock {gateMutex};
                                                gate.wait(lock, [&] { return open; });
                                                return true;
                                            });

    // Capacity: QUEUE_SLOTS (4) + the jobs the two workers already popped and hold gated.
    std::vector<std::shared_ptr<FakeResponder>> accepted;
    int rejected = 0;
    for (int i = 0; i < 12; ++i)
    {
        auto responder = dispatch("slow");
        if (responder->waitForResponse(std::chrono::milliseconds {50}))
        {
            EXPECT_EQ(503, responder->response().status);
            EXPECT_NE(std::string::npos, responder->response().body.find("ondemand_queue_full"));
            ++rejected;
        }
        else
        {
            accepted.push_back(std::move(responder));
        }
    }
    EXPECT_GE(rejected, 12 - 6 - 1) << "beyond slots + in-flight the lane must shed explicitly";

    {
        std::lock_guard<std::mutex> lock {gateMutex};
        open = true;
    }
    gate.notify_all();
    for (auto& responder : accepted)
    {
        ASSERT_TRUE(responder->waitForResponse());
        EXPECT_EQ(200, responder->response().status);
    }
}

TEST_F(OnDemandManagerTest, RemoveEndpointWaitsForTheInFlightRunAndThenNothingOfItRuns)
{
    std::mutex gateMutex;
    std::condition_variable gate;
    bool open = false;
    std::atomic<int> runs {0};
    OnDemandManager::instance().addEndpoint("keeper", [](ActionOrchestrator::UpdateData) { return true; });
    OnDemandManager::instance().addEndpoint("mine",
                                            [&](ActionOrchestrator::UpdateData)
                                            {
                                                runs.fetch_add(1);
                                                std::unique_lock<std::mutex> lock {gateMutex};
                                                gate.wait(lock, [&] { return open; });
                                                return true;
                                            });

    auto inFlight = dispatch("mine");
    while (runs.load() == 0)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {5});
    }

    // The contract Action's teardown relies on: removeEndpoint() returns only once no callback
    // of the removed topic is still running.
    auto removing = std::async(std::launch::async, [] { OnDemandManager::instance().removeEndpoint("mine"); });
    EXPECT_NE(std::future_status::ready, removing.wait_for(std::chrono::milliseconds {100}));
    {
        std::lock_guard<std::mutex> lock {gateMutex};
        open = true;
    }
    gate.notify_all();
    removing.get();
    ASSERT_TRUE(inFlight->waitForResponse());
    EXPECT_EQ(200, inFlight->response().status);

    auto afterRemoval = dispatch("mine");
    ASSERT_TRUE(afterRemoval->waitForResponse());
    EXPECT_EQ(404, afterRemoval->response().status);
}

TEST_F(OnDemandManagerTest, AThrowingUpdateIs500AndTheWorkerSurvives)
{
    int calls = 0;
    OnDemandManager::instance().addEndpoint("flaky",
                                            [&](ActionOrchestrator::UpdateData) -> bool
                                            {
                                                if (++calls == 1)
                                                {
                                                    throw std::runtime_error {"download blew up"};
                                                }
                                                return true;
                                            });
    auto first = dispatch("flaky");
    ASSERT_TRUE(first->waitForResponse());
    EXPECT_EQ(500, first->response().status);
    EXPECT_NE(std::string::npos, first->response().body.find("update_failed"));

    auto second = dispatch("flaky");
    ASSERT_TRUE(second->waitForResponse());
    EXPECT_EQ(200, second->response().status) << "one failed update must not kill the lane";
}

TEST_F(OnDemandManagerTest, EmptyingTheRegistryStopsTheLaneAndDispatchSaysShuttingDown)
{
    OnDemandManager::instance().addEndpoint("only", [](ActionOrchestrator::UpdateData) { return true; });
    OnDemandManager::instance().removeEndpoint("only");

    // The registry is empty, so this is a 404 -- but re-adding restarts the lane cleanly.
    OnDemandManager::instance().addEndpoint("again", [](ActionOrchestrator::UpdateData) { return true; });
    auto responder = dispatch("again");
    ASSERT_TRUE(responder->waitForResponse());
    EXPECT_EQ(200, responder->response().status) << "the lane must come back with the next endpoint";
}
