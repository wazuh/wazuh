/*
 * Wazuh content manager - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The module's small public seams, which the bigger suites reach only indirectly: the
 * on-demand free function other modules call across the .so boundary, the callback wrapper
 * every pipeline stage reports through, and the factory that assembles the update chain.
 */

#include "contentOnDemand.hpp"
#include "onDemandManager.hpp"
#include "sharedDefs.hpp"

#include "gtest/gtest.h"

#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace
{
    class CapturingResponder final : public wazuh::uds_http::IHttpResponder
    {
    public:
        void send(wazuh::uds_http::HttpResponse response) override
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            m_responses.push_back(std::move(response));
        }

        std::size_t count()
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_responses.size();
        }

        wazuh::uds_http::HttpResponse first()
        {
            std::lock_guard<std::mutex> lock {m_mutex};
            return m_responses.empty() ? wazuh::uds_http::HttpResponse {} : m_responses.front();
        }

    private:
        std::mutex m_mutex;
        std::vector<wazuh::uds_http::HttpResponse> m_responses;
    };

    class ContentManagerSeamsTest : public ::testing::Test
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
} // namespace

// content_manager::dispatchOnDemand is what vulnerability_scanner's POST /ondemand route calls
// ACROSS the .so boundary -- the only entry point into this module's on-demand lane. The lane
// itself is covered elsewhere; what matters here is that the free function forwards to the
// singleton instead of quietly doing nothing.
TEST_F(ContentManagerSeamsTest, DispatchOnDemandForwardsToTheLane)
{
    auto responder = std::make_shared<CapturingResponder>();
    content_manager::dispatchOnDemand("no_such_topic", -1, responder);

    // No topic registered, so the lane answers inline with the unknown-topic verdict: proof the
    // call reached it rather than being swallowed at the boundary.
    ASSERT_EQ(1U, responder->count());
    EXPECT_EQ(404, responder->first().status);
    EXPECT_NE(std::string::npos, responder->first().body.find("unknown_topic"));
}

TEST_F(ContentManagerSeamsTest, DispatchOnDemandCarriesTheOffsetThrough)
{
    int seenOffset = 0;
    OnDemandManager::instance().addEndpoint("topic",
                                            [&seenOffset](ActionOrchestrator::UpdateData data)
                                            {
                                                seenOffset = data.offset;
                                                return true;
                                            });

    auto responder = std::make_shared<CapturingResponder>();
    content_manager::dispatchOnDemand("topic", 0, responder);

    // The lane is asynchronous, so wait on the response rather than on the callback.
    for (int i = 0; i < 500 && responder->count() == 0; ++i)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds {10});
    }
    ASSERT_EQ(1U, responder->count());
    EXPECT_EQ(200, responder->first().status);
    EXPECT_EQ(0, seenOffset) << "offset 0 means 'restart the content', and must survive the hop";
}

// invokeContentUpdateCallback is the guard every pipeline stage reports success/failure
// through. Its whole reason to exist is that a throwing consumer callback must never escape
// into the update pipeline.
TEST(ContentUpdateCallbackTest, ANullCallbackIsANoOp)
{
    EXPECT_NO_THROW(invokeContentUpdateCallback(nullptr, "success"));
}

TEST(ContentUpdateCallbackTest, TheCallbackRuns)
{
    bool called = false;
    invokeContentUpdateCallback([&called] { called = true; }, "success");
    EXPECT_TRUE(called);
}

TEST(ContentUpdateCallbackTest, AThrowingCallbackIsSwallowedAndLogged)
{
    EXPECT_NO_THROW(invokeContentUpdateCallback([] { throw std::runtime_error("boom"); }, "failure"))
        << "a consumer's exception must not propagate into the update pipeline";
}

// FactoryContentUpdater is deliberately NOT unit-tested here: creating the chain instantiates
// IndexerDownloader, which pulls IndexerConnectorSync's out-of-line symbols and would force
// this binary to link the indexer connector for seven lines of factory code. The component
// suite builds the same chain for real, and its coverage now counts.
