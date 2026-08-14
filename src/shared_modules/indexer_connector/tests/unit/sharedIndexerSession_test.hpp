/*
 * Wazuh Indexer Connector - shared monitor / transport test fixture
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SHARED_INDEXER_SESSION_TEST_HPP
#define _SHARED_INDEXER_SESSION_TEST_HPP

#include "mocks/MockHTTPRequest.hpp"
#include "monitoring.hpp"
#include "serverSelector.hpp"
#include <atomic>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <json.hpp>
#include <memory>
#include <string>
#include <variant>
#include <vector>

/*
 * NOTE ON FILE LAYOUT: the sync and async assertions live in two separate translation units on
 * purpose. indexerConnectorSyncImpl.hpp and indexerConnectorAsyncImpl.hpp cannot be included
 * together -- both define HTTP_VERSION_CONFLICT, HTTP_CONTENT_LENGTH, HTTP_TOO_MANY_REQUESTS,
 * FORMATTED_LENGTH and appendEscapedId at file scope. That is pre-existing (every other test file
 * here includes exactly one of the two), so this fixture is shared by both instead.
 *
 * The consequence for coverage: the "one sync + one async connector cost ONE health-check round"
 * assertion cannot be written at the Impl level. It is pinned through the public facades in
 * tests/component/ instead, where only indexerConnector.hpp is needed. What each unit test file
 * below pins is the decomposition of that guarantee: adopting a monitor costs zero checks, and a
 * connector handed a pre-built selector builds none of its own.
 */

namespace shared_session_test
{
    /// Long enough that no test ever sees the periodic sweep: everything asserted here is about the
    /// ONE synchronous round TMonitoring's constructor performs.
    constexpr auto NO_PERIODIC_SWEEP {3600};

    inline const std::vector<std::string>& hosts()
    {
        static const std::vector<std::string> instance {"http://localhost:9209", "http://localhost:9210"};
        return instance;
    }

    inline nlohmann::json baseConfig()
    {
        nlohmann::json config;
        config["hosts"] = hosts();
        return config;
    }

    /// Answers every health check with "green" and counts the requests.
    inline void installCountingHealthCheck(::testing::NiceMock<MockHTTPRequest>& mock, std::atomic<int>& counter)
    {
        using ::testing::_;
        using ::testing::Invoke;

        EXPECT_CALL(mock, get(_, _, _))
            .WillRepeatedly(Invoke(
                [&counter](auto /*requestParams*/, PostRequestParametersVariant postParams, auto /*configParams*/)
                {
                    ++counter;
                    std::string response {R"([{"status":"green"}])"};
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                    }
                }));
    }
} // namespace shared_session_test

/**
 * @brief Fixture giving each test a counting health-check mock and a shared monitor factory.
 */
class SharedMonitorTestBase : public ::testing::Test
{
protected:
    std::unique_ptr<::testing::NiceMock<MockHTTPRequest>> m_mockHttpRequest;
    std::atomic<int> m_healthChecks {0};

    void SetUp() override
    {
        m_mockHttpRequest = std::make_unique<::testing::NiceMock<MockHTTPRequest>>();
        m_healthChecks = 0;
        shared_session_test::installCountingHealthCheck(*m_mockHttpRequest, m_healthChecks);
    }

    void TearDown() override
    {
        m_mockHttpRequest.reset();
    }

    std::shared_ptr<TMonitoring<MockHTTPRequest>> makeSharedMonitor()
    {
        return std::make_shared<TMonitoring<MockHTTPRequest>>(shared_session_test::hosts(),
                                                              shared_session_test::NO_PERIODIC_SWEEP,
                                                              SecureCommunication {},
                                                              m_mockHttpRequest.get());
    }

    std::unique_ptr<TServerSelector<MockHTTPRequest>>
    makeSelectorOver(const std::shared_ptr<TMonitoring<MockHTTPRequest>>& monitor)
    {
        return std::make_unique<TServerSelector<MockHTTPRequest>>(monitor, shared_session_test::hosts());
    }
};

#endif // _SHARED_INDEXER_SESSION_TEST_HPP
