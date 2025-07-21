/*
 * Wazuh Indexer Connector - ServerSelector tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 08, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SERVER_SELECTOR_TEST_HPP
#define _SERVER_SELECTOR_TEST_HPP

#include "mocks/MockHTTPRequest.hpp"
#include "serverSelector.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <json.hpp>
#include <memory>
#include <string>
#include <variant>
#include <vector>

// Use TServerSelector with MockHTTPRequest for testing
using TestServerSelector = TServerSelector<MockHTTPRequest>;

/**
 * @brief Runs unit tests for ServerSelector class using mocked HTTP requests
 */
class ServerSelectorTest : public ::testing::Test
{
protected:
    std::unique_ptr<::testing::NiceMock<MockHTTPRequest>> m_mockHttpRequest; ///< Mock HTTP request for testing

    /**
     * @brief Sets initial conditions for each test case.
     */
    void SetUp() override
    {
        // Create mock HTTP request
        m_mockHttpRequest = std::make_unique<::testing::NiceMock<MockHTTPRequest>>();
    }

    void TearDown() override
    {
        m_mockHttpRequest.reset();
    }

    /**
     * @brief Helper to setup mock HTTP responses for health checks
     *
     * @param server1Health Status for green server (9209)
     * @param server2Health Status for red server (9210)
     * @param server3Health Status for yellow server (9211)
     */
    void setupHealthCheckMocks(const std::string& server1Health,
                               const std::string& server2Health,
                               const std::string& server3Health)
    {
        using ::testing::_;
        using ::testing::Invoke;

        EXPECT_CALL(*m_mockHttpRequest, get(_, _, _))
            .WillRepeatedly(Invoke(
                [server1Health, server2Health, server3Health](
                    auto requestParams, PostRequestParametersVariant postParams, auto /*configParams*/)
                {
                    // Extract the URL to determine which server is being checked
                    std::string url;
                    if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                    {
                        url = std::get<TRequestParameters<std::string>>(requestParams).url.url();
                    }
                    else
                    {
                        url = std::get<TRequestParameters<nlohmann::json>>(requestParams).url.url();
                    }

                    std::string response;
                    if (url.find("9209") != std::string::npos)
                    {
                        // Green server
                        response = R"([{"status":")" + server1Health + R"("}])";
                    }
                    else if (url.find("9210") != std::string::npos)
                    {
                        // Red server
                        response = R"([{"status":")" + server2Health + R"("}])";
                    }
                    else if (url.find("9211") != std::string::npos)
                    {
                        // Yellow server
                        response = R"([{"status":")" + server3Health + R"("}])";
                    }

                    if (!response.empty())
                    {
                        if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                        {
                            std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                        }
                        else
                        {
                            std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                        }
                    }
                    else
                    {
                        if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                        {
                            std::get<TPostRequestParameters<const std::string&>>(postParams)
                                .onError("Server not found", 404);
                        }
                        else
                        {
                            std::get<TPostRequestParameters<std::string&&>>(postParams)
                                .onError("Server not found", 404);
                        }
                    }
                }));
    }
};

#endif // _SERVER_SELECTOR_TEST_HPP
