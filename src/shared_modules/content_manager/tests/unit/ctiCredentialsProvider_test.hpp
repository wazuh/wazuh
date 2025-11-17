/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * November 04, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CTI_CREDENTIALS_PROVIDER_TEST_HPP
#define _CTI_CREDENTIALS_PROVIDER_TEST_HPP

#include "HTTPRequest.hpp"
#include "ctiCredentialsProvider.hpp"
#include "updaterContext.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <memory>

using namespace std::chrono_literals;

// Type aliases to avoid MOCK_METHOD preprocessor issues with complex template types
using RequestParamsVariant = std::
    variant<TRequestParameters<std::string>, TRequestParameters<nlohmann::json>, TRequestParameters<std::string_view>>;
using PostRequestParamsVariant =
    std::variant<TPostRequestParameters<const std::string&>, TPostRequestParameters<std::string&&>>;

/**
 * @brief Mock class for IURLRequest interface.
 */
class MockURLRequest : public IURLRequest
{
public:
    MOCK_METHOD(void,
                get,
                (RequestParamsVariant requestParameters,
                 PostRequestParamsVariant postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));
    MOCK_METHOD(void,
                post,
                (RequestParamsVariant requestParameters,
                 PostRequestParamsVariant postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));
    MOCK_METHOD(void,
                download,
                (RequestParamsVariant requestParameters,
                 PostRequestParamsVariant postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));
    MOCK_METHOD(void,
                put,
                (RequestParamsVariant requestParameters,
                 PostRequestParamsVariant postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));
    MOCK_METHOD(void,
                patch,
                (RequestParamsVariant requestParameters,
                 PostRequestParamsVariant postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));
    MOCK_METHOD(void,
                delete_,
                (RequestParamsVariant requestParameters,
                 PostRequestParamsVariant postRequestParameters,
                 ConfigurationParameters configurationParameters),
                (override));
};

/**
 * @brief Runs unit tests for CTICredentialsProvider
 */
class CTICredentialsProviderTest : public ::testing::Test
{
protected:
    CTICredentialsProviderTest() = default;
    ~CTICredentialsProviderTest() override = default;

    std::unique_ptr<MockURLRequest> m_mockUrlRequest;
    nlohmann::json m_config;

    /**
     * @brief Sets initial conditions for each test case.
     */
    void SetUp() override
    {
        m_mockUrlRequest = std::make_unique<MockURLRequest>();

        // Default configuration
        m_config = R"({
            "indexer": {
                "url": "http://localhost:9200",
                "credentialsEndpoint": "/_plugins/content-manager/subscription",
                "pollInterval": 60,
                "timeout": 5000,
                "retryAttempts": 3
            }
        })"_json;
    }

    /**
     * @brief Tear down routine for tests
     */
    void TearDown() override
    {
        m_mockUrlRequest.reset();
    }

    /**
     * @brief Helper to create a valid credentials JSON response
     */
    std::string createCredentialsResponse()
    {
        nlohmann::json response;
        response["access_token"] = "test_access_token_123";
        response["token_type"] = "Bearer";
        return response.dump();
    }
};

#endif //_CTI_CREDENTIALS_PROVIDER_TEST_HPP
