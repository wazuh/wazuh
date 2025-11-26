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

#ifndef _CTI_SIGNED_URL_PROVIDER_TEST_HPP
#define _CTI_SIGNED_URL_PROVIDER_TEST_HPP

#include "HTTPRequest.hpp"
#include "ctiSignedUrlProvider.hpp"
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
 * @brief Mock class for IURLRequest interface used by CTISignedUrlProvider.
 */
class MockURLRequestSignedUrl : public IURLRequest
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
 * @brief Runs unit tests for CTISignedUrlProvider
 */
class CTISignedUrlProviderTest : public ::testing::Test
{
protected:
    CTISignedUrlProviderTest() = default;
    ~CTISignedUrlProviderTest() override = default;

    std::unique_ptr<MockURLRequestSignedUrl> m_mockUrlRequest;
    nlohmann::json m_config;

    /**
     * @brief Sets initial conditions for each test case.
     */
    void SetUp() override
    {
        m_mockUrlRequest = std::make_unique<MockURLRequestSignedUrl>();

        // Default configuration
        m_config = R"({
            "console": {
                "url": "https://console.wazuh.com"
            },
            "tokenExchange": {
                "enabled": true,
                "tokenEndpoint": "/api/v1/instances/token/exchange",
                "cacheSignedUrls": true
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
     * @brief Helper to create a valid token exchange response
     */
    std::string createTokenExchangeResponse(const std::string& signedUrl, uint64_t expiresIn = 300)
    {
        nlohmann::json response;
        response["access_token"] = signedUrl;
        response["issued_token_type"] = "urn:wazuh:params:oauth:token-type:signed_url";
        response["expires_in"] = expiresIn;
        return response.dump();
    }
};

#endif //_CTI_SIGNED_URL_PROVIDER_TEST_HPP
