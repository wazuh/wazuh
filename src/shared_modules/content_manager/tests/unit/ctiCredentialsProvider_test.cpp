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

#include "ctiCredentialsProvider_test.hpp"

using namespace testing;

/**
 * @brief Test successful credential fetch from Indexer
 */
TEST_F(CTICredentialsProviderTest, FetchCredentialsSuccess)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Simulate successful response
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createCredentialsResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createCredentialsResponse());
                }
            }));

    CTICredentialsProvider provider(*m_mockUrlRequest, m_config);
    auto creds = provider.fetchFromIndexer();

    EXPECT_EQ(creds.accessToken, "test_access_token_123");
}

/**
 * @brief Test getAccessToken returns token and caches it
 */
TEST_F(CTICredentialsProviderTest, GetAccessTokenSuccess)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .Times(1) // Should only fetch once due to caching
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createCredentialsResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createCredentialsResponse());
                }
            }));

    CTICredentialsProvider provider(*m_mockUrlRequest, m_config);

    // First call should fetch
    auto token1 = provider.getAccessToken();
    EXPECT_EQ(token1, "test_access_token_123");

    // Second call should use cached value
    auto token2 = provider.getAccessToken();
    EXPECT_EQ(token2, "test_access_token_123");
}

/**
 * @brief Test retry logic on temporary failure
 */
TEST_F(CTICredentialsProviderTest, FetchWithRetrySuccess)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .Times(2) // First call fails, second succeeds
        .WillOnce(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Simulate error on first attempt
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Service Unavailable", 503, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Service Unavailable", 503, "");
                }
            }))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Simulate success on second attempt
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createCredentialsResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createCredentialsResponse());
                }
            }));

    CTICredentialsProvider provider(*m_mockUrlRequest, m_config);

    // Should succeed after retry
    EXPECT_NO_THROW({
        auto creds = provider.fetchFromIndexer();
        EXPECT_EQ(creds.accessToken, "test_access_token_123");
    });
}

/**
 * @brief Test failure after max retries
 */
TEST_F(CTICredentialsProviderTest, FetchFailureAfterMaxRetries)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .Times(3) // Should try 3 times (as configured)
        .WillRepeatedly(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Simulate error on all attempts
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Service Unavailable", 503, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Service Unavailable", 503, "");
                }
            }));

    CTICredentialsProvider provider(*m_mockUrlRequest, m_config);

    // Should throw after all retries exhausted
    EXPECT_THROW(provider.fetchFromIndexer(), std::runtime_error);
}

/**
 * @brief Test configuration validation - missing indexer section
 */
TEST_F(CTICredentialsProviderTest, ConfigValidationMissingIndexer)
{
    nlohmann::json badConfig = R"({})"_json;

    EXPECT_THROW(CTICredentialsProvider provider(*m_mockUrlRequest, badConfig), std::runtime_error);
}

/**
 * @brief Test configuration validation - missing URL
 */
TEST_F(CTICredentialsProviderTest, ConfigValidationMissingUrl)
{
    nlohmann::json badConfig = R"({
        "indexer": {
            "credentialsEndpoint": "/_plugins/content-manager/subscription"
        }
    })"_json;

    EXPECT_THROW(CTICredentialsProvider provider(*m_mockUrlRequest, badConfig), std::runtime_error);
}

/**
 * @brief Test invalid JSON response from Indexer
 */
TEST_F(CTICredentialsProviderTest, FetchInvalidJsonResponse)
{
    // Expect 3 retry attempts (exponential backoff)
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Return invalid JSON
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("not valid json {");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("not valid json {");
                }
            }));

    CTICredentialsProvider provider(*m_mockUrlRequest, m_config);

    EXPECT_THROW(provider.fetchFromIndexer(), std::runtime_error);
}

/**
 * @brief Test missing fields in JSON response
 */
TEST_F(CTICredentialsProviderTest, FetchMissingFields)
{
    // Expect 3 retry attempts (exponential backoff)
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .Times(3)
        .WillRepeatedly(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Return JSON missing required fields
                nlohmann::json response;
                response["access_token"] = "test_token";
                // Missing token_type

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTICredentialsProvider provider(*m_mockUrlRequest, m_config);

    EXPECT_THROW(provider.fetchFromIndexer(), std::runtime_error);
}

/**
 * @brief Test auto-refresh thread start and stop
 */
TEST_F(CTICredentialsProviderTest, AutoRefreshThreadLifecycle)
{
    CTICredentialsProvider provider(*m_mockUrlRequest, m_config);

    // Start refresh thread
    EXPECT_NO_THROW(provider.startAutoRefresh());

    // Trying to start again should log warning but not crash
    EXPECT_NO_THROW(provider.startAutoRefresh());

    // Stop refresh thread
    EXPECT_NO_THROW(provider.stopAutoRefresh());

    // Stopping again should be safe
    EXPECT_NO_THROW(provider.stopAutoRefresh());
}
