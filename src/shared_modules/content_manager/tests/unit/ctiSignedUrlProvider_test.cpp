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

#include "ctiSignedUrlProvider_test.hpp"

using namespace testing;

/**
 * @brief Test successful token exchange
 */
TEST_F(CTISignedUrlProviderTest, TokenExchangeSuccess)
{
    const std::string resourceUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";
    const std::string signedUrl = resourceUrl + "?verify=1234567890-hmac_signature";

    EXPECT_CALL(*m_mockUrlRequest, post(_, _, _))
        .WillOnce(Invoke(
            [this, signedUrl](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Simulate successful token exchange
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedUrl));
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedUrl));
                }
            }));

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    auto result = provider.exchangeForSignedUrl(resourceUrl);
    EXPECT_EQ(result, signedUrl);
}

/**
 * @brief Test token exchange without setting access token
 */
TEST_F(CTISignedUrlProviderTest, TokenExchangeNoAccessToken)
{
    const std::string resourceUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);
    // Don't set access token

    EXPECT_THROW(provider.exchangeForSignedUrl(resourceUrl), std::runtime_error);
}

/**
 * @brief Test signed URL caching (cache hit)
 */
TEST_F(CTISignedUrlProviderTest, CacheHitOnSecondRequest)
{
    const std::string resourceUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";
    const std::string signedUrl = resourceUrl + "?verify=1234567890-hmac_signature";

    EXPECT_CALL(*m_mockUrlRequest, post(_, _, _))
        .Times(1) // Should only be called once due to caching
        .WillOnce(Invoke(
            [this, signedUrl](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedUrl, 300));
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedUrl, 300));
                }
            }));

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    // First request - should perform token exchange
    auto result1 = provider.exchangeForSignedUrl(resourceUrl);
    EXPECT_EQ(result1, signedUrl);

    // Second request - should use cache
    auto result2 = provider.exchangeForSignedUrl(resourceUrl);
    EXPECT_EQ(result2, signedUrl);
}

/**
 * @brief Test cache expiration
 */
TEST_F(CTISignedUrlProviderTest, CacheExpiration)
{
    const std::string resourceUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";
    const std::string signedUrl1 = resourceUrl + "?verify=first_signature";
    const std::string signedUrl2 = resourceUrl + "?verify=second_signature";

    EXPECT_CALL(*m_mockUrlRequest, post(_, _, _))
        .Times(2) // Should be called twice (initial + after expiration)
        .WillOnce(Invoke(
            [this, signedUrl1](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // First exchange - expires in 1 second
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedUrl1, 1));
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedUrl1, 1));
                }
            }))
        .WillOnce(Invoke(
            [this, signedUrl2](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Second exchange - new signed URL
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedUrl2, 300));
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedUrl2, 300));
                }
            }));

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    // First request
    auto result1 = provider.exchangeForSignedUrl(resourceUrl);
    EXPECT_EQ(result1, signedUrl1);

    // Wait for cache to expire
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Second request after expiration - should fetch new URL
    auto result2 = provider.exchangeForSignedUrl(resourceUrl);
    EXPECT_EQ(result2, signedUrl2);
}

/**
 * @brief Test getCachedSignedUrl returns nullopt when no cache entry
 */
TEST_F(CTISignedUrlProviderTest, GetCachedSignedUrlMiss)
{
    const std::string resourceUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);

    auto cached = provider.getCachedSignedUrl(resourceUrl);
    EXPECT_FALSE(cached.has_value());
}

/**
 * @brief Test getCachedSignedUrl returns value when cached
 */
TEST_F(CTISignedUrlProviderTest, GetCachedSignedUrlHit)
{
    const std::string resourceUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";
    const std::string signedUrl = resourceUrl + "?verify=1234567890-hmac_signature";

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);
    provider.cacheSignedUrl(resourceUrl, signedUrl, 300);

    auto cached = provider.getCachedSignedUrl(resourceUrl);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached.value(), signedUrl);
}

/**
 * @brief Test clearExpiredCacheEntries
 */
TEST_F(CTISignedUrlProviderTest, ClearExpiredCacheEntries)
{
    const std::string resourceUrl1 = "https://cti.wazuh.com/api/v1/resource1";
    const std::string resourceUrl2 = "https://cti.wazuh.com/api/v1/resource2";
    const std::string signedUrl1 = resourceUrl1 + "?verify=sig1";
    const std::string signedUrl2 = resourceUrl2 + "?verify=sig2";

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);

    // Cache two URLs with different expiration times
    provider.cacheSignedUrl(resourceUrl1, signedUrl1, 1);   // Expires in 1 second
    provider.cacheSignedUrl(resourceUrl2, signedUrl2, 300); // Expires in 5 minutes

    // Both should be cached initially
    EXPECT_TRUE(provider.getCachedSignedUrl(resourceUrl1).has_value());
    EXPECT_TRUE(provider.getCachedSignedUrl(resourceUrl2).has_value());

    // Wait for first URL to expire
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Clear expired entries
    provider.clearExpiredCacheEntries();

    // First should be gone, second should remain
    EXPECT_FALSE(provider.getCachedSignedUrl(resourceUrl1).has_value());
    EXPECT_TRUE(provider.getCachedSignedUrl(resourceUrl2).has_value());
}

/**
 * @brief Test token exchange with HTTP error
 */
TEST_F(CTISignedUrlProviderTest, TokenExchangeHttpError)
{
    const std::string resourceUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";

    EXPECT_CALL(*m_mockUrlRequest, post(_, _, _))
        .WillOnce(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Simulate HTTP error
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Unauthorized", 401, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Unauthorized", 401, "");
                }
            }));

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    EXPECT_THROW(provider.exchangeForSignedUrl(resourceUrl), std::runtime_error);
}

/**
 * @brief Test token exchange with invalid JSON response
 */
TEST_F(CTISignedUrlProviderTest, TokenExchangeInvalidJson)
{
    const std::string resourceUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";

    EXPECT_CALL(*m_mockUrlRequest, post(_, _, _))
        .WillOnce(Invoke(
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

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    EXPECT_THROW(provider.exchangeForSignedUrl(resourceUrl), std::runtime_error);
}

/**
 * @brief Test token exchange with missing fields in response
 */
TEST_F(CTISignedUrlProviderTest, TokenExchangeMissingFields)
{
    const std::string resourceUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";

    EXPECT_CALL(*m_mockUrlRequest, post(_, _, _))
        .WillOnce(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Return JSON missing required fields
                nlohmann::json response;
                response["issued_token_type"] = "urn:wazuh:params:oauth:token-type:signed_url";
                // Missing access_token and expires_in

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    EXPECT_THROW(provider.exchangeForSignedUrl(resourceUrl), std::runtime_error);
}

/**
 * @brief Test configuration validation - missing tokenExchange section
 */
TEST_F(CTISignedUrlProviderTest, ConfigValidationMissingTokenExchange)
{
    nlohmann::json badConfig = R"({})"_json;

    EXPECT_THROW(CTISignedUrlProvider provider(*m_mockUrlRequest, badConfig), std::runtime_error);
}

/**
 * @brief Test configuration validation - missing consoleUrl
 */
TEST_F(CTISignedUrlProviderTest, ConfigValidationMissingConsoleUrl)
{
    nlohmann::json badConfig = R"({
        "tokenExchange": {
            "tokenEndpoint": "/api/v1/instances/token/exchange"
        }
    })"_json;

    EXPECT_THROW(CTISignedUrlProvider provider(*m_mockUrlRequest, badConfig), std::runtime_error);
}

/**
 * @brief Test caching disabled configuration
 */
TEST_F(CTISignedUrlProviderTest, CachingDisabled)
{
    m_config["tokenExchange"]["cacheSignedUrls"] = false;

    const std::string resourceUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";
    const std::string signedUrl = resourceUrl + "?verify=1234567890-hmac_signature";

    EXPECT_CALL(*m_mockUrlRequest, post(_, _, _))
        .Times(2) // Should be called twice (no caching)
        .WillRepeatedly(Invoke(
            [this, signedUrl](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedUrl));
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedUrl));
                }
            }));

    CTISignedUrlProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    // Both requests should perform token exchange (no caching)
    auto result1 = provider.exchangeForSignedUrl(resourceUrl);
    EXPECT_EQ(result1, signedUrl);

    auto result2 = provider.exchangeForSignedUrl(resourceUrl);
    EXPECT_EQ(result2, signedUrl);
}
