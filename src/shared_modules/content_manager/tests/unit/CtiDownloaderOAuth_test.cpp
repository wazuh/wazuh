/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * November 05, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "CtiDownloaderOAuth_test.hpp"

using namespace testing;

/**
 * @brief Test backward compatibility - CtiOffsetDownloader without OAuth providers
 *
 * Verifies that the downloader works as before when no providers are passed.
 */
TEST_F(CtiDownloaderOAuthTest, BackwardCompatibility_NoProviders)
{
    // Create downloader WITHOUT OAuth providers (backward compatibility)
    auto downloader = std::make_shared<CtiOffsetDownloader>(*m_mockUrlRequest);

    // Setup mock expectations for metadata request (original URL, no OAuth)
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this](const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                // Verify it's using the original URL (not transformed)
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    const auto& params = std::get<TRequestParameters<std::string>>(requestParams);
                    EXPECT_EQ(params.url.url(),
                              "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0");
                }

                // Return metadata
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createMetadataResponse(10));
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createMetadataResponse(10));
                }
            }))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Return offset content
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("{}");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("{}");
                }
            }));

    // Execute download - should work without OAuth
    EXPECT_NO_THROW(downloader->handleRequest(m_spUpdaterContext));
}

/**
 * @brief Test OAuth integration - URL transformation to signed URL
 *
 * Verifies that when OAuth providers are configured, URLs are transformed to signed URLs.
 */
TEST_F(CtiDownloaderOAuthTest, OAuth_URLTransformation)
{
    createOAuthProviders();

    // Create downloader WITH OAuth providers
    auto downloader =
        std::make_shared<CtiOffsetDownloader>(*m_mockUrlRequest, m_credentialsProvider, m_signedUrlProvider);

    const std::string originalUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";
    const std::string signedUrl = originalUrl + "?verify=hmac_signature_12345";

    // Setup mock expectations

    // 1. Credentials request
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this](const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                // Verify credentials endpoint
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    const auto& params = std::get<TRequestParameters<std::string>>(requestParams);
                    EXPECT_EQ(params.url.url(), "http://localhost:9200/_wazuh/cti/credentials");
                }

                // Return credentials
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createCredentialsResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createCredentialsResponse());
                }
            }))
        // 3. Metadata request with signed URL
        .WillOnce(Invoke(
            [this, signedUrl](const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                // Verify it's using the SIGNED URL
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    const auto& params = std::get<TRequestParameters<std::string>>(requestParams);
                    EXPECT_EQ(params.url.url(), signedUrl);
                }

                // Return metadata
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createMetadataResponse(10));
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createMetadataResponse(10));
                }
            }))
        // 4. Offset content request with signed URL
        .WillOnce(Invoke(
            [this, signedUrl](const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                // Verify it's using the SIGNED URL
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    const auto& params = std::get<TRequestParameters<std::string>>(requestParams);
                    // Should have query parameters appended to signed URL
                    EXPECT_TRUE(params.url.url().find(signedUrl) == 0);
                }

                // Return offset content
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("{}");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("{}");
                }
            }));

    // 2. Token exchange request
    EXPECT_CALL(*m_mockUrlRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, originalUrl, signedUrl](
                const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                // Verify token exchange endpoint
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    const auto& params = std::get<TRequestParameters<std::string>>(requestParams);
                    EXPECT_EQ(params.url.url(), "https://console.wazuh.com/api/v1/instances/token/exchange");

                    // Verify request body contains the resource URL
                    auto body = nlohmann::json::parse(params.data);
                    std::string resourceUrl = body["resource"];
                    EXPECT_EQ(resourceUrl, originalUrl);
                }

                // Return signed URL
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

    // Execute download - should use signed URLs
    EXPECT_NO_THROW(downloader->handleRequest(m_spUpdaterContext));
}

/**
 * @brief Test OAuth authentication failure handling
 *
 * Verifies that authentication failures are properly propagated.
 */
TEST_F(CtiDownloaderOAuthTest, OAuth_AuthenticationFailure)
{
    createOAuthProviders();

    auto downloader =
        std::make_shared<CtiOffsetDownloader>(*m_mockUrlRequest, m_credentialsProvider, m_signedUrlProvider);

    // Setup mock to fail credentials request (with retries - up to 3 attempts)
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .Times(AtLeast(1)) // Allow retries
        .WillRepeatedly(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Return error
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Unauthorized", 401, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Unauthorized", 401, "");
                }
            }));

    // Execute download - should propagate authentication error
    EXPECT_THROW(downloader->handleRequest(m_spUpdaterContext), std::runtime_error);
}

/**
 * @brief Test successful OAuth flow with basic verification
 *
 * Verifies that the OAuth providers work end-to-end.
 */
TEST_F(CtiDownloaderOAuthTest, OAuth_SignedUrlCaching)
{
    createOAuthProviders();

    auto downloader =
        std::make_shared<CtiOffsetDownloader>(*m_mockUrlRequest, m_credentialsProvider, m_signedUrlProvider);

    const std::string originalUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";
    const std::string signedUrl = originalUrl + "?verify=hmac_signature_cached";

    // Setup mock expectations
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Credentials request
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createCredentialsResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createCredentialsResponse());
                }
            }))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Metadata request
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createMetadataResponse(5));
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createMetadataResponse(5));
                }
            }))
        .WillRepeatedly(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Offset content requests
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("{}");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("{}");
                }
            }));

    EXPECT_CALL(*m_mockUrlRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, signedUrl](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Return signed URL
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

    // Execute download - should work with OAuth enabled
    EXPECT_NO_THROW(downloader->handleRequest(m_spUpdaterContext));
}

/**
 * @brief Test CtiSnapshotDownloader with OAuth
 *
 * Verifies that snapshot downloader also works with OAuth providers.
 */
TEST_F(CtiDownloaderOAuthTest, OAuth_SnapshotDownloader)
{
    createOAuthProviders();

    auto downloader =
        std::make_shared<CtiSnapshotDownloader>(*m_mockUrlRequest, m_credentialsProvider, m_signedUrlProvider);

    const std::string originalUrl = "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0";
    const std::string snapshotUrl = "https://cti.wazuh.com/snapshots/latest.tar.gz";
    const std::string signedSnapshotUrl = snapshotUrl + "?verify=hmac_snapshot_signature";

    // Setup mock expectations
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Credentials request
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createCredentialsResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createCredentialsResponse());
                }
            }))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Metadata request
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createMetadataResponse(1000));
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createMetadataResponse(1000));
                }
            }))
        .WillOnce(Invoke(
            [this, signedSnapshotUrl](const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                // Snapshot download with signed URL
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    const auto& params = std::get<TRequestParameters<std::string>>(requestParams);
                    EXPECT_EQ(params.url.url(), signedSnapshotUrl);
                }

                // Return snapshot content
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("snapshot_content");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("snapshot_content");
                }
            }));

    EXPECT_CALL(*m_mockUrlRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this,
             signedSnapshotUrl](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Token exchange - return signed snapshot URL
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedSnapshotUrl));
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createTokenExchangeResponse(signedSnapshotUrl));
                }
            }));

    // Execute download
    EXPECT_NO_THROW(downloader->handleRequest(m_spUpdaterContext));
}
