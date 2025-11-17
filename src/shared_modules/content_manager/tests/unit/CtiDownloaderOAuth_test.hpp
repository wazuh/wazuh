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

#ifndef _CTI_DOWNLOADER_OAUTH_TEST_HPP
#define _CTI_DOWNLOADER_OAUTH_TEST_HPP

#include "CtiOffsetDownloader.hpp"
#include "CtiSnapshotDownloader.hpp"
#include "HTTPRequest.hpp"
#include "conditionSync.hpp"
#include "ctiCredentialsProvider.hpp"
#include "ctiSignedUrlProvider.hpp"
#include "updaterContext.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <memory>

using namespace testing;

// Type aliases for mock method parameters
using RequestParamsVariant = std::
    variant<TRequestParameters<std::string>, TRequestParameters<nlohmann::json>, TRequestParameters<std::string_view>>;
using PostRequestParamsVariant =
    std::variant<TPostRequestParameters<const std::string&>, TPostRequestParameters<std::string&&>>;

/**
 * @brief Mock class for IURLRequest interface used in OAuth integration tests.
 */
class MockURLRequestOAuth : public IURLRequest
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
 * @brief Runs integration tests for CtiDownloader with OAuth providers
 */
class CtiDownloaderOAuthTest : public ::testing::Test
{
protected:
    CtiDownloaderOAuthTest() = default;
    ~CtiDownloaderOAuthTest() override = default;

    std::unique_ptr<MockURLRequestOAuth> m_mockUrlRequest;
    std::shared_ptr<UpdaterContext> m_spUpdaterContext;
    std::shared_ptr<UpdaterBaseContext> m_spUpdaterBaseContext;
    std::shared_ptr<ConditionSync> m_spStopActionCondition;

    // OAuth providers
    std::shared_ptr<CTICredentialsProvider> m_credentialsProvider;
    std::shared_ptr<CTIProductsProvider> m_productsProvider;
    std::shared_ptr<CTISignedUrlProvider> m_signedUrlProvider;

    nlohmann::json m_oauthConfig;

    /**
     * @brief Sets initial conditions for each test case.
     */
    void SetUp() override
    {
        m_mockUrlRequest = std::make_unique<MockURLRequestOAuth>();
        m_spStopActionCondition = std::make_shared<ConditionSync>(false);

        // OAuth configuration
        m_oauthConfig = R"({
            "indexer": {
                "url": "http://localhost:9200",
                "credentialsEndpoint": "/_plugins/content-manager/subscription",
                "pollInterval": 60,
                "timeout": 5000,
                "retryAttempts": 3
            },
            "console": {
                "url": "https://console.wazuh.com",
                "instancesEndpoint": "/api/v1/instances/me",
                "timeout": 5000,
                "productType": "catalog:consumer"
            },
            "tokenExchange": {
                "enabled": true,
                "consoleUrl": "https://console.wazuh.com",
                "tokenEndpoint": "/api/v1/instances/token/exchange",
                "cacheSignedUrls": true,
                "signedUrlLifetime": 300
            }
        })"_json;

        // Create updater base context
        m_spUpdaterBaseContext =
            std::make_shared<UpdaterBaseContext>(m_spStopActionCondition,
                                                 [](const std::string& msg) -> FileProcessingResult {
                                                     return {0, "", false};
                                                 });
        m_spUpdaterBaseContext->outputFolder = "/tmp/cti-oauth-tests";
        m_spUpdaterBaseContext->downloadsFolder = m_spUpdaterBaseContext->outputFolder / DOWNLOAD_FOLDER;
        m_spUpdaterBaseContext->contentsFolder = m_spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER;
        m_spUpdaterBaseContext->configData = R"(
            {
                "contentSource": "cti-offset",
                "compressionType": "raw",
                "versionedContent": "false",
                "deleteDownloadedContent": false,
                "url": "https://cti.wazuh.com/api/v1/catalog/contexts/vd_1.0.0/consumers/vd_5.0.0",
                "outputFolder": "/tmp/cti-oauth-tests",
                "contentFileName": "sample.json"
            }
        )"_json;

        // Create updater context
        m_spUpdaterContext = std::make_shared<UpdaterContext>();
        m_spUpdaterContext->spUpdaterBaseContext = m_spUpdaterBaseContext;
        m_spUpdaterContext->currentOffset = 0;

        // Create folders
        std::filesystem::create_directories(m_spUpdaterBaseContext->downloadsFolder);
        std::filesystem::create_directories(m_spUpdaterBaseContext->contentsFolder);
    }

    /**
     * @brief Tear down routine for tests
     */
    void TearDown() override
    {
        m_mockUrlRequest.reset();
        m_credentialsProvider.reset();
        m_productsProvider.reset();
        m_signedUrlProvider.reset();

        // Cleanup test folders
        std::filesystem::remove_all(m_spUpdaterBaseContext->outputFolder);
    }

    /**
     * @brief Helper to create OAuth providers with mocked HTTP requests
     */
    void createOAuthProviders()
    {
        m_credentialsProvider = std::make_shared<CTICredentialsProvider>(*m_mockUrlRequest, m_oauthConfig);
        m_productsProvider = std::make_shared<CTIProductsProvider>(*m_mockUrlRequest, m_oauthConfig);
        m_signedUrlProvider = std::make_shared<CTISignedUrlProvider>(*m_mockUrlRequest, m_oauthConfig);
    }

    /**
     * @brief Helper to create valid credentials JSON response
     */
    std::string createCredentialsResponse()
    {
        nlohmann::json response;
        response["access_token"] = "test_access_token_123";
        response["token_type"] = "Bearer";
        return response.dump();
    }

    /**
     * @brief Helper to create subscription response with products
     */
    std::string createSubscriptionResponse(const std::string& resourceUrl)
    {
        nlohmann::json response;
        response["data"]["organization"]["identifier"] = "org-test";
        response["data"]["organization"]["name"] = "Test Org";
        response["data"]["plans"] = nlohmann::json::array();

        nlohmann::json plan;
        plan["identifier"] = "plan-test";
        plan["name"] = "Test Plan";
        plan["products"] = nlohmann::json::array();

        nlohmann::json product;
        product["identifier"] = "test-product";
        product["type"] = "catalog:consumer";
        product["name"] = "Test Product";
        product["resource"] = resourceUrl;

        plan["products"].push_back(product);
        response["data"]["plans"].push_back(plan);

        return response.dump();
    }

    /**
     * @brief Helper to create valid token exchange response
     */
    std::string createTokenExchangeResponse(const std::string& signedUrl, uint64_t expiresIn = 300)
    {
        nlohmann::json response;
        response["access_token"] = signedUrl;
        response["issued_token_type"] = "urn:wazuh:params:oauth:token-type:signed_url";
        response["expires_in"] = expiresIn;
        return response.dump();
    }

    /**
     * @brief Helper to create CTI metadata response
     */
    std::string createMetadataResponse(int lastOffset = 1000)
    {
        nlohmann::json response;
        response["data"]["last_offset"] = lastOffset;
        response["data"]["last_snapshot_link"] = "https://cti.wazuh.com/snapshots/latest.tar.gz";
        response["data"]["last_snapshot_offset"] = lastOffset;
        return response.dump();
    }
};

#endif //_CTI_DOWNLOADER_OAUTH_TEST_HPP
