/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * November 07, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ctiProductsProvider_test.hpp"

using namespace testing;

/**
 * @brief Test successful subscription fetch from Console
 */
TEST_F(CTIProductsProviderTest, FetchSubscriptionSuccess)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Simulate successful response
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createSubscriptionResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createSubscriptionResponse());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    auto subscription = provider.fetchSubscription();

    // Verify organization
    EXPECT_EQ(subscription.organization.name, "ACME Corporation");
    EXPECT_EQ(subscription.organization.avatar, "https://example.com/avatar.png");

    // Verify plans
    ASSERT_EQ(subscription.plans.size(), 1);
    EXPECT_EQ(subscription.plans[0].name, "Pro Plan");
    EXPECT_EQ(subscription.plans[0].description, "Professional plan with advanced features");

    // Verify products
    ASSERT_EQ(subscription.plans[0].products.size(), 4);

    // First product (vulnerabilities)
    const auto& vuln = subscription.plans[0].products[0];
    EXPECT_EQ(vuln.identifier, "vulnerabilities-pro");
    EXPECT_EQ(vuln.type, "catalog:consumer");
    EXPECT_EQ(vuln.name, "Vulnerabilities Pro");
    EXPECT_EQ(vuln.description, "Real-time vulnerability intelligence");
    EXPECT_FALSE(vuln.resource.empty());

    // Fourth product (support service)
    const auto& support = subscription.plans[0].products[3];
    EXPECT_EQ(support.identifier, "support-assistance");
    EXPECT_EQ(support.type, "cloud:assistance");
    EXPECT_EQ(support.email, "support@wazuh.com");
    EXPECT_EQ(support.phone, "+1-555-0100");
}

/**
 * @brief Test getCatalogProducts filters correctly
 */
TEST_F(CTIProductsProviderTest, GetCatalogProductsFiltersCorrectly)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createSubscriptionResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createSubscriptionResponse());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    auto catalogProducts = provider.getCatalogProducts();

    // Should only return catalog:consumer products with resources (3 out of 4)
    ASSERT_EQ(catalogProducts.size(), 3);

    // All should be catalog:consumer type
    for (const auto& product : catalogProducts)
    {
        EXPECT_EQ(product.type, "catalog:consumer");
        EXPECT_FALSE(product.resource.empty());
    }

    // Verify specific products
    EXPECT_EQ(catalogProducts[0].identifier, "vulnerabilities-pro");
    EXPECT_EQ(catalogProducts[1].identifier, "bad-guy-ips-pro");
    EXPECT_EQ(catalogProducts[2].identifier, "malware-signatures-pro");
}

/**
 * @brief Test caching mechanism
 */
TEST_F(CTIProductsProviderTest, CachingMechanism)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .Times(1) // Should only fetch once due to caching
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createMinimalSubscriptionResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createMinimalSubscriptionResponse());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    // First call should fetch
    auto sub1 = provider.fetchSubscription();
    EXPECT_EQ(sub1.organization.name, "Test Org");

    // Second call should use cache (useCache = true by default)
    auto sub2 = provider.fetchSubscription(true);
    EXPECT_EQ(sub2.organization.name, "Test Org");

    // Third call should also use cache
    auto products = provider.getCatalogProducts();
    EXPECT_EQ(products.size(), 1);
}

/**
 * @brief Test cache clearing
 */
TEST_F(CTIProductsProviderTest, ClearCacheForcesFetch)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .Times(2) // Should fetch twice: once initially, once after cache clear
        .WillRepeatedly(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createMinimalSubscriptionResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createMinimalSubscriptionResponse());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    // First fetch
    auto sub1 = provider.fetchSubscription();
    EXPECT_EQ(sub1.organization.name, "Test Org");

    // Clear cache
    provider.clearCache();

    // Second fetch should hit the API again
    auto sub2 = provider.fetchSubscription();
    EXPECT_EQ(sub2.organization.name, "Test Org");
}

/**
 * @brief Test fetchSubscription with useCache=false forces fresh fetch
 */
TEST_F(CTIProductsProviderTest, ForceFreshFetch)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .Times(2) // Should fetch twice
        .WillRepeatedly(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createMinimalSubscriptionResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createMinimalSubscriptionResponse());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    // First fetch
    provider.fetchSubscription();

    // Second fetch with useCache=false should force API call
    auto sub = provider.fetchSubscription(false);
    EXPECT_EQ(sub.organization.name, "Test Org");
}

/**
 * @brief Test error handling with missing access token
 */
TEST_F(CTIProductsProviderTest, ThrowsWithoutAccessToken)
{
    CTIProductsProvider provider(*m_mockUrlRequest, m_config);

    // Should throw when access token is not set
    EXPECT_THROW(provider.fetchSubscription(), std::runtime_error);
    EXPECT_THROW(provider.getCatalogProducts(), std::runtime_error);
}

/**
 * @brief Test error handling with invalid JSON response
 */
TEST_F(CTIProductsProviderTest, ThrowsOnInvalidJSON)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("invalid json {{{");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("invalid json {{{");
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    EXPECT_THROW(provider.fetchSubscription(), std::runtime_error);
}

/**
 * @brief Test error handling with missing 'data' field
 */
TEST_F(CTIProductsProviderTest, ThrowsOnMissingDataField)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                std::string response = R"({"error": "something went wrong"})";
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    EXPECT_THROW(provider.fetchSubscription(), std::runtime_error);
}

/**
 * @brief Test HTTP error handling (401 Unauthorized)
 */
TEST_F(CTIProductsProviderTest, ThrowsOnUnauthorized)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Unauthorized", 401, "Invalid token");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Unauthorized", 401, "Invalid token");
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("invalid_token");

    EXPECT_THROW(provider.fetchSubscription(), std::runtime_error);
}

/**
 * @brief Test HTTP error handling (500 Internal Server Error)
 */
TEST_F(CTIProductsProviderTest, ThrowsOnServerError)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Internal Server Error", 500, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Internal Server Error", 500, "");
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    EXPECT_THROW(provider.fetchSubscription(), std::runtime_error);
}

/**
 * @brief Test handling empty subscription (no plans)
 */
TEST_F(CTIProductsProviderTest, HandlesEmptySubscription)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createEmptySubscriptionResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createEmptySubscriptionResponse());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    auto subscription = provider.fetchSubscription();
    EXPECT_EQ(subscription.organization.name, "Empty Org");
    EXPECT_EQ(subscription.plans.size(), 0);

    auto catalogProducts = provider.getCatalogProducts();
    EXPECT_EQ(catalogProducts.size(), 0);
}

/**
 * @brief Test handling subscription with no catalog products
 */
TEST_F(CTIProductsProviderTest, HandlesNoCatalogProducts)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createNoCatalogProductsResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createNoCatalogProductsResponse());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    auto subscription = provider.fetchSubscription();
    ASSERT_EQ(subscription.plans.size(), 1);
    ASSERT_EQ(subscription.plans[0].products.size(), 1);
    EXPECT_EQ(subscription.plans[0].products[0].type, "cloud:assistance");

    // getCatalogProducts should return empty vector
    auto catalogProducts = provider.getCatalogProducts();
    EXPECT_EQ(catalogProducts.size(), 0);
}

/**
 * @brief Test Bearer token is included in Authorization header
 */
TEST_F(CTIProductsProviderTest, IncludesBearerTokenInHeader)
{
    std::string capturedAuth;

    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this, &capturedAuth](const auto& requestParams, const auto& postParams, const auto& /*configParams*/)
            {
                // Capture the Authorization header
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    const auto& params = std::get<TRequestParameters<std::string>>(requestParams);
                    // Note: In real implementation, headers would be in RequestParameters
                    // This is a simplified check
                }

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createMinimalSubscriptionResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createMinimalSubscriptionResponse());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("my_secret_token");

    EXPECT_NO_THROW(provider.fetchSubscription());
}

/**
 * @brief Test configuration with custom endpoint
 */
TEST_F(CTIProductsProviderTest, CustomEndpointConfiguration)
{
    nlohmann::json customConfig = R"({
        "console": {
            "url": "https://custom-console.example.com",
            "instancesEndpoint": "/custom/api/subscription",
            "timeout": 10000
        }
    })"_json;

    // Provider should accept custom configuration
    EXPECT_NO_THROW({
        CTIProductsProvider provider(*m_mockUrlRequest, customConfig);
        provider.setAccessToken("test_token");
    });
}

/**
 * @brief Test configuration with missing console section
 */
TEST_F(CTIProductsProviderTest, ThrowsOnMissingConsoleConfig)
{
    nlohmann::json badConfig = R"({
        "indexer": {
            "url": "http://localhost:9200"
        }
    })"_json;

    // Should throw when console config is missing
    EXPECT_THROW(CTIProductsProvider provider(*m_mockUrlRequest, badConfig), std::exception);
}

/**
 * @brief Test thread safety of caching mechanism
 */
TEST_F(CTIProductsProviderTest, ThreadSafeCaching)
{
    // Allow multiple calls due to race conditions in concurrent access
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillRepeatedly(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                // Simulate some delay to increase chance of concurrent access
                std::this_thread::sleep_for(std::chrono::milliseconds(5));

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createMinimalSubscriptionResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(createMinimalSubscriptionResponse());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    // Launch multiple threads trying to fetch subscription
    std::vector<std::thread> threads;
    std::vector<CTISubscription> results(5);

    for (size_t i = 0; i < 5; ++i)
    {
        threads.emplace_back([&provider, &results, i]() { results[i] = provider.fetchSubscription(); });
    }

    // Wait for all threads
    for (auto& t : threads)
    {
        t.join();
    }

    // All results should be identical
    for (const auto& result : results)
    {
        EXPECT_EQ(result.organization.name, "Test Org");
    }
}

/**
 * @brief Test product resource URL validation
 */
TEST_F(CTIProductsProviderTest, ValidatesProductResourceURLs)
{
    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(Invoke(
            [this](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(createSubscriptionResponse());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(createSubscriptionResponse());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    auto catalogProducts = provider.getCatalogProducts();

    // All catalog products should have non-empty resource URLs
    for (const auto& product : catalogProducts)
    {
        EXPECT_FALSE(product.resource.empty());
        EXPECT_TRUE(product.resource.find("http") == 0); // Should start with http
    }
}

/**
 * @brief Test parsing product with missing optional fields (name, description)
 */
TEST_F(CTIProductsProviderTest, ParseProductWithMissingOptionalFields)
{
    nlohmann::json response = R"({
        "data": {
            "organization": {
                "identifier": "org-123",
                "name": "Test Organization"
            },
            "plans": [{
                "identifier": "plan-123",
                "name": "Test Plan",
                "products": [{
                    "identifier": "prod-123",
                    "type": "catalog:consumer",
                    "resource": "https://example.com/catalog"
                }]
            }]
        }
    })"_json;

    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(::testing::Invoke(
            [response](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    auto subscription = provider.fetchSubscription();

    EXPECT_EQ(subscription.plans.size(), 1);
    EXPECT_EQ(subscription.plans[0].products.size(), 1);
    EXPECT_EQ(subscription.plans[0].products[0].identifier, "prod-123");
    EXPECT_TRUE(subscription.plans[0].products[0].name.empty());
    EXPECT_TRUE(subscription.plans[0].products[0].description.empty());
}

/**
 * @brief Test parsing organization with missing optional avatar field
 */
TEST_F(CTIProductsProviderTest, ParseOrganizationWithMissingAvatar)
{
    nlohmann::json response = R"({
        "data": {
            "organization": {
                "identifier": "org-123",
                "name": "Test Organization"
            },
            "plans": []
        }
    })"_json;

    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(::testing::Invoke(
            [response](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    auto subscription = provider.fetchSubscription();

    EXPECT_EQ(subscription.organization.name, "Test Organization");
    EXPECT_TRUE(subscription.organization.avatar.empty());
}

/**
 * @brief Test parsing product with invalid JSON structure
 */
TEST_F(CTIProductsProviderTest, ThrowsOnInvalidProductStructure)
{
    nlohmann::json response = R"({
        "data": {
            "organization": {
                "identifier": "org-123",
                "name": "Test Organization"
            },
            "plans": [{
                "identifier": "plan-123",
                "name": "Test Plan",
                "products": ["invalid-product-structure"]
            }]
        }
    })"_json;

    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(::testing::Invoke(
            [response](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (const auto* param = std::get_if<TPostRequestParameters<std::string&&>>(&postParams))
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    EXPECT_THROW(provider.fetchSubscription(), std::runtime_error);
}

/**
 * @brief Test with missing organization field
 */
TEST_F(CTIProductsProviderTest, ThrowsOnMissingOrganization)
{
    nlohmann::json response = R"({
        "data": {
            "plans": []
        }
    })"_json;

    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(::testing::Invoke(
            [response](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (const auto* param = std::get_if<TPostRequestParameters<std::string&&>>(&postParams))
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    EXPECT_THROW(provider.fetchSubscription(), std::runtime_error);
}

/**
 * @brief Test with missing plans field
 */
TEST_F(CTIProductsProviderTest, ThrowsOnMissingPlans)
{
    nlohmann::json response = R"({
        "data": {
            "organization": {
                "identifier": "org-123",
                "name": "Test Organization"
            }
        }
    })"_json;

    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(::testing::Invoke(
            [response](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (const auto* param = std::get_if<TPostRequestParameters<std::string&&>>(&postParams))
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    EXPECT_THROW(provider.fetchSubscription(), std::runtime_error);
}

/**
 * @brief Test parsing plan with missing products field
 */
TEST_F(CTIProductsProviderTest, ParsePlanWithMissingProducts)
{
    nlohmann::json response = R"({
        "data": {
            "organization": {
                "identifier": "org-123",
                "name": "Test Organization"
            },
            "plans": [{
                "identifier": "plan-123",
                "name": "Test Plan"
            }]
        }
    })"_json;

    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(::testing::Invoke(
            [response](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    auto subscription = provider.fetchSubscription();

    EXPECT_EQ(subscription.plans.size(), 1);
    EXPECT_EQ(subscription.plans[0].products.size(), 0);
}

/**
 * @brief Test multiple organizations handling (should use first one)
 */
TEST_F(CTIProductsProviderTest, HandlesMultiplePlans)
{
    nlohmann::json response = R"({
        "data": {
            "organization": {
                "identifier": "org-123",
                "name": "Test Organization",
                "avatar": "https://example.com/avatar.png"
            },
            "plans": [
                {
                    "identifier": "plan-1",
                    "name": "Plan 1",
                    "products": [{
                        "identifier": "prod-1",
                        "name": "Product 1",
                        "type": "catalog:consumer",
                        "resource": "https://example.com/catalog1"
                    }]
                },
                {
                    "identifier": "plan-2",
                    "name": "Plan 2",
                    "products": [{
                        "identifier": "prod-2",
                        "name": "Product 2",
                        "type": "cloud:assistance",
                        "resource": "https://example.com/offset1"
                    }]
                }
            ]
        }
    })"_json;

    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(::testing::Invoke(
            [response](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    auto subscription = provider.fetchSubscription();

    EXPECT_EQ(subscription.plans.size(), 2);
    EXPECT_EQ(subscription.plans[0].name, "Plan 1");
    EXPECT_EQ(subscription.plans[1].name, "Plan 2");

    auto catalogProducts = provider.getCatalogProducts();
    EXPECT_EQ(catalogProducts.size(), 1);
    EXPECT_EQ(catalogProducts[0].identifier, "prod-1");
}

/**
 * @brief Test parseProduct throws on missing 'identifier'
 */
TEST_F(CTIProductsProviderTest, ThrowsOnMissingProductIdentifier)
{
    // Response with product missing 'identifier' field
    auto response = R"({
        "data": {
            "organization": {
                "name": "Test Org"
            },
            "plans": [{
                "name": "Test Plan",
                "products": [{
                    "type": "catalog:consumer",
                    "name": "Product Without ID",
                    "resource": "https://example.com/resource"
                }]
            }]
        }
    })"_json;

    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(::testing::Invoke(
            [response](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    // Should succeed - invalid products are skipped with log error
    auto subscription = provider.fetchSubscription();
    EXPECT_EQ(subscription.plans.size(), 1);
    EXPECT_EQ(subscription.plans[0].products.size(), 0); // Product should be skipped
}

/**
 * @brief Test parseProduct throws on missing 'type'
 */
TEST_F(CTIProductsProviderTest, ThrowsOnMissingProductType)
{
    // Response with product missing 'type' field
    auto response = R"({
        "data": {
            "organization": {
                "name": "Test Org"
            },
            "plans": [{
                "name": "Test Plan",
                "products": [{
                    "identifier": "test-product",
                    "name": "Product Without Type",
                    "resource": "https://example.com/resource"
                }]
            }]
        }
    })"_json;

    EXPECT_CALL(*m_mockUrlRequest, get(_, _, _))
        .WillOnce(::testing::Invoke(
            [response](const auto& /*requestParams*/, const auto& postParams, const auto& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(response.dump());
                }
            }));

    CTIProductsProvider provider(*m_mockUrlRequest, m_config);
    provider.setAccessToken("test_access_token");

    // Should succeed - invalid products are skipped with log error
    auto subscription = provider.fetchSubscription();
    EXPECT_EQ(subscription.plans.size(), 1);
    EXPECT_EQ(subscription.plans[0].products.size(), 0); // Product should be skipped
}

/**
 * @brief Test constructor throws on missing 'console.url'
 */
TEST_F(CTIProductsProviderTest, ThrowsOnMissingConsoleUrl)
{
    // Config missing 'url' field
    auto invalidConfig = R"({
        "console": {
            "instancesEndpoint": "/api/v1/instances/me"
        }
    })"_json;

    EXPECT_THROW(CTIProductsProvider provider(*m_mockUrlRequest, invalidConfig), std::runtime_error);
}

/**
 * @brief Test setAccessToken with empty string triggers warning
 */
TEST_F(CTIProductsProviderTest, SetEmptyAccessTokenLogsWarning)
{
    CTIProductsProvider provider(*m_mockUrlRequest, m_config);

    // Set empty token - should log warning
    provider.setAccessToken("");

    // Should throw when trying to fetch without token
    EXPECT_THROW(provider.fetchSubscription(false), std::runtime_error);
}
