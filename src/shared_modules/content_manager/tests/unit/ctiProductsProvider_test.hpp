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

#ifndef _CTI_PRODUCTS_PROVIDER_TEST_HPP
#define _CTI_PRODUCTS_PROVIDER_TEST_HPP

#include "HTTPRequest.hpp"
#include "ctiProductsProvider.hpp"
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
class MockURLRequestProducts : public IURLRequest
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
 * @brief Runs unit tests for CTIProductsProvider
 */
class CTIProductsProviderTest : public ::testing::Test
{
protected:
    CTIProductsProviderTest() = default;
    ~CTIProductsProviderTest() override = default;

    std::unique_ptr<MockURLRequestProducts> m_mockUrlRequest;
    nlohmann::json m_config;

    /**
     * @brief Sets initial conditions for each test case.
     */
    void SetUp() override
    {
        m_mockUrlRequest = std::make_unique<MockURLRequestProducts>();

        // Default configuration
        m_config = R"({
            "console": {
                "url": "http://localhost:8080",
                "instancesEndpoint": "/api/v1/instances/me",
                "timeout": 5000,
                "productType": "catalog:consumer"
            }
        })"_json;
    }

    /**
     * @brief Clean up after each test case.
     */
    void TearDown() override
    {
        m_mockUrlRequest.reset();
    }

    /**
     * @brief Helper: Create a valid subscription response with multiple products
     */
    std::string createSubscriptionResponse()
    {
        return R"({
            "data": {
                "organization": {
                    "name": "ACME Corporation",
                    "avatar": "https://example.com/avatar.png"
                },
                "plans": [
                    {
                        "name": "Pro Plan",
                        "description": "Professional plan with advanced features",
                        "products": [
                            {
                                "identifier": "vulnerabilities-pro",
                                "type": "catalog:consumer",
                                "name": "Vulnerabilities Pro",
                                "description": "Real-time vulnerability intelligence",
                                "resource": "https://cti.wazuh.com/api/v1/catalog/plans/pro/contexts/vulnerabilities/consumer/realtime"
                            },
                            {
                                "identifier": "bad-guy-ips-pro",
                                "type": "catalog:consumer",
                                "name": "Bad Guy IPs Pro",
                                "description": "Malicious IP addresses database",
                                "resource": "https://cti.wazuh.com/api/v1/catalog/plans/pro/contexts/bad-guy-ips/consumer/realtime"
                            },
                            {
                                "identifier": "malware-signatures-pro",
                                "type": "catalog:consumer",
                                "name": "Malware Signatures Pro",
                                "description": "Malware signatures and hashes",
                                "resource": "https://cti.wazuh.com/api/v1/catalog/plans/pro/contexts/malware/consumer/realtime"
                            },
                            {
                                "identifier": "support-assistance",
                                "type": "cloud:assistance",
                                "name": "24/7 Support",
                                "description": "Round-the-clock technical support",
                                "email": "support@wazuh.com",
                                "phone": "+1-555-0100"
                            }
                        ]
                    }
                ]
            }
        })";
    }

    /**
     * @brief Helper: Create a minimal subscription response with one product
     */
    std::string createMinimalSubscriptionResponse()
    {
        return R"({
            "data": {
                "organization": {
                    "name": "Test Org",
                    "avatar": ""
                },
                "plans": [
                    {
                        "name": "Basic Plan",
                        "description": "Basic features",
                        "products": [
                            {
                                "identifier": "test-product",
                                "type": "catalog:consumer",
                                "name": "Test Product",
                                "description": "Test description",
                                "resource": "https://test.com/resource"
                            }
                        ]
                    }
                ]
            }
        })";
    }

    /**
     * @brief Helper: Create subscription with no catalog products
     */
    std::string createNoCatalogProductsResponse()
    {
        return R"({
            "data": {
                "organization": {
                    "name": "Service Only Org",
                    "avatar": ""
                },
                "plans": [
                    {
                        "name": "Service Plan",
                        "description": "Services only",
                        "products": [
                            {
                                "identifier": "support-only",
                                "type": "cloud:assistance",
                                "name": "Support",
                                "description": "Support service",
                                "email": "support@example.com"
                            }
                        ]
                    }
                ]
            }
        })";
    }

    /**
     * @brief Helper: Create empty subscription response
     */
    std::string createEmptySubscriptionResponse()
    {
        return R"({
            "data": {
                "organization": {
                    "name": "Empty Org",
                    "avatar": ""
                },
                "plans": []
            }
        })";
    }

    /**
     * @brief Helper: Create subscription with specific product types (e.g., catalog:consumer:decoders)
     */
    std::string createSpecificProductTypeResponse()
    {
        return R"({
            "data": {
                "organization": {
                    "name": "ACME S.L.",
                    "avatar": "https://acme.sl/avatar.png"
                },
                "plans": [
                    {
                        "name": "Pro Plan Deluxe",
                        "description": "...",
                        "products": [
                            {
                                "identifier": "vulnerabilities-pro",
                                "type": "catalog:consumer:decoders",
                                "name": "Vulnerabilities Pro",
                                "description": "...",
                                "resource": "https://cti.wazuh.com/api/v1/catalog/plans/pro/contexts/vulnerabilities/consumer/realtime"
                            },
                            {
                                "identifier": "malware-sigs",
                                "type": "catalog:consumer:rules",
                                "name": "Malware Signatures",
                                "description": "...",
                                "resource": "https://cti.wazuh.com/api/v1/catalog/plans/pro/contexts/malware/consumer/realtime"
                            },
                            {
                                "identifier": "support-service",
                                "type": "cloud:assistance",
                                "name": "Support",
                                "description": "...",
                                "email": "support@wazuh.com"
                            }
                        ]
                    }
                ]
            }
        })";
    }
};

#endif // _CTI_PRODUCTS_PROVIDER_TEST_HPP
