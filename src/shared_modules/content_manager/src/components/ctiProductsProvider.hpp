/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * November 07, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CTI_PRODUCTS_PROVIDER_HPP
#define _CTI_PRODUCTS_PROVIDER_HPP

#include "IURLRequest.hpp"
#include "json.hpp"
#include "sharedDefs.hpp"
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

/**
 * @brief CTI Product information
 *
 * Represents a product/service from the CTI Console subscription.
 */
struct CTIProduct
{
    std::string identifier;  ///< Stable product identifier (e.g., "vulnerabilities-pro")
    std::string type;        ///< Product type (e.g., "catalog:consumer", "cloud:assistance")
    std::string name;        ///< Display name
    std::string description; ///< Product description
    std::string resource;    ///< Resource URL for token exchange (only for catalog products)

    // Cloud-specific fields (optional)
    std::string email; ///< Support email (for cloud:assistance)
    std::string phone; ///< Support phone (for cloud:assistance)
};

/**
 * @brief CTI Plan information
 *
 * Represents a subscription plan with its products.
 */
struct CTIPlan
{
    std::string name;                 ///< Plan name (e.g., "Pro Plan Deluxe")
    std::string description;          ///< Plan description
    std::vector<CTIProduct> products; ///< Products included in the plan
};

/**
 * @brief Organization information
 */
struct CTIOrganization
{
    std::string name;   ///< Organization name
    std::string avatar; ///< Organization avatar URL
};

/**
 * @brief Complete subscription information
 */
struct CTISubscription
{
    CTIOrganization organization;
    std::vector<CTIPlan> plans;
};

/**
 * @class CTIProductsProvider
 *
 * @brief Provides subscribed products information from CTI Console
 *
 * This class handles:
 * - Fetching subscription info from Console REST API (GET /api/v1/instances/me)
 * - Parsing organization and plan details
 * - Extracting product metadata including resource URLs for token exchange
 * - Filtering products by configured product type
 * - Caching subscription data to minimize API calls
 * - Thread-safe access to subscription information
 *
 * Authentication:
 * - Uses Bearer token (access_token from CTICredentialsProvider)
 * - Sent in Authorization header
 *
 * Product Type Filtering:
 * - Configure "productType" in console config to filter specific product types
 * - Default: "catalog:consumer" (for backward compatibility)
 * - For engine module: "catalog:consumer:decoders"
 * - getCatalogProducts() returns only products matching the configured type
 *
 * Example usage:
 * @code
 *   // Configure for engine module decoders
 *   nlohmann::json config = {
 *       {"console", {
 *           {"url", "https://console.wazuh.com"},
 *           {"productType", "catalog:consumer:decoders"}  // Filter specific type
 *       }}
 *   };
 *   auto provider = std::make_shared<CTIProductsProvider>(urlRequest, config);
 *   provider->setAccessToken(accessToken);
 *
 *   // Get only products matching "catalog:consumer:decoders"
 *   auto catalogProducts = provider->getCatalogProducts();
 *   for (const auto& product : catalogProducts) {
 *       // All products here will have type "catalog:consumer:decoders"
 *       // and include a valid resource URL for content download
 *       std::string signedUrl = signedUrlProvider->getSignedUrl(product.resource, accessToken);
 *       // ... download content using signedUrl
 *   }
 * @endcode
 */
class CTIProductsProvider
{
private:
    IURLRequest& m_urlRequest;
    std::string m_consoleUrl;
    std::string m_instancesEndpoint;
    uint32_t m_timeout;
    std::string m_productType; ///< Product type to filter (e.g., "catalog:consumer:decoders")

    // Access token for Authorization header
    std::string m_accessToken;
    mutable std::mutex m_tokenMutex;

    // Cached subscription data
    CTISubscription m_cachedSubscription;
    bool m_hasCachedData;
    mutable std::mutex m_cacheMutex;

    /**
     * @brief Parse organization from JSON
     */
    CTIOrganization parseOrganization(const nlohmann::json& orgJson)
    {
        CTIOrganization org;

        if (orgJson.contains("name"))
        {
            org.name = orgJson.at("name").get<std::string>();
        }

        if (orgJson.contains("avatar"))
        {
            org.avatar = orgJson.at("avatar").get<std::string>();
        }

        return org;
    }

    /**
     * @brief Parse product from JSON
     */
    CTIProduct parseProduct(const nlohmann::json& productJson)
    {
        CTIProduct product;

        // Required fields
        if (!productJson.contains("identifier"))
        {
            throw std::runtime_error("Product missing required 'identifier' field");
        }
        product.identifier = productJson.at("identifier").get<std::string>();

        if (!productJson.contains("type"))
        {
            throw std::runtime_error("Product missing required 'type' field");
        }
        product.type = productJson.at("type").get<std::string>();

        // Optional common fields
        if (productJson.contains("name"))
        {
            product.name = productJson.at("name").get<std::string>();
        }

        if (productJson.contains("description"))
        {
            product.description = productJson.at("description").get<std::string>();
        }

        // Catalog-specific fields
        if (productJson.contains("resource"))
        {
            product.resource = productJson.at("resource").get<std::string>();
        }

        // Cloud-specific fields
        if (productJson.contains("email"))
        {
            product.email = productJson.at("email").get<std::string>();
        }

        if (productJson.contains("phone"))
        {
            product.phone = productJson.at("phone").get<std::string>();
        }

        return product;
    }

    /**
     * @brief Parse plan from JSON
     */
    CTIPlan parsePlan(const nlohmann::json& planJson)
    {
        CTIPlan plan;

        if (planJson.contains("name"))
        {
            plan.name = planJson.at("name").get<std::string>();
        }

        if (planJson.contains("description"))
        {
            plan.description = planJson.at("description").get<std::string>();
        }

        // Parse products array
        if (planJson.contains("products") && planJson.at("products").is_array())
        {
            for (const auto& productJson : planJson.at("products"))
            {
                try
                {
                    plan.products.push_back(parseProduct(productJson));
                }
                catch (const std::exception& e)
                {
                    logError(WM_CONTENTUPDATER, "CTIProductsProvider: Failed to parse product: %s", e.what());
                    // Continue parsing other products
                }
            }
        }

        return plan;
    }

public:
    /**
     * @brief Constructor
     *
     * @param urlRequest HTTP request interface
     * @param config Configuration JSON with Console settings
     *
     * Expected config structure:
     * @code
     * {
     *   "console": {
     *     "url": "https://console.wazuh.com",           // required
     *     "instancesEndpoint": "/api/v1/instances/me",  // optional, default shown
     *     "timeout": 5000,                              // optional, milliseconds, default 5000
     *     "productType": "catalog:consumer:decoders"    // optional, product type filter
     *   }
     * }
     * @endcode
     */
    explicit CTIProductsProvider(IURLRequest& urlRequest, const nlohmann::json& config)
        : m_urlRequest(urlRequest)
        , m_hasCachedData(false)
    {
        // Parse configuration
        if (!config.contains("console"))
        {
            throw std::runtime_error("CTIProductsProvider: Missing 'console' configuration");
        }

        const auto& consoleConfig = config.at("console");

        if (!consoleConfig.contains("url"))
        {
            throw std::runtime_error("CTIProductsProvider: Missing 'console.url' configuration");
        }

        m_consoleUrl = consoleConfig.at("url").get<std::string>();
        m_instancesEndpoint = consoleConfig.value("instancesEndpoint", "/api/v1/instances/me");
        m_timeout = consoleConfig.value("timeout", 5000);
        m_productType = consoleConfig.value("productType", "catalog:consumer");

        logDebug1(WM_CONTENTUPDATER,
                  "CTIProductsProvider initialized (URL: %s, endpoint: %s, productType: %s)",
                  m_consoleUrl.c_str(),
                  m_instancesEndpoint.c_str(),
                  m_productType.c_str());
    }

    /**
     * @brief Destructor
     */
    ~CTIProductsProvider() = default;

    // Delete copy constructor and assignment operator
    CTIProductsProvider(const CTIProductsProvider&) = delete;
    CTIProductsProvider& operator=(const CTIProductsProvider&) = delete;

    /**
     * @brief Set access token for API authentication
     *
     * Must be called before fetchSubscription().
     *
     * @param token Bearer access token from CTICredentialsProvider
     */
    void setAccessToken(const std::string& token)
    {
        std::lock_guard<std::mutex> lock(m_tokenMutex);
        m_accessToken = token;

        if (token.empty())
        {
            logWarn(WM_CONTENTUPDATER, "CTIProductsProvider: Setting empty access token");
        }
        else
        {
            logDebug2(WM_CONTENTUPDATER, "CTIProductsProvider: Access token updated (length: %zu)", token.length());
        }
    }

    /**
     * @brief Fetch subscription information from Console
     *
     * Makes an HTTP GET request to {consoleUrl}{instancesEndpoint}
     * with Authorization: Bearer {accessToken} header.
     *
     * Expected response format:
     * @code
     * {
     *   "data": {
     *     "organization": {
     *       "name": "ACME S.L.",
     *       "avatar": "https://acme.sl/avatar.png"
     *     },
     *     "plans": [
     *       {
     *         "name": "Pro Plan Deluxe",
     *         "description": "...",
     *         "products": [
     *           {
     *             "identifier": "vulnerabilities-pro",
     *             "type": "catalog:consumer:decoders",
     *             "name": "Vulnerabilities Pro",
     *             "description": "...",
     *             "resource": "https://cti.wazuh.com/api/v1/..."
     *           }
     *         ]
     *       }
     *     ]
     *   }
     * }
     * @endcode
     *
     * @param useCache If true, return cached data if available
     * @return CTISubscription struct with organization and plans (unfiltered)
     * @throws std::runtime_error if fetch fails or response is invalid
     */
    CTISubscription fetchSubscription(bool useCache = true)
    {
        // Check cache first
        if (useCache)
        {
            std::lock_guard<std::mutex> lock(m_cacheMutex);
            if (m_hasCachedData)
            {
                logDebug2(WM_CONTENTUPDATER, "CTIProductsProvider: Returning cached subscription");
                return m_cachedSubscription;
            }
        }

        const std::string url = m_consoleUrl + m_instancesEndpoint;

        logDebug2(WM_CONTENTUPDATER, "Fetching subscription from Console: '%s'", url.c_str());

        // Get access token
        std::string token;
        {
            std::lock_guard<std::mutex> lock(m_tokenMutex);
            token = m_accessToken;
        }

        if (token.empty())
        {
            throw std::runtime_error("CTIProductsProvider: Access token not set. Call setAccessToken() first.");
        }

        std::string responseBody;
        bool success = false;
        std::string errorMessage;
        long statusCode = 0;

        // Success callback
        auto onSuccess = [&](const std::string& response)
        {
            responseBody = response;
            success = true;
        };

        // Error callback
        auto onError = [&](const std::string& error, long code, const std::string& body)
        {
            errorMessage = error;
            statusCode = code;
            responseBody = body;
            success = false;
        };

        // Prepare Authorization header
        std::unordered_set<std::string> headers = {"Authorization: Bearer " + token};

        // Perform HTTP GET request with Authorization header
        m_urlRequest.get(RequestParameters {.url = HttpURL(url), .httpHeaders = headers},
                         PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                         ConfigurationParameters {.timeout = static_cast<long>(m_timeout)});

        if (!success)
        {
            throw std::runtime_error("HTTP request failed: " + errorMessage +
                                     " (status: " + std::to_string(statusCode) + ")");
        }

        // Parse JSON response
        if (!nlohmann::json::accept(responseBody))
        {
            throw std::runtime_error("Invalid JSON response from Console");
        }

        nlohmann::json jsonResponse = nlohmann::json::parse(responseBody);

        // Validate response structure
        if (!jsonResponse.contains("data"))
        {
            throw std::runtime_error("Response missing 'data' field");
        }

        const auto& data = jsonResponse.at("data");

        CTISubscription subscription;

        // Parse organization
        if (data.contains("organization"))
        {
            subscription.organization = parseOrganization(data.at("organization"));
        }

        // Parse plans
        if (data.contains("plans") && data.at("plans").is_array())
        {
            for (const auto& planJson : data.at("plans"))
            {
                try
                {
                    subscription.plans.push_back(parsePlan(planJson));
                }
                catch (const std::exception& e)
                {
                    logError(WM_CONTENTUPDATER, "CTIProductsProvider: Failed to parse plan: %s", e.what());
                    // Continue parsing other plans
                }
            }
        }

        logInfo(WM_CONTENTUPDATER,
                "CTIProductsProvider: Fetched subscription for '%s' (%zu plans, %zu total products)",
                subscription.organization.name.c_str(),
                subscription.plans.size(),
                [&]()
                {
                    size_t count = 0;
                    for (const auto& plan : subscription.plans) count += plan.products.size();
                    return count;
                }());

        // Cache the result
        {
            std::lock_guard<std::mutex> lock(m_cacheMutex);
            m_cachedSubscription = subscription;
            m_hasCachedData = true;
        }

        return subscription;
    }

    /**
     * @brief Get catalog products matching the configured product type
     *
     * Convenience method to extract only catalog products that match
     * the configured product type and have resource URLs for token exchange.
     *
     * @param useCache If true, use cached subscription data
     * @return Vector of catalog products matching the configured product type
     *         Empty vector if no matching products found
     */
    std::vector<CTIProduct> getCatalogProducts(bool useCache = true)
    {
        auto subscription = fetchSubscription(useCache);

        std::vector<CTIProduct> catalogProducts;

        for (const auto& plan : subscription.plans)
        {
            for (const auto& product : plan.products)
            {
                // Filter products by exact type match and require non-empty resource URL
                if (product.type == m_productType && !product.resource.empty())
                {
                    catalogProducts.push_back(product);
                }
            }
        }

        logDebug2(WM_CONTENTUPDATER,
                  "CTIProductsProvider: Found %zu products matching type '%s'",
                  catalogProducts.size(),
                  m_productType.c_str());

        return catalogProducts;
    }

    /**
     * @brief Clear cached subscription data
     *
     * Forces next fetchSubscription() to make a fresh API call.
     */
    void clearCache()
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);
        m_hasCachedData = false;
        m_cachedSubscription = CTISubscription {};

        logDebug2(WM_CONTENTUPDATER, "CTIProductsProvider: Cache cleared");
    }
};

#endif // _CTI_PRODUCTS_PROVIDER_HPP
