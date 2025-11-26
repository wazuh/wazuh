/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * November 04, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CTI_SIGNED_URL_PROVIDER_HPP
#define _CTI_SIGNED_URL_PROVIDER_HPP

#include "IURLRequest.hpp"
#include "json.hpp"
#include "sharedDefs.hpp"
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>

/**
 * @brief Cached signed URL entry
 */
struct SignedUrlCacheEntry
{
    std::string signedUrl; ///< HMAC-signed URL
    uint64_t expiresAt;    ///< Expiration timestamp (UNIX time)
};

/**
 * @class CTISignedUrlProvider
 *
 * @brief Provides signed URLs via OAuth 2.0 Token Exchange
 *
 * This class handles:
 * - Exchanging access_token for resource-specific signed URLs
 * - Caching signed URLs with expiration tracking based on server response
 * - Thread-safe cache operations
 * - Automatic cache entry cleanup
 *
 * The signed URLs are obtained from the CTI Console by exchanging the
 * access token (from Indexer) for a resource-specific HMAC-signed URL
 * following RFC 8693 (OAuth 2.0 Token Exchange).
 *
 * Example token exchange request:
 * POST /api/v1/instances/token/exchange
 * {
 *   "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
 *   "subject_token": "<access_token>",
 *   "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
 *   "requested_token_type": "urn:wazuh:params:oauth:token-type:signed_url",
 *   "resource": "https://cti.wazuh.com/api/v1/catalog/..."
 * }
 *
 * Response:
 * {
 *   "access_token": "https://cti.wazuh.com/...?verify=<hmac_signature>",
 *   "issued_token_type": "urn:wazuh:params:oauth:token-type:signed_url",
 *   "expires_in": 300
 * }
 */
class CTISignedUrlProvider final
{
private:
    IURLRequest& m_urlRequest;                                             ///< HTTP request interface
    std::string m_accessToken;                                             ///< Current access token
    std::string m_consoleUrl;                                              ///< CTI Console base URL
    std::string m_tokenEndpoint;                                           ///< Token exchange endpoint path
    bool m_cacheEnabled;                                                   ///< Enable/disable URL caching
    std::unordered_map<std::string, SignedUrlCacheEntry> m_signedUrlCache; ///< Signed URL cache
    mutable std::mutex m_cacheMutex;                                       ///< Mutex for thread-safe cache access

    /**
     * @brief Perform HTTP POST request
     */
    void performHttpPost(const std::string& url,
                         const std::string& body,
                         const std::function<void(const std::string&)>& onSuccess,
                         const std::function<void(const std::string&, long, const std::string&)>& onError)
    {
        m_urlRequest.post(RequestParameters {.url = HttpURL(url), .data = body},
                          PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                          ConfigurationParameters {});
    }

    /**
     * @brief Remove expired entries from cache (internal helper)
     *
     * @note Caller must hold m_cacheMutex lock
     * @param nowTime Current time as UNIX timestamp
     * @return Number of entries removed
     */
    size_t removeExpiredEntriesUnlocked(uint64_t nowTime)
    {
        size_t removedCount = 0;
        for (auto it = m_signedUrlCache.begin(); it != m_signedUrlCache.end();)
        {
            if (it->second.expiresAt <= nowTime)
            {
                it = m_signedUrlCache.erase(it);
                ++removedCount;
            }
            else
            {
                ++it;
            }
        }
        return removedCount;
    }

    /**
     * @brief Perform token exchange HTTP request
     */
    std::string performTokenExchange(const std::string& resourceUrl)
    {
        if (m_accessToken.empty())
        {
            throw std::runtime_error("CTISignedUrlProvider: No access token set. Call setAccessToken() first.");
        }

        const std::string url = m_consoleUrl + m_tokenEndpoint;

        logDebug2(WM_CONTENTUPDATER,
                  "CTISignedUrlProvider: Performing token exchange (Console: %s, Resource: %s)",
                  url.c_str(),
                  resourceUrl.c_str());

        // Build request body according to RFC 8693
        nlohmann::json requestBody;
        requestBody["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange";
        requestBody["subject_token"] = m_accessToken;
        requestBody["subject_token_type"] = "urn:ietf:params:oauth:token-type:access_token";
        requestBody["requested_token_type"] = "urn:wazuh:params:oauth:token-type:signed_url";
        requestBody["resource"] = resourceUrl;

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

        // Perform HTTP POST request
        performHttpPost(url, requestBody.dump(), onSuccess, onError);

        if (!success)
        {
            throw std::runtime_error("CTISignedUrlProvider: Token exchange failed: " + errorMessage +
                                     " (status: " + std::to_string(statusCode) + ")");
        }

        // Parse JSON response
        if (!nlohmann::json::accept(responseBody))
        {
            throw std::runtime_error("CTISignedUrlProvider: Invalid JSON response from Console");
        }

        auto json = nlohmann::json::parse(responseBody);

        // Extract signed URL
        if (!json.contains("access_token"))
        {
            throw std::runtime_error("CTISignedUrlProvider: Missing 'access_token' in Console response");
        }
        if (!json.contains("expires_in"))
        {
            throw std::runtime_error("CTISignedUrlProvider: Missing 'expires_in' in Console response");
        }

        std::string signedUrl = json.at("access_token").get<std::string>();
        uint64_t expiresIn = json.at("expires_in").get<uint64_t>();

        logDebug2(WM_CONTENTUPDATER, "CTISignedUrlProvider: Signed URL obtained, expires in %llu seconds", expiresIn);

        // Cache the signed URL if caching is enabled
        if (m_cacheEnabled)
        {
            cacheSignedUrl(resourceUrl, signedUrl, expiresIn);
        }

        return signedUrl;
    }

public:
    /**
     * @brief Constructor
     */
    explicit CTISignedUrlProvider(IURLRequest& urlRequest, const nlohmann::json& config)
        : m_urlRequest(urlRequest)
    {
        // Parse configuration
        if (!config.contains("console"))
        {
            throw std::runtime_error("CTISignedUrlProvider: Missing 'console' configuration");
        }

        const auto& consoleConfig = config.at("console");

        if (!consoleConfig.contains("url"))
        {
            throw std::runtime_error("CTISignedUrlProvider: Missing 'console.url' configuration");
        }

        m_consoleUrl = consoleConfig.at("url").get<std::string>();

        if (!config.contains("tokenExchange"))
        {
            throw std::runtime_error("CTISignedUrlProvider: Missing 'tokenExchange' configuration");
        }

        const auto& tokenExConfig = config.at("tokenExchange");
        m_tokenEndpoint = tokenExConfig.value("tokenEndpoint", "/api/v1/instances/token/exchange");
        m_cacheEnabled = tokenExConfig.value("cacheSignedUrls", true);

        logDebug1(WM_CONTENTUPDATER,
                  "CTISignedUrlProvider initialized (Console: %s, endpoint: %s, cache: %s)",
                  m_consoleUrl.c_str(),
                  m_tokenEndpoint.c_str(),
                  m_cacheEnabled ? "enabled" : "disabled");
    }

    /**
     * @brief Destructor
     */
    ~CTISignedUrlProvider() = default;

    // Delete copy constructor and assignment operator
    CTISignedUrlProvider(const CTISignedUrlProvider&) = delete;
    CTISignedUrlProvider& operator=(const CTISignedUrlProvider&) = delete;

    /**
     * @brief Set access token for token exchange
     */
    void setAccessToken(const std::string& token)
    {
        if (token.empty())
        {
            logWarn(WM_CONTENTUPDATER, "CTISignedUrlProvider: Setting empty access token");
        }

        m_accessToken = token;

        logDebug2(WM_CONTENTUPDATER, "CTISignedUrlProvider: Access token set");
    }

    /**
     * @brief Exchange access token for signed URL
     */
    std::string exchangeForSignedUrl(const std::string& resourceUrl)
    {
        // Check cache first if caching is enabled
        if (m_cacheEnabled)
        {
            auto cachedUrl = getCachedSignedUrl(resourceUrl);
            if (cachedUrl.has_value())
            {
                logDebug2(WM_CONTENTUPDATER, "CTISignedUrlProvider: Using cached signed URL");
                return cachedUrl.value();
            }
        }

        // Perform token exchange
        logDebug1(WM_CONTENTUPDATER, "CTISignedUrlProvider: No cached URL, performing token exchange");
        return performTokenExchange(resourceUrl);
    }

    /**
     * @brief Get cached signed URL if available and not expired
     */
    std::optional<std::string> getCachedSignedUrl(const std::string& resourceUrl) const
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);

        auto it = m_signedUrlCache.find(resourceUrl);
        if (it == m_signedUrlCache.end())
        {
            logDebug2(WM_CONTENTUPDATER, "CTISignedUrlProvider: No cache entry for resource");
            return std::nullopt;
        }

        // Check if cached entry is still valid
        auto now = std::chrono::system_clock::now();
        auto expiresAt = std::chrono::system_clock::from_time_t(it->second.expiresAt);

        if (now >= expiresAt)
        {
            logDebug2(WM_CONTENTUPDATER, "CTISignedUrlProvider: Cached URL expired");
            return std::nullopt;
        }

        auto timeRemaining = std::chrono::duration_cast<std::chrono::seconds>(expiresAt - now);
        logDebug2(WM_CONTENTUPDATER,
                  "CTISignedUrlProvider: Cache hit, URL valid for %lld more seconds",
                  timeRemaining.count());

        return it->second.signedUrl;
    }

    /**
     * @brief Cache signed URL
     */
    void cacheSignedUrl(const std::string& resourceUrl, const std::string& signedUrl, uint64_t expiresIn)
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);

        auto now = std::chrono::system_clock::now();
        auto expiryTime = now + std::chrono::seconds(expiresIn);
        uint64_t expiresAt = std::chrono::system_clock::to_time_t(expiryTime);

        SignedUrlCacheEntry entry {signedUrl, expiresAt};
        m_signedUrlCache[resourceUrl] = std::move(entry);

        logDebug2(WM_CONTENTUPDATER, "CTISignedUrlProvider: Cached signed URL (expires in %llu seconds)", expiresIn);

        // Opportunistically clean expired entries
        // Note: We're already holding the lock, so we can clean directly
        auto nowTime = std::chrono::system_clock::to_time_t(now);
        size_t removedCount = removeExpiredEntriesUnlocked(nowTime);

        if (removedCount > 0)
        {
            logDebug2(WM_CONTENTUPDATER, "CTISignedUrlProvider: Removed %zu expired cache entries", removedCount);
        }
    }

    /**
     * @brief Clear expired entries from cache
     */
    void clearExpiredCacheEntries()
    {
        std::lock_guard<std::mutex> lock(m_cacheMutex);

        auto now = std::chrono::system_clock::now();
        auto nowTime = std::chrono::system_clock::to_time_t(now);

        size_t removedCount = removeExpiredEntriesUnlocked(nowTime);

        if (removedCount > 0)
        {
            logDebug1(WM_CONTENTUPDATER, "CTISignedUrlProvider: Cleared %zu expired cache entries", removedCount);
        }
    }
};

#endif // _CTI_SIGNED_URL_PROVIDER_HPP
