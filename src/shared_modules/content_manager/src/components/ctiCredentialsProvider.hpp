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

#ifndef _CTI_CREDENTIALS_PROVIDER_HPP
#define _CTI_CREDENTIALS_PROVIDER_HPP

#include "IURLRequest.hpp"
#include "json.hpp"
#include "sharedDefs.hpp"
#include <chrono>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

/**
 * @brief Credential structure returned by Wazuh Indexer
 *
 * Contains OAuth 2.0 credentials from Device Authorization Grant flow.
 * Stored in memory only, never persisted to disk.
 */
struct Credentials
{
    std::string accessToken; ///< OAuth 2.0 access token
};

/**
 * @brief Thread-safe credentials with mutex protection
 */
struct ProtectedCredentials
{
    std::string accessToken;
    mutable std::mutex mutex; ///< Protects all credential fields
};

/**
 * @class CTICredentialsProvider
 *
 * @brief Provides OAuth 2.0 credentials from Wazuh Indexer
 *
 * This class handles:
 * - Fetching credentials from Indexer REST API (GET /_plugins/content-manager/subscription)
 * - Storing access_token in memory
 * - Automatic token refresh on each request
 * - Thread-safe credential access
 * - Background refresh thread monitoring
 *
 * The credentials are obtained from the Wazuh Indexer which performs the
 * OAuth 2.0 Device Authorization Grant flow with the CTI Console.
 */
class CTICredentialsProvider final
{
private:
    ProtectedCredentials m_credentials;      ///< Current credential state
    IURLRequest& m_urlRequest;               ///< HTTP request interface
    std::string m_indexerUrl;                ///< Indexer base URL
    std::string m_credentialsEndpoint;       ///< Credentials API endpoint
    uint32_t m_pollInterval;                 ///< Refresh check interval (seconds)
    uint32_t m_timeout;                      ///< HTTP request timeout (milliseconds)
    uint32_t m_retryAttempts;                ///< Number of retry attempts
    std::thread m_refreshThread;             ///< Background refresh thread
    std::atomic<bool> m_stopRefresh {false}; ///< Flag to stop refresh thread

    /**
     * @brief Perform HTTP GET request with retry logic
     */
    void performHttpGet(const std::string& url,
                        const std::function<void(const std::string&)>& onSuccess,
                        const std::function<void(const std::string&, long, const std::string&)>& onError)
    {
        m_urlRequest.get(RequestParameters {.url = HttpURL(url)},
                         PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                         ConfigurationParameters {});
    }

    /**
     * @brief Background thread loop for automatic refresh
     */
    void refreshThreadLoop()
    {
        logDebug1(WM_CONTENTUPDATER, "CTICredentialsProvider: Refresh thread loop started");

        while (!m_stopRefresh)
        {
            try
            {
                checkAndRefreshIfNeeded();
            }
            catch (const std::exception& e)
            {
                logError(WM_CONTENTUPDATER, "CTICredentialsProvider: Error in refresh thread: %s", e.what());
            }

            // Sleep for poll interval (with periodic checks for stop flag)
            for (uint32_t i = 0; i < m_pollInterval && !m_stopRefresh; ++i)
            {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

        logDebug1(WM_CONTENTUPDATER, "CTICredentialsProvider: Refresh thread loop exited");
    }

    /**
     * @brief Refresh token from indexer
     *
     * Always fetches a fresh token since the endpoint doesn't provide expiration info.
     */
    void checkAndRefreshIfNeeded()
    {
        std::lock_guard<std::mutex> lock(m_credentials.mutex);

        logDebug2(WM_CONTENTUPDATER, "CTICredentialsProvider: Refreshing access token...");

        try
        {
            // Release lock during HTTP call
            m_credentials.mutex.unlock();
            auto newCreds = fetchFromIndexer();
            m_credentials.mutex.lock();

            m_credentials.accessToken = std::move(newCreds.accessToken);

            logInfo(WM_CONTENTUPDATER, "CTICredentialsProvider: Access token refreshed successfully");
        }
        catch (const std::exception& e)
        {
            // Re-acquire lock if we released it
            if (!m_credentials.mutex.try_lock())
            {
                m_credentials.mutex.lock();
            }

            logError(WM_CONTENTUPDATER, "CTICredentialsProvider: Failed to refresh token: %s", e.what());
        }
    }

public:
    /**
     * @brief Constructor
     *
     * @param urlRequest HTTP request interface
     * @param config Configuration JSON with indexer settings
     */
    explicit CTICredentialsProvider(IURLRequest& urlRequest, const nlohmann::json& config)
        : m_urlRequest(urlRequest)
    {
        // Parse configuration
        if (!config.contains("indexer"))
        {
            throw std::runtime_error("CTICredentialsProvider: Missing 'indexer' configuration");
        }

        const auto& indexerConfig = config.at("indexer");

        if (!indexerConfig.contains("url"))
        {
            throw std::runtime_error("CTICredentialsProvider: Missing 'indexer.url' configuration");
        }

        m_indexerUrl = indexerConfig.at("url").get<std::string>();
        m_credentialsEndpoint = indexerConfig.value("credentialsEndpoint", "/_plugins/content-manager/subscription");
        m_pollInterval = indexerConfig.value("pollInterval", 60);
        m_timeout = indexerConfig.value("timeout", 5000);
        m_retryAttempts = indexerConfig.value("retryAttempts", 3);

        logInfo(WM_CONTENTUPDATER,
                "CTICredentialsProvider initialized (URL: %s, endpoint: %s, poll: %us)",
                m_indexerUrl.c_str(),
                m_credentialsEndpoint.c_str(),
                m_pollInterval);
    }

    /**
     * @brief Destructor - stops refresh thread
     */
    ~CTICredentialsProvider()
    {
        stopAutoRefresh();
    }

    // Delete copy constructor and assignment operator
    CTICredentialsProvider(const CTICredentialsProvider&) = delete;
    CTICredentialsProvider& operator=(const CTICredentialsProvider&) = delete;

    /**
     * @brief Fetch credentials from Indexer API
     *
     * Makes an HTTP GET request to {indexerUrl}{credentialsEndpoint}
     * Expected response format:
     * {
     *   "access_token": "AYjcyMzY3ZDhiNmJkNTY",
     *   "token_type": "Bearer"
     * }
     *
     * @return Credentials struct with access token
     * @throws std::runtime_error if fetch fails after retries
     */
    Credentials fetchFromIndexer()
    {
        const std::string url = m_indexerUrl + m_credentialsEndpoint;

        logDebug2(WM_CONTENTUPDATER, "Fetching credentials from Indexer: '%s'", url.c_str());

        // Retry logic with exponential backoff
        for (uint32_t attempt = 1; attempt <= m_retryAttempts; ++attempt)
        {
            try
            {
                Credentials creds;
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

                // Perform HTTP GET request
                performHttpGet(url, onSuccess, onError);

                if (!success)
                {
                    throw std::runtime_error("HTTP request failed: " + errorMessage +
                                             " (status: " + std::to_string(statusCode) + ")");
                }

                // Parse JSON response
                if (!nlohmann::json::accept(responseBody))
                {
                    throw std::runtime_error("Invalid JSON response from Indexer");
                }

                auto json = nlohmann::json::parse(responseBody);

                // Extract credentials
                if (!json.contains("access_token"))
                {
                    throw std::runtime_error("Missing 'access_token' in Indexer response");
                }
                if (!json.contains("token_type"))
                {
                    throw std::runtime_error("Missing 'token_type' in Indexer response");
                }

                creds.accessToken = json.at("access_token").get<std::string>();
                std::string tokenType = json.at("token_type").get<std::string>();

                logInfo(WM_CONTENTUPDATER,
                        "Credentials fetched successfully from Indexer (token_type: %s)",
                        tokenType.c_str());

                return creds;
            }
            catch (const std::exception& e)
            {
                logWarn(WM_CONTENTUPDATER,
                        "Failed to fetch credentials from Indexer: %s (attempt %u/%u)",
                        e.what(),
                        attempt,
                        m_retryAttempts);

                // Exponential backoff before retry
                if (attempt < m_retryAttempts)
                {
                    uint32_t backoffTime = 2 * attempt; // 2, 4, 6 seconds
                    logDebug1(WM_CONTENTUPDATER, "Retrying in %u seconds...", backoffTime);
                    std::this_thread::sleep_for(std::chrono::seconds(backoffTime));
                }
            }
        }

        throw std::runtime_error("Failed to fetch credentials from Indexer after " + std::to_string(m_retryAttempts) +
                                 " attempts");
    }

    /**
     * @brief Get current access token
     *
     * If no token is available, automatically fetches new credentials from the Indexer.
     *
     * @return Access token string
     * @throws std::runtime_error if unable to obtain token
     */
    std::string getAccessToken()
    {
        std::lock_guard<std::mutex> lock(m_credentials.mutex);

        // Fetch if no token
        if (m_credentials.accessToken.empty())
        {
            logDebug1(WM_CONTENTUPDATER, "No access token available, fetching from Indexer");

            // Release lock during HTTP call to avoid holding it
            m_credentials.mutex.unlock();
            auto newCreds = fetchFromIndexer();
            m_credentials.mutex.lock();

            m_credentials.accessToken = std::move(newCreds.accessToken);
        }

        return m_credentials.accessToken;
    }

    /**
     * @brief Start background refresh thread
     *
     * Starts a background thread that periodically checks if credentials need
     * refreshing and automatically fetches new ones when needed.
     */
    void startAutoRefresh()
    {
        if (m_refreshThread.joinable())
        {
            logWarn(WM_CONTENTUPDATER, "CTICredentialsProvider: Refresh thread already running");
            return;
        }

        m_stopRefresh = false;
        m_refreshThread = std::thread(&CTICredentialsProvider::refreshThreadLoop, this);

        logInfo(
            WM_CONTENTUPDATER, "CTICredentialsProvider: Auto-refresh thread started (interval: %us)", m_pollInterval);
    }

    /**
     * @brief Stop background refresh thread
     *
     * Stops the background refresh thread gracefully.
     */
    void stopAutoRefresh()
    {
        if (!m_refreshThread.joinable())
        {
            return;
        }

        logInfo(WM_CONTENTUPDATER, "CTICredentialsProvider: Stopping auto-refresh thread...");

        m_stopRefresh = true;
        m_refreshThread.join();

        logInfo(WM_CONTENTUPDATER, "CTICredentialsProvider: Auto-refresh thread stopped");
    }
};

#endif // _CTI_CREDENTIALS_PROVIDER_HPP
