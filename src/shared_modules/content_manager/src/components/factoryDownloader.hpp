/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * April 14, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_DOWNLOADER_HPP
#define _FACTORY_DOWNLOADER_HPP

#include "APIDownloader.hpp"
#include "CtiOffsetDownloader.hpp"
#include "CtiSnapshotDownloader.hpp"
#include "HTTPRequest.hpp"
#include "ctiCredentialsProvider.hpp"
#include "ctiProductsProvider.hpp"
#include "ctiSignedUrlProvider.hpp"
#include "fileDownloader.hpp"
#include "json.hpp"
#include "offlineDownloader.hpp"
#include "sharedDefs.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <memory>
#include <string>

/**
 * @class FactoryDownloader
 *
 * @brief Class in charge of creating the content downloader.
 *
 */
class FactoryDownloader final
{
private:
    /**
     * @brief Create OAuth providers if configuration is present
     *
     * Creates the three OAuth providers needed for the complete authentication flow:
     * 1. CTICredentialsProvider - Fetches access tokens from Indexer
     * 2. CTIProductsProvider - Fetches subscription/products from Console (optional)
     * 3. CTISignedUrlProvider - Exchanges tokens for signed URLs
     *
     * Expected configuration structure:
     * {
     *   "oauth": {
     *     "indexer": {
     *       "url": "https://indexer.wazuh.com",
     *       "credentialsEndpoint": "/_plugins/content-manager/subscription",  // Optional
     *       "timeout": 5000                                     // Optional
     *     },
     *     "console": {
     *       "url": "https://console.wazuh.com",
     *       "instancesEndpoint": "/api/v1/instances/me",        // Optional
     *       "tokenExchangeEndpoint": "/api/v1/instances/token/exchange",  // Optional
     *       "timeout": 5000                                      // Optional
     *     },
     *     "enableProductsProvider": true  // Optional, defaults to true
     *   }
     * }
     *
     * @param config Configuration JSON containing OAuth settings
     * @return Tuple of (credentialsProvider, productsProvider, signedUrlProvider)
     *         Any provider can be nullptr if config is missing or incomplete
     */
    static std::tuple<std::shared_ptr<CTICredentialsProvider>,
                      std::shared_ptr<CTIProductsProvider>,
                      std::shared_ptr<CTISignedUrlProvider>>
    createOAuthProviders(const nlohmann::json& config)
    {
        // Check if OAuth configuration exists
        if (!config.contains("oauth"))
        {
            logDebug2(WM_CONTENTUPDATER, "FactoryDownloader: No OAuth configuration found, providers disabled");
            return {nullptr, nullptr, nullptr};
        }

        const auto& oauthConfig = config.at("oauth");

        try
        {
            // Step 1: Create credentials provider (required for OAuth flow)
            std::shared_ptr<CTICredentialsProvider> credentialsProvider = nullptr;
            if (oauthConfig.contains("indexer"))
            {
                logDebug1(WM_CONTENTUPDATER, "FactoryDownloader: Creating CTICredentialsProvider");
                credentialsProvider = std::make_shared<CTICredentialsProvider>(HTTPRequest::instance(), oauthConfig);
                logInfo(WM_CONTENTUPDATER, "FactoryDownloader: CTICredentialsProvider created successfully");
            }
            else
            {
                logWarn(WM_CONTENTUPDATER,
                        "FactoryDownloader: OAuth config missing 'indexer' section, credentials provider disabled");
            }

            // Step 2: Create products provider (optional, for subscription-based product discovery)
            std::shared_ptr<CTIProductsProvider> productsProvider = nullptr;
            bool enableProductsProvider = true;
            if (oauthConfig.contains("enableProductsProvider"))
            {
                enableProductsProvider = oauthConfig.at("enableProductsProvider").get<bool>();
            }

            if (enableProductsProvider && oauthConfig.contains("console"))
            {
                logDebug1(WM_CONTENTUPDATER, "FactoryDownloader: Creating CTIProductsProvider");
                productsProvider = std::make_shared<CTIProductsProvider>(HTTPRequest::instance(), oauthConfig);
                logInfo(WM_CONTENTUPDATER, "FactoryDownloader: CTIProductsProvider created successfully");
            }
            else if (!enableProductsProvider)
            {
                logDebug1(WM_CONTENTUPDATER, "FactoryDownloader: CTIProductsProvider disabled by configuration");
            }
            else
            {
                logDebug1(WM_CONTENTUPDATER,
                          "FactoryDownloader: OAuth config missing 'console' section, products provider disabled");
            }

            // Step 3: Create signed URL provider (required for OAuth flow)
            std::shared_ptr<CTISignedUrlProvider> signedUrlProvider = nullptr;
            if (oauthConfig.contains("console"))
            {
                logDebug1(WM_CONTENTUPDATER, "FactoryDownloader: Creating CTISignedUrlProvider");
                signedUrlProvider = std::make_shared<CTISignedUrlProvider>(HTTPRequest::instance(), oauthConfig);
                logInfo(WM_CONTENTUPDATER, "FactoryDownloader: CTISignedUrlProvider created successfully");
            }
            else
            {
                logWarn(WM_CONTENTUPDATER,
                        "FactoryDownloader: OAuth config missing 'console' section, signed URL provider disabled");
            }

            // Log the OAuth configuration status
            if (credentialsProvider && signedUrlProvider)
            {
                if (productsProvider)
                {
                    logInfo(WM_CONTENTUPDATER,
                            "FactoryDownloader: Complete OAuth flow enabled (3 providers: credentials + products + "
                            "signed URL)");
                }
                else
                {
                    logInfo(WM_CONTENTUPDATER,
                            "FactoryDownloader: Basic OAuth flow enabled (2 providers: credentials + signed URL)");
                }
            }
            else
            {
                logWarn(WM_CONTENTUPDATER,
                        "FactoryDownloader: Incomplete OAuth configuration, authentication may not work properly");
            }

            return {credentialsProvider, productsProvider, signedUrlProvider};
        }
        catch (const std::exception& e)
        {
            logError(WM_CONTENTUPDATER, "FactoryDownloader: Failed to create OAuth providers: %s", e.what());
            logWarn(WM_CONTENTUPDATER, "FactoryDownloader: Falling back to non-authenticated downloads");
            return {nullptr, nullptr, nullptr};
        }
    }

public:
    /**
     * @brief Create the content downloader based on the contentSource value.
     *
     * This method creates the appropriate downloader and configures OAuth authentication
     * if the configuration contains an "oauth" section.
     *
     * OAuth Configuration (optional):
     * - If present, creates CTICredentialsProvider, CTIProductsProvider (optional), and CTISignedUrlProvider
     * - If missing or invalid, falls back to non-authenticated downloads
     * - Maintains backward compatibility with existing configurations
     *
     * @param config Configurations.
     * @return std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>>
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> create(const nlohmann::json& config)
    {
        const auto& downloaderType {config.at("contentSource").get_ref<const std::string&>()};
        logDebug1(WM_CONTENTUPDATER, "Creating '%s' downloader", downloaderType.c_str());

        // Create OAuth providers if configuration is present
        auto [credentialsProvider, productsProvider, signedUrlProvider] = createOAuthProviders(config);

        if ("api" == downloaderType)
        {
            return std::make_shared<APIDownloader>(HTTPRequest::instance());
        }
        if ("cti-offset" == downloaderType)
        {
            return std::make_shared<CtiOffsetDownloader>(
                HTTPRequest::instance(), credentialsProvider, productsProvider, signedUrlProvider);
        }
        if ("cti-snapshot" == downloaderType)
        {
            return std::make_shared<CtiSnapshotDownloader>(
                HTTPRequest::instance(), credentialsProvider, productsProvider, signedUrlProvider);
        }
        if ("file" == downloaderType)
        {
            return std::make_shared<FileDownloader>();
        }
        if ("offline" == downloaderType)
        {
            return std::make_shared<OfflineDownloader>(HTTPRequest::instance());
        }

        throw std::invalid_argument {"Invalid 'contentSource' type: " + downloaderType};
    }
};

#endif // _FACTORY_DOWNLOADER_HPP
