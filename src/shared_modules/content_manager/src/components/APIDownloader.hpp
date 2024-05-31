/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 02, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _API_DOWNLOADER_HPP
#define _API_DOWNLOADER_HPP

#include "../sharedDefs.hpp"
#include "IURLRequest.hpp"
#include "componentsHelper.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <memory>

/**
 * @class APIDownloader
 *
 * @brief Class in charge of downloading the content from the API as a step of a chain of responsibility.
 *
 */
class APIDownloader final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Download the content from the API.
     *
     * @param context updater context.
     */
    void download()
    {
        // Get the parameters needed to download the content.
        getParameters();

        // Download the content.
        downloadContent();

        // Save the path of the downloaded content in the context
        m_context->data.at("paths").push_back(m_fullFilePath);

        logDebug2(WM_CONTENTUPDATER, "APIDownloader - Finishing - Download done successfully");
    }

    /**
     * @brief Get the parameters needed to download the content.
     *
     */
    void getParameters()
    {
        // URL of the API to connect to.
        m_url = m_context->spUpdaterBaseContext->configData.at("url").get<std::string>();
        // output folder where the file will be saved
        std::string outputFolder {m_context->spUpdaterBaseContext->downloadsFolder};
        if (m_context->spUpdaterBaseContext->configData.at("compressionType").get<std::string>().compare("raw") == 0)
        {
            outputFolder = m_context->spUpdaterBaseContext->contentsFolder;
        }
        // name of the file where the content will be saved
        const auto fileName {m_context->spUpdaterBaseContext->configData.at("contentFileName").get<std::string>()};
        // full path where the content will be saved
        m_fullFilePath = outputFolder + "/" + fileName;
    }

    /**
     * @brief Download the content from the API.
     *
     */
    void downloadContent()
    {
        logDebug2(WM_CONTENTUPDATER, "Downloading from API '%s'", m_url.c_str());

        const auto onError {
            [](const std::string& message, [[maybe_unused]] const long statusCode)
            {
                throw std::runtime_error("APIDownloader - Could not get response from API because: " + message);
            }};

        // Run the request. Save the file on disk.
        m_urlRequest.download(
            HttpURL(m_url), m_fullFilePath, onError, {}, {}, m_context->spUpdaterBaseContext->httpUserAgent);
    }

    std::string m_url {};                         ///< URL of the API to connect to.
    std::string m_fullFilePath {};                ///< Full path where the content will be saved.
    IURLRequest& m_urlRequest;                    ///< Interface to perform HTTP requests
    std::shared_ptr<UpdaterContext> m_context {}; ///< updater context

public:
    // LCOV_EXCL_START
    ~APIDownloader() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Class constructor.
     *
     * @param urlRequest Object to perform the HTTP requests to an API.
     */
    explicit APIDownloader(IURLRequest& urlRequest)
        : m_urlRequest(urlRequest)
    {
    }

    /**
     * @brief Download the content from the API.
     *
     * @param context updater context.
     * @return std::shared_ptr<UpdaterContext>
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "APIDownloader - Starting process");
        constexpr auto COMPONENT_NAME {"APIDownloader"};

        m_context = context;

        try
        {
            download();
        }
        catch (const std::exception& e)
        {
            // Push error state.
            Components::pushStatus(COMPONENT_NAME, Components::Status::STATUS_FAIL, *context);

            throw std::runtime_error("Download failed: " + std::string(e.what()));
        }

        // Push success state.
        Components::pushStatus(COMPONENT_NAME, Components::Status::STATUS_OK, *context);

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
    }
};

#endif // _API_DOWNLOADER_HPP
