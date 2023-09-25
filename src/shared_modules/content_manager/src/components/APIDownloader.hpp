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

#include "IURLRequest.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <iostream>
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
        std::cout << "APIDownloader - Starting" << std::endl;
        // Get the parameters needed to download the content.
        getParameters();

        // First, make a get request to the API to get the consumer offset.
        getConsumerLastOffset();

        // Iterate until the current offset is equal to the consumer offset.
        while (m_context->currentOffset < m_consumerLastOffset)
        {
            // Calculate the offset to download
            const auto toOffset = std::min(m_consumerLastOffset, m_context->currentOffset + 1000);

            // full path where the content will be saved.
            std::ostringstream filePathStream;
            filePathStream << m_outputFolder << "/" << toOffset << "-" << m_fileName;
            const std::string fullFilePath = filePathStream.str();

            // Download the content.
            downloadContent(toOffset, fullFilePath);

            // Update the current offset.
            m_context->currentOffset = toOffset;

            // Save the path of the downloaded content in the context.
            m_context->data.at("paths").push_back(fullFilePath);
        }

        // Set the status of the stage.
        m_context->data.at("stageStatus").push_back(R"({"stage": "APIDownloader", "status": "ok"})"_json);
        std::cout << "APIDownloader - Finishing" << std::endl;
    }

    /**
     * @brief Get the parameters needed to download the content.
     *
     */
    void getParameters()
    {
        // URL of the API to connect to.
        m_url = m_context->spUpdaterBaseContext->configData.at("url").get<std::string>();

        // Output folder where the file will be saved.
        m_outputFolder = m_context->spUpdaterBaseContext->downloadsFolder;
        if (m_context->spUpdaterBaseContext->configData.at("compressionType").get<std::string>().compare("raw") == 0)
        {
            m_outputFolder = m_context->spUpdaterBaseContext->contentsFolder;
        }

        // name of the file where the content will be saved.
        m_fileName = m_context->spUpdaterBaseContext->configData.at("contentFileName").get<std::string>();
    }

    /**
     * @brief Get the consumer offset.
     *
     */
    void getConsumerLastOffset()
    {
        // Save the consumer offset.
        const auto onSuccess {[this](const std::string& data)
                              {
                                  const auto dataBlobObj = nlohmann::json::parse(data);
                                  m_consumerLastOffset = dataBlobObj.at("data").at("last_offset").get<int>();
                                  std::cout << "APIDownloader - Request processed successfully.\n";
                              }};

        const auto onError {
            [this](const std::string& message, [[maybe_unused]] const long statusCode)
            {
                // Set the status of the stage
                m_context->data.at("stageStatus").push_back(R"({"stage": "APIDownloader", "status": "fail"})"_json);

                throw std::runtime_error("APIDownloader - Could not get response from API because: " + message);
            }};

        // Make a get request to the API to get the consumer offset.
        m_urlRequest.get(HttpURL(m_url), onSuccess, onError);
    }

    /**
     * @brief Download the content from the API.
     *
     * @param toOffset end offset to download.
     * @param fullFilePath full path where the content will be saved.
     */
    void downloadContent(int toOffset, const std::string& fullFilePath) const
    {
        const auto onSuccess {[]([[maybe_unused]] const std::string& data)
                              {
                                  std::cout << "APIDownloader - Request processed successfully.\n";
                              }};

        const auto onError {
            [this](const std::string& message, [[maybe_unused]] const long statusCode)
            {
                // Set the status of the stage
                m_context->data.at("stageStatus").push_back(R"({"stage": "APIDownloader", "status": "fail"})"_json);

                throw std::runtime_error("APIDownloader - Could not get response from API because: " + message);
            }};

        const auto fromOffset = m_context->currentOffset;

        // make the parameters for the request
        const auto queryParameters =
            "/changes?from_offset=" + std::to_string(fromOffset) + "&to_offset=" + std::to_string(toOffset);

        // Make a get request to the API to get the content.
        m_urlRequest.get(HttpURL(m_url + queryParameters), onSuccess, onError, fullFilePath);
    }

    IURLRequest& m_urlRequest;                    ///< Interface to perform HTTP requests
    std::string m_url {};                         ///< URL of the API to connect to.
    std::string m_outputFolder {};                ///< output folder where the file will be saved
    std::string m_fileName {};                    ///< name of the file where the content will be saved
    int m_consumerLastOffset {};                  ///< consumer offset
    std::shared_ptr<UpdaterContext> m_context {}; ///< updater context

public:
    // LCOV_EXCL_START
    ~APIDownloader() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Class constructor.
     *
     * @param urlRequest Object to perform the HTTP requests to the CTI API.
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
        m_context = context;
        download();

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _API_DOWNLOADER_HPP
