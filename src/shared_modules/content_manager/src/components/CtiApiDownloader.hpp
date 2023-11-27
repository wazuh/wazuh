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
#ifndef _CTI_API_DOWNLOADER_HPP
#define _CTI_API_DOWNLOADER_HPP

#include "../sharedDefs.hpp"
#include "IURLRequest.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <utility>

/**
 * @brief Custom exception used to identify server HTTP errors when downloading from the CTI server.
 *
 */
class cti_server_error : public std::exception // NOLINT
{
    std::string m_what; ///< Exception message.

public:
    /**
     * @brief Class constructor.
     *
     * @param what Exception message.
     */
    explicit cti_server_error(std::string what)
        : m_what(std::move(what))
    {
    }

    /**
     * @brief Returns the exception message.
     *
     * @return const char* Message.
     */
    const char* what() const noexcept override
    {
        return m_what.c_str();
    }
};

/**
 * @class CtiApiDownloader
 *
 * @brief Class in charge of downloading the content from the API as a step of a chain of responsibility.
 *
 */
class CtiApiDownloader final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Download the content from the API.
     *
     * @param context updater context.
     */
    void download()
    {
        logDebug2(WM_CONTENTUPDATER, "CtiApiDownloader - Starting");
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
        m_context->data.at("stageStatus").push_back(R"({"stage": "CtiApiDownloader", "status": "ok"})"_json);
        logDebug2(WM_CONTENTUPDATER, "CtiApiDownloader - Finishing");
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
                                  logDebug2(WM_CONTENTUPDATER, "CtiApiDownloader - Request processed successfully.");
                              }};

        // Make a get request to the API to get the consumer offset.
        performQueryWithRetry(onSuccess);
    }

    /**
     * @brief Download the content from the API.
     *
     * @param toOffset end offset to download.
     * @param fullFilePath full path where the content will be saved.
     */
    void downloadContent(int toOffset, const std::string& fullFilePath) const
    {
        // Define the parameters for the request.
        const auto queryParameters = "/changes?from_offset=" + std::to_string(m_context->currentOffset) +
                                     "&to_offset=" + std::to_string(toOffset);

        // On download success routine.
        const auto onSuccess {[]([[maybe_unused]] const std::string& data)
                              {
                                  logDebug2(WM_CONTENTUPDATER, "CtiApiDownloader - Request processed successfully.");
                              }};

        // Download the content.
        performQueryWithRetry(onSuccess, queryParameters, fullFilePath);
    }

    /**
     * @brief Loop for retrying the downloads from the server until the download is successful or there is an HTTP error
     * different from 5xx.
     *
     * @param onSuccess Callback on success download.
     * @param queryParameters Parameters to the GET query.
     * @param outputFilepath File where to store the downloaded content.
     */
    void performQueryWithRetry(const std::function<void(const std::string&)>& onSuccess,
                               const std::string& queryParameters = "",
                               const std::string& outputFilepath = "") const
    {
        // On download error routine.
        const auto onError {
            [](const std::string& message, const long statusCode)
            {
                const std::string exceptionMessage {"Error " + std::to_string(statusCode) + " from server: " + message};

                // If there is an error from the server, throw a different exception.
                if (statusCode >= 500 && statusCode <= 599)
                {
                    throw cti_server_error {exceptionMessage};
                }
                throw std::runtime_error {exceptionMessage};
            }};

        constexpr auto INITIAL_SLEEP_TIME {1};
        auto sleepTime {INITIAL_SLEEP_TIME};
        auto retryAttempt {1};
        auto retry {true};
        while (retry)
        {
            try
            {
                m_urlRequest.get(HttpURL(m_url + queryParameters), onSuccess, onError, outputFilepath);
                retry = false;
            }
            catch (const cti_server_error& e)
            {
                constexpr auto SLEEP_TIME_THRESHOLD {30};

                logError(WM_CONTENTUPDATER, e.what());

                // Sleep and, if necessary, increase sleep time exponentially.
                std::this_thread::sleep_for(std::chrono::seconds(sleepTime));
                if (sleepTime < SLEEP_TIME_THRESHOLD)
                {
                    sleepTime = std::min(SLEEP_TIME_THRESHOLD, static_cast<int>(std::pow(2, retryAttempt)));
                    ++retryAttempt;
                }
            }
        }
    }

    IURLRequest& m_urlRequest;                    ///< Interface to perform HTTP requests
    std::string m_url {};                         ///< URL of the API to connect to.
    std::string m_outputFolder {};                ///< output folder where the file will be saved
    std::string m_fileName {};                    ///< name of the file where the content will be saved
    int m_consumerLastOffset {};                  ///< consumer offset
    std::shared_ptr<UpdaterContext> m_context {}; ///< updater context

public:
    // LCOV_EXCL_START
    ~CtiApiDownloader() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Class constructor.
     *
     * @param urlRequest Object to perform the HTTP requests to the CTI API.
     */
    explicit CtiApiDownloader(IURLRequest& urlRequest)
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

        try
        {
            download();
        }
        catch (const std::exception& e)
        {
            m_context->data.at("stageStatus").push_back(R"({"stage": "CtiApiDownloader", "status": "fail"})"_json);
            throw;
        }

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _CTI_API_DOWNLOADER_HPP
