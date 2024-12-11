/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * October 24, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OFFLINE_DOWNLOADER_HPP
#define _OFFLINE_DOWNLOADER_HPP

#include "../sharedDefs.hpp"
#include "IURLRequest.hpp"
#include "componentsHelper.hpp"
#include "hashHelper.h"
#include "json.hpp"
#include "stringHelper.h"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

/**
 * @class OfflineDownloader
 *
 * @brief Class in charge of downloading a file in offline mode and updating the context accordingly, as a step of a
 * chain of responsibility.
 *
 */
class OfflineDownloader final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    IURLRequest& m_urlRequest; ///< HTTP driver instance.

    /**
     * @brief Copy a file from the localsystem.
     *
     * @param inputFilepath Input path from where to copy the file.
     * @param outputFilepath Output path where to paste the file.
     * @return true if the file was copied, otherwise false.
     */
    bool copyFile(const std::filesystem::path& inputFilepath, const std::filesystem::path& outputFilepath) const
    {
        constexpr auto FILE_PREFIX {"file://"};

        // Remove file prefix.
        auto unprefixedUrl {inputFilepath.string()};
        Utils::replaceFirst(unprefixedUrl, FILE_PREFIX, "");

        // Check input file existence.
        if (!std::filesystem::exists(unprefixedUrl))
        {
            logWarn(WM_CONTENTUPDATER, "File '%s' doesn't exist.", inputFilepath.string().c_str());
            return false;
        }

        // Copy file, overriding the output one if necessary.
        logDebug2(WM_CONTENTUPDATER,
                  "Copying file from '%s' into '%s'",
                  inputFilepath.string().c_str(),
                  outputFilepath.string().c_str());
        std::filesystem::copy(unprefixedUrl, outputFilepath, std::filesystem::copy_options::overwrite_existing);
        return true;
    }

    /**
     * @brief Download a file from an HTTP server.
     *
     * @param inputFileURL URL from where to download the file.
     * @param outputFilepath Output path where to store the downloaded file.
     * @param userAgent HTTP user agent.
     * @return true if the file was downloaded, otherwise false.
     */
    bool downloadFile(const std::filesystem::path& inputFileURL,
                      const std::filesystem::path& outputFilepath,
                      const std::string& userAgent) const
    {
        auto returnCode {true};
        const auto onError {
            [&returnCode](const std::string& errorMessage, const long errorCode)
            {
                logWarn(WM_CONTENTUPDATER, "Error '%d' when downloading file: %s.", errorCode, errorMessage.c_str());
                returnCode = false;
            }};

        // Download file from URL.
        logDebug2(WM_CONTENTUPDATER,
                  "Downloading file from '%s' into '%s'",
                  inputFileURL.string().c_str(),
                  outputFilepath.string().c_str());
        m_urlRequest.download(HttpURL(inputFileURL), outputFilepath, onError, {}, {}, userAgent);
        return returnCode;
    }

    /**
     * @brief Downloads a file in offline mode and updates the context accordingly.
     *
     * @param context Updater context.
     */
    void download(UpdaterContext& context) const
    {
        constexpr auto FILE_PREFIX {"file://"};
        constexpr auto HTTP_PREFIX {"http://"};
        constexpr auto HTTPS_PREFIX {"https://"};

        // Remote or local file URL.
        const std::filesystem::path fileUrl {
            context.spUpdaterBaseContext->configData.at("url").get_ref<const std::string&>()};

        // Check input filename existence.
        if (!fileUrl.has_filename())
        {
            throw std::runtime_error {"Couldn't get filename from URL: " + fileUrl.string()};
        }

        // Generate output file path. If the input file is compressed, the output file will be in the downloads
        // folder and if it's not compressed, in the contents folder.
        const auto compressed {
            "raw" != context.spUpdaterBaseContext->configData.at("compressionType").get_ref<const std::string&>()};
        auto outputFilePath {compressed ? context.spUpdaterBaseContext->downloadsFolder
                                        : context.spUpdaterBaseContext->contentsFolder};
        outputFilePath = outputFilePath / fileUrl.filename();

        if (Utils::startsWith(fileUrl, FILE_PREFIX))
        {
            if (!copyFile(fileUrl, outputFilePath))
            {
                return;
            }
        }
        else if (Utils::startsWith(fileUrl, HTTP_PREFIX) || Utils::startsWith(fileUrl, HTTPS_PREFIX))
        {
            if (!downloadFile(fileUrl, outputFilePath, context.spUpdaterBaseContext->httpUserAgent))
            {
                return;
            }
        }
        else
        {
            throw std::runtime_error {"Unknown URL prefix for " + fileUrl.string()};
        }

        // Just process the new file if the hash is different from the last one.
        auto inputFileHash {Utils::asciiToHex(Utils::hashFile(outputFilePath))};
        if (context.spUpdaterBaseContext->downloadedFileHash != inputFileHash)
        {
            // Download finished: Insert path into context.
            context.data.at("paths").push_back(outputFilePath.string());
            context.data["fileMetadata"]["hash"] = std::move(inputFileHash);
            return;
        }

        logDebug2(WM_CONTENTUPDATER,
                  "File '%s' didn't change from last download so it won't be published",
                  outputFilePath.string().c_str());
    }

public:
    /**
     * @brief Class constructor.
     *
     * @param urlRequest HTTP driver instance to use within the class.
     */
    explicit OfflineDownloader(IURLRequest& urlRequest)
        : m_urlRequest(urlRequest) {};

    /**
     * @brief Downloads a file in offline mode in order to be processed and passes the control to the next chain
     * stage.
     *
     * @param context Updater context.
     * @return std::shared_ptr<UpdaterContext> Next step of the chain.
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "OfflineDownloader - Starting process");
        constexpr auto COMPONENT_NAME {"OfflineDownloader"};

        try
        {
            download(*context);
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

#endif // _OFFLINE_DOWNLOADER_HPP
