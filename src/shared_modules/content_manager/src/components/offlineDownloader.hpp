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
#include "hashHelper.h"
#include "json.hpp"
#include "stringHelper.h"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

/**
 * @class OfflineDownloader
 *
 * @brief Class in charge of copying a file from the filesystem and update the context accordingly, as a step of a chain
 * of responsibility.
 *
 */
class OfflineDownloader final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    IURLRequest& m_urlRequest; ///< HTTP driver instance.

    /**
     * @brief Pushes the state of the current stage into the data field of the context.
     *
     * @param contextData Reference to the context data.
     * @param status Status to be pushed.
     */
    void pushStageStatus(nlohmann::json& contextData, std::string status) const
    {
        auto statusObject = nlohmann::json::object();
        statusObject["stage"] = "OfflineDownloader";
        statusObject["status"] = std::move(status);

        contextData.at("stageStatus").push_back(std::move(statusObject));
    }

    /**
     * @brief Function to calculate the hash of a file.
     *
     * @param filepath Path to the file.
     * @return std::string Digest vector.
     */
    std::string hashFile(const std::filesystem::path& filepath) const
    {
        if (std::ifstream inputFile(filepath, std::fstream::in); inputFile)
        {
            constexpr int BUFFER_SIZE {4096};
            std::array<char, BUFFER_SIZE> buffer {};

            Utils::HashData hash;
            while (inputFile.read(buffer.data(), buffer.size()))
            {
                hash.update(buffer.data(), inputFile.gcount());
            }
            hash.update(buffer.data(), inputFile.gcount());

            return Utils::asciiToHex(hash.hash());
        }

        // LCOV_EXCL_START
        throw std::runtime_error {"Unable to open '" + filepath.string() + "' for hashing."};
        // LCOV_EXCL_STOP
    };

    /**
     * @brief Downloads the requested local file and update the context accordingly.
     *
     * @note Despite the method name, there is no such download since the file is present in the filesystem.
     *
     * @param context Updater context.
     */
    void download(UpdaterContext& context) const
    {
        constexpr auto FILE_PREFIX {"file://"};
        constexpr auto HTTP_PREFIX {"http://"};
        constexpr auto HTTPS_PREFIX {"https://"};

        // Remote or local file URL.
        std::filesystem::path fileUrl {
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

        auto httpDownload {false}; // Flag that indicates if the download is made from an HTTP server.
        if (Utils::startsWith(fileUrl, FILE_PREFIX))
        {
            // Remove file prefix.
            auto unprefixedUrl {fileUrl.string()};
            Utils::replaceFirst(unprefixedUrl, FILE_PREFIX, "");
            fileUrl = std::filesystem::path(unprefixedUrl);

            // Check input file existence.
            if (!std::filesystem::exists(fileUrl))
            {
                logWarn(
                    WM_CONTENTUPDATER, "File '%s' doesn't exist. Skipping download.", inputFilePath.string().c_str());
                return;
            }
        }
        else if (Utils::startsWith(fileUrl, HTTP_PREFIX) || Utils::startsWith(fileUrl, HTTPS_PREFIX))
        {
            const auto onError {[](const std::string& errorMessage, const long errorCode)
                                {
                                    throw std::runtime_error {"(" + std::to_string(errorCode) + ") " + errorMessage};
                                }};

            // Download file from URL.
            m_urlRequest.download(HttpURL(fileUrl), outputFilePath, onError);
            httpDownload = true;
        }
        else
        {
            throw std::runtime_error {"Unkown URL prefix for " + fileUrl.string()};
        }

        // Process input file hash.
        const auto inputFile {httpDownload ? outputFilePath : fileUrl};
        auto inputFileHash {hashFile(inputFile)};

        // Just process the new file if the hash is different from the last one.
        if (context.spUpdaterBaseContext->downloadedFileHash != inputFileHash)
        {
            if (!httpDownload)
            {
                // Copy file, overriding the output one if necessary.
                std::filesystem::copy(fileUrl, outputFilePath, std::filesystem::copy_options::overwrite_existing);
            }

            // Store new hash.
            context.spUpdaterBaseContext->downloadedFileHash = std::move(inputFileHash);

            // Download finished: Insert path into context.
            context.data.at("paths").push_back(outputFilePath.string());
        }
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
     * @brief Copies a file from the local filesystem in order to be processed and passes the control to the next chain
     * stage.
     *
     * @param context Updater context.
     * @return std::shared_ptr<UpdaterContext> Next step of the chain.
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        try
        {
            download(*context);
        }
        catch (const std::exception& e)
        {
            // Push error state.
            pushStageStatus(context->data, "fail");

            throw std::runtime_error("Download failed: " + std::string(e.what()));
        }

        // Push success state.
        pushStageStatus(context->data, "ok");

        logDebug2(WM_CONTENTUPDATER, "OfflineDownloader - Download done successfully");

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _OFFLINE_DOWNLOADER_HPP
