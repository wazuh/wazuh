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

        auto url {context.spUpdaterBaseContext->configData.at("url").get<std::string>()};
        std::filesystem::path inputFilePath;
        auto httpDownload {false};

        if (Utils::startsWith(url, FILE_PREFIX))
        {
            // Use the URL as a path to a file within the filesystem.
            Utils::replaceFirst(url, FILE_PREFIX, "");
            inputFilePath = url;

            // Check input file existence.
            if (!std::filesystem::exists(inputFilePath))
            {
                logWarn(
                    WM_CONTENTUPDATER, "File '%s' doesn't exist. Skipping download.", inputFilePath.string().c_str());
                return;
            }
        }
        else if (Utils::startsWith(url, HTTP_PREFIX) || Utils::startsWith(url, HTTPS_PREFIX))
        {
            const auto onError {[](const std::string& errorMessage, const long errorCode)
                                {
                                    throw std::runtime_error {"(" + std::to_string(errorCode) + ") " + errorMessage};
                                }};

            const std::filesystem::path pathURL {url};
            if (!pathURL.has_filename())
            {
                throw std::runtime_error {"Couldn't get filename from URL: " + url};
            }

            inputFilePath = std::filesystem::temp_directory_path() / pathURL.filename();
            httpDownload = true;

            // Download file from URL and store in a temporary directory.
            m_urlRequest.download(HttpURL(url), inputFilePath, onError);
        }
        else
        {
            throw std::runtime_error {"Unkown URL prefix for " + url};
        }

        // Process input file hash.
        auto inputFileHash {hashFile(inputFilePath)};

        // Just process the new file if the hash is different from the last one.
        if (context.spUpdaterBaseContext->downloadedFileHash != inputFileHash)
        {
            // Check if file is compressed.
            const auto compressed {
                "raw" != context.spUpdaterBaseContext->configData.at("compressionType").get_ref<const std::string&>()};

            // Generate output file path. If the input file is compressed, the output file will be in the downloads
            // folder and if it's not compressed, in the contents folder.
            auto outputFilePath {compressed ? context.spUpdaterBaseContext->downloadsFolder
                                            : context.spUpdaterBaseContext->contentsFolder};
            outputFilePath = outputFilePath / inputFilePath.filename();

            if (httpDownload)
            {
                // Move downloaded file.
                std::filesystem::rename(inputFilePath, outputFilePath);
            }
            else
            {
                // Copy file, overriding the output one if necessary.
                std::filesystem::copy(inputFilePath, outputFilePath, std::filesystem::copy_options::overwrite_existing);
            }

            // Store new hash.
            context.spUpdaterBaseContext->downloadedFileHash = std::move(inputFileHash);

            // Download finished: Insert path into context.
            context.data.at("paths").push_back(outputFilePath.string());
            return;
        }

        if (httpDownload)
        {
            // Remove temporary downloaded file.
            std::filesystem::remove(inputFilePath);
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
