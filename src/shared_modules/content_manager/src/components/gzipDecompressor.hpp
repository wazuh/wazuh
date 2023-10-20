/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * October 20, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _GZIP_DECOMPRESSOR_HPP
#define _GZIP_DECOMPRESSOR_HPP

#include "json.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "utils/stringHelper.h"
#include "utils/zlibHelper.hpp"
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

/**
 * @class GzipDecompressor
 *
 * @brief Class in charge of decompressing the content in GZ format as a step of a chain of responsibility.
 *
 */
class GzipDecompressor final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Pushes the state of the current stage into the data field of the context.
     *
     * @param contextData Reference to the context data.
     * @param status Status to be pushed.
     */
    void pushStageStatus(nlohmann::json& contextData, std::string status) const
    {
        auto statusObject = R"(
            { 
                "stage": "GzipDecompressor",
                "status": "n/a"
            }
        )"_json;
        statusObject.at("status") = std::move(status);

        contextData.at("stageStatus").push_back(std::move(statusObject));
    }

    /**
     * @brief Decompress the compresesd content and update the context paths.
     *
     * @param context Updater context.
     */
    void decompress(UpdaterContext& context) const
    {
        for (auto& path : context.data.at("paths"))
        {
            // Copy input path.
            std::filesystem::path inputPath {path};
            auto outputPath {path.get<std::string>()};

            // Replace downloads folder for contents folder.
            const auto& outputFolder {context.spUpdaterBaseContext->outputFolder};
            Utils::replaceFirst(
                outputPath, (outputFolder / DOWNLOAD_FOLDER).string(), (outputFolder / CONTENTS_FOLDER).string());

            // Remove .gz extension.
            outputPath = Utils::rightTrim(path, inputPath.extension());

            // Decompress.
            Utils::ZlibHelper::gzipDecompress(inputPath, outputPath);

            // Decompression finished: Update context path.
            path = std::move(outputPath);
        }
    }

public:
    /**
     * @brief Decompress the GZ content and passes the control to the next step on the chain.
     *
     * @param context Updater context.
     * @return std::shared_ptr<UpdaterContext> Next step on the chain.
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        try
        {
            decompress(*context);
        }
        catch (const std::exception& e)
        {
            // Push error state.
            pushStageStatus(context->data, "fail");

            throw std::runtime_error("Decompression failed: " + std::string(e.what()));
        }

        // Push success state.
        pushStageStatus(context->data, "ok");

        std::cout << "GzipDecompressor - Finishing process" << std::endl;

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _GZIP_DECOMPRESSOR_HPP
