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

#include "../sharedDefs.hpp"
#include "componentsHelper.hpp"
#include "json.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "utils/stringHelper.h"
#include "utils/zlibHelper.hpp"
#include <filesystem>
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
     * @brief Decompress the compressed content and update the context paths.
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
            // For example, for an output folder equal to '/tmp/output' and a path equal to
            // '/tmp/output/downloads/file.json.gz', the new path will be '/tmp/output/contents/file.json.gz'.
            const auto& outputFolder {context.spUpdaterBaseContext->outputFolder};
            Utils::replaceFirst(
                outputPath, (outputFolder / DOWNLOAD_FOLDER).string(), (outputFolder / CONTENTS_FOLDER).string());

            // Remove .gz extension.
            outputPath = Utils::rightTrim(outputPath, inputPath.extension());

            // Decompress.
            logDebug2(
                WM_CONTENTUPDATER, "Decompressing '%s' into '%s'", inputPath.string().c_str(), outputPath.c_str());
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
        logDebug1(WM_CONTENTUPDATER, "GzipDecompressor - Starting process");
        constexpr auto COMPONENT_NAME {"GzipDecompressor"};

        try
        {
            decompress(*context);
        }
        catch (const std::exception& e)
        {
            // Push error state.
            Components::pushStatus(COMPONENT_NAME, Components::Status::STATUS_FAIL, *context);

            throw std::runtime_error("Decompression failed: " + std::string(e.what()));
        }

        // Push success state.
        Components::pushStatus(COMPONENT_NAME, Components::Status::STATUS_OK, *context);

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
    }
};

#endif // _GZIP_DECOMPRESSOR_HPP
