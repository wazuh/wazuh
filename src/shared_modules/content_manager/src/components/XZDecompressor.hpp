/*
 * Wazuh Content Manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 02, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _XZ_DECOMPRESSOR_HPP
#define _XZ_DECOMPRESSOR_HPP

#include "../sharedDefs.hpp"
#include "componentsHelper.hpp"
#include "json.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "utils/stringHelper.h"
#include "utils/xzHelper.hpp"
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

/**
 * @class XZDecompressor
 *
 * @brief Class in charge of decompressing the content as a step of a chain of responsibility.
 *
 */
class XZDecompressor final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Decompress the content and save it in the context.
     *
     * @param context updater context.
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
            // '/tmp/output/downloads/file.json.xz', the new path will be '/tmp/output/contents/file.json.xz'.
            const auto& outputFolder {context.spUpdaterBaseContext->outputFolder};
            Utils::replaceFirst(
                outputPath, (outputFolder / DOWNLOAD_FOLDER).string(), (outputFolder / CONTENTS_FOLDER).string());

            // Remove .xz extension.
            outputPath = Utils::rightTrim(outputPath, inputPath.extension());

            // Decompress.
            logDebug2(
                WM_CONTENTUPDATER, "Decompressing '%s' into '%s'", inputPath.string().c_str(), outputPath.c_str());
            Utils::XzHelper(inputPath, outputPath).decompress();

            // Decompression finished: Update context path.
            path = std::move(outputPath);
        }
    }

public:
    /**
     * @brief Decompress the content.
     *
     * @param context updater context.
     * @return std::shared_ptr<UpdaterContext>
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "XZDecompressor - Starting process");
        constexpr auto COMPONENT_NAME {"XZDecompressor"};

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

#endif // _XZ_DECOMPRESSOR_HPP
