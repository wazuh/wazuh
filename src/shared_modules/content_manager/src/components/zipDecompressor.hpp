/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * November 03, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ZIP_DECOMPRESSOR_HPP
#define _ZIP_DECOMPRESSOR_HPP

#include "../sharedDefs.hpp"
#include "json.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "utils/zlibHelper.hpp"
#include <filesystem>
#include <iterator>
#include <memory>
#include <string>
#include <utility>
#include <vector>

/**
 * @class ZipDecompressor
 *
 * @brief Class in charge of decompressing the content in ZIP format as a step of a chain of responsibility.
 *
 */
class ZipDecompressor final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Pushes the state of the current stage into the data field of the context.
     *
     * @param contextData Reference to the context data.
     * @param status Status to be pushed.
     */
    void pushStageStatus(nlohmann::json& contextData, const std::string& status) const
    {
        auto statusObject = nlohmann::json::object();
        statusObject["stage"] = "ZipDecompressor";
        statusObject["status"] = status;

        contextData.at("stageStatus").push_back(std::move(statusObject));
    }

    /**
     * @brief Decompress the compressed content and update the context paths.
     *
     * @param context Updater context.
     */
    void decompress(UpdaterContext& context) const
    {
        const auto& outputFolder {context.spUpdaterBaseContext->outputFolder / CONTENTS_FOLDER};
        std::vector<std::string> newPaths;

        for (const auto& path : context.data.at("paths"))
        {
            logDebug2(WM_CONTENTUPDATER,
                      "Decompressing '%s' into '%s'",
                      path.get_ref<const std::string&>().c_str(),
                      outputFolder.string().c_str());

            // Decompress and move paths.
            auto decompressedFiles {Utils::ZlibHelper::zipDecompress(path, outputFolder)};
            newPaths.insert(newPaths.end(),
                            std::make_move_iterator(decompressedFiles.begin()),
                            std::make_move_iterator(decompressedFiles.end()));
        }

        // Decompression finished: Update paths.
        context.data["paths"] = std::move(newPaths);
    }

public:
    /**
     * @brief Decompress the ZIP content and passes the control to the next step on the chain.
     *
     * @param context Updater context.
     * @return std::shared_ptr<UpdaterContext> Next step on the chain.
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "ZipDecompressor - Starting process");

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

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _ZIP_DECOMPRESSOR_HPP
