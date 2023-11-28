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

#ifndef _XZ_DECOMPRESSOR_HPP
#define _XZ_DECOMPRESSOR_HPP

#include "../sharedDefs.hpp"
#include "json.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "utils/stringHelper.h"
#include "utils/xzHelper.hpp"
#include <memory>

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
            logDebug2(WM_CONTENTUPDATER, "Attempting to decompress '%s'", path.get_ref<const std::string&>().c_str());

            std::filesystem::path inputPath {path};
            try
            {
                // Update the output folder and file name, and update the path in the context.
                // Ex: assumings compressionType = xz and dataFormat = json
                // from: /tmp/output_folder/downloads/file.xz
                // to: /tmp/output_folder/contents/file.json
                Utils::replaceAll(path.get_ref<std::string&>(), DOWNLOAD_FOLDER, CONTENTS_FOLDER);
                Utils::replaceAll(path.get_ref<std::string&>(),
                                  context.spUpdaterBaseContext->configData.at("compressionType").get<std::string>(),
                                  context.spUpdaterBaseContext->configData.at("dataFormat").get<std::string>());
                std::filesystem::path outputPath {path};

                Utils::XzHelper(inputPath, outputPath).decompress();
            }
            catch (const std::exception& e)
            {
                // Set the status of the stage
                context.data.at("stageStatus").push_back(R"({"stage": "XZDecompressor", "status": "fail"})"_json);

                throw std::runtime_error("XZDecompressor - Could not decompress the file " + inputPath.string() +
                                         " because: " + e.what());
            }
        }
        context.data.at("stageStatus").push_back(R"({"stage": "XZDecompressor", "status": "ok"})"_json);
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

        decompress(*context);

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _XZ_DECOMPRESSOR_HPP
