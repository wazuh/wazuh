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

#ifndef _CLEAN_UP_CONTENT_HPP
#define _CLEAN_UP_CONTENT_HPP

#include "../sharedDefs.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <filesystem>
#include <memory>

/**
 * @class CleanUpContent
 *
 * @brief Class in charge of deleting all files located in the output folder as a step of a chain of responsibility.
 *
 */
class CleanUpContent final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Deletes all files in the output folder.
     *
     * @param context updater context.
     */
    void cleanUp(const UpdaterContext& context) const
    {
        // Get the path to the folder.
        const auto& path = context.spUpdaterBaseContext->downloadsFolder;

        // Check if the path exists.
        if (!std::filesystem::exists(path))
        {
            logWarn(WM_CONTENTUPDATER, "The path does not exist: %s.", path.string().c_str());
            return;
        }

        // Delete the folder.
        std::filesystem::remove_all(path);

        // Create the folder again.
        std::filesystem::create_directory(path);
    }

public:
    /**
     * @brief Deletes all files in the output folder.
     *
     * @param context updater context.
     * @return std::shared_ptr<UpdaterContext>
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "CleanUpContent - Starting process");

        cleanUp(*context);

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
    }
};

#endif // _CLEAN_UP_CONTENT_HPP
