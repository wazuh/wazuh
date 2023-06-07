/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 23, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EXECUTION_CONTEXT_HPP
#define _EXECUTION_CONTEXT_HPP

#include "chainOfResponsability.hpp"
#include "updaterContext.hpp"
#include <filesystem>

const std::string GENERIC_OUTPUT_FOLDER_PATH {std::filesystem::temp_directory_path() / "output_folder"};

/**
 * @class ExecutionContext
 *
 * @brief Prepares the execution context as a step of a chain of responsibility.
 *
 */
class ExecutionContext final : public AbstractHandler<std::shared_ptr<UpdaterBaseContext>>
{
private:
    /**
     * @brief Creates the folder that are needed by the tool in order to be executed.
     *
     * @param context updater base context.
     */
    void createOutputFolder(UpdaterBaseContext& context) const
    {

        // Check if the output folder path is given and not empty.
        if (context.configData.contains("outputFolder") &&
            !context.configData.at("outputFolder").get<std::string>().empty())
        {
            // set the output folder path to the given value
            context.outputFolder = context.configData.at("outputFolder").get<std::string>();
        }
        else
        {
            // set the output folder path to the default value.
            context.outputFolder = GENERIC_OUTPUT_FOLDER_PATH;
        }

        auto const& outputFolderPath = context.outputFolder;

        // check if the output folder exists.
        if (std::filesystem::exists(outputFolderPath))
        {
            // Delete the output folder to avoid conflicts.
            std::filesystem::remove_all(outputFolderPath);
        }

        // Create the output folder.
        std::filesystem::create_directory(outputFolderPath);

        std::cout << "Created output folder: " << outputFolderPath << std::endl;
    }

public:
    /**
     * @brief Prepare the execution context necessary to execute the orchestration.
     *
     * @param context updater base context.
     * @return std::shared_ptr<UpdaterBaseContext>
     */
    std::shared_ptr<UpdaterBaseContext> handleRequest(std::shared_ptr<UpdaterBaseContext> context) override
    {

        createOutputFolder(*context);

        return AbstractHandler<std::shared_ptr<UpdaterBaseContext>>::handleRequest(context);
    }
};

#endif // _EXECUTION_CONTEXT_HPP
