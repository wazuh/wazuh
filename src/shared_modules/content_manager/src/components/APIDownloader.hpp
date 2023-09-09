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
#ifndef _API_DOWNLOADER_HPP
#define _API_DOWNLOADER_HPP

#include "http-request/include/HTTPRequest.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <iostream>
#include <memory>

/**
 * @class APIDownloader
 *
 * @brief Class in charge of downloading the content from the API as a step of a chain of responsibility.
 *
 */
class APIDownloader final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Download the content from the API.
     *
     * @param context updater context.
     */
    void download(UpdaterContext& context) const
    {
        // URL of the API to connect to.
        const auto url {context.spUpdaterBaseContext->configData.at("url").get<std::string>()};
        // output folder where the file will be saved
        std::string outputFolder {context.spUpdaterBaseContext->downloadsFolder};
        if (context.spUpdaterBaseContext->configData.at("compressionType").get<std::string>().compare("raw") == 0)
        {
            outputFolder = context.spUpdaterBaseContext->contentsFolder;
        }
        // name of the file where the content will be saved
        const auto fileName {context.spUpdaterBaseContext->configData.at("contentFileName").get<std::string>()};
        // full path where the content will be saved
        const std::string fullFilePath {outputFolder + "/" + fileName};

        const auto onError {
            [&context](const std::string& message, const long /*statusCode*/)
            {
                std::cout << "APIDownloader - Could not get response from API because: " << message << std::endl;
                // Set the status of the stage
                context.data.at("stageStatus").push_back(R"({"stage": "APIDownloader", "status": "fail"})"_json);
                throw std::runtime_error(message);
            }};

        // Run the request. Save the file on disk.
        HTTPRequest::instance().download(HttpURL(url), fullFilePath, onError);

        // Save the path of the downloaded content in the context
        context.data.at("paths").push_back(fullFilePath);

        // Set the status of the stage
        context.data.at("stageStatus").push_back(R"({"stage": "APIDownloader", "status": "ok"})"_json);

        std::cout << "APIDownloader - Download done successfully" << std::endl;
    }

public:
    /**
     * @brief Download the content from the API.
     *
     * @param context updater context.
     * @return std::shared_ptr<UpdaterContext>
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        download(*context);

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _API_DOWNLOADER_HPP
