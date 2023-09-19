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

#ifndef _S3_DOWNLOADER_HPP
#define _S3_DOWNLOADER_HPP

#include "http-request/include/HTTPRequest.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <iostream>
#include <memory>

/**
 * @class S3Downloader
 *
 * @brief Class in charge of downloading the content from the S3 bucket as a step of a chain of responsibility.
 *
 */
class S3Downloader final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    /**
     * @brief Download the content from the S3 bucket.
     *
     * @param context updater context.
     */
    void download(UpdaterContext& context) const
    {
        // URL of the S3 bucket to connect to.
        const auto url {context.spUpdaterBaseContext->configData.at("url").get<std::string>()};
        // output folder where the file will be saved
        std::string outputFolder {context.spUpdaterBaseContext->downloadsFolder};
        if (context.spUpdaterBaseContext->configData.at("compressionType").get<std::string>().compare("raw") == 0)
        {
            outputFolder = context.spUpdaterBaseContext->contentsFolder;
        }
        // name of the file where the content will be saved
        const auto fileName {context.spUpdaterBaseContext->configData.at("s3FileName").get<std::string>()};
        // full path where the content will be saved
        const std::string fullFilePath {outputFolder + "/" + fileName};

        const auto onError {
            [&context](const std::string& message, const long /*statusCode*/)
            {
                // Set the status of the stage
                context.data.at("stageStatus").push_back(R"({"stage": "S3Downloader", "status": "fail"})"_json);

                throw std::runtime_error("S3Downloader - Could not get response from S3 because: " + message);
            }};

        // Run the request. Save the file on disk.
        HTTPRequest::instance().download(HttpURL(url + fileName), fullFilePath, onError);

        // Save the path of the downloaded content in the context
        context.data.at("paths").push_back(fullFilePath);

        // Set the status of the stage
        context.data.at("stageStatus").push_back(R"({"stage": "S3Downloader", "status": "ok"})"_json);

        std::cout << "S3Downloader - Download done successfully" << std::endl;
    }

public:
    /**
     * @brief Download the content from the S3 bucket.
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

#endif // _S3_DOWNLOADER_HPP
