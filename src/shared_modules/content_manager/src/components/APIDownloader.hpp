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

#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "wazuh-http-request/include/HTTPRequest.hpp"
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
        const auto url {context.spUpdaterBaseContext->configData.at("url").get<std::string>()};

        const auto onError {[](const std::string& message)
                            {
                                std::cout << "APIDownloader - Could not get response from API because: " << message
                                          << std::endl;
                                throw std::runtime_error(message);
                            }};

        std::function<void(std::string_view)> onSuccess {[](std::string_view) { /* Do nothing */ }};

        std::string filePath {};

        // check if the content is not compressed.
        if (context.spUpdaterBaseContext->configData.at("compressionType").get<std::string>().compare("raw") == 0)
        {
            // save the raw content in the context
            onSuccess = [&context](std::string_view data)
            {
                context.data = std::vector<char>(data.begin(), data.end());
            };
        }
        else
        {
            // define the file path to save the content on disk.
            filePath = static_cast<std::string>(context.spUpdaterBaseContext->outputFolder) + "/" +
                       context.spUpdaterBaseContext->configData.at("fileName").get<std::string>();
        }

        // Run the request.
        HTTPRequest::instance().get(HttpURL(url), onSuccess, onError, filePath);

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
