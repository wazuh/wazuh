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
    void download(const UpdaterContext& context) const
    {
        const auto url {context.spUpdaterBaseContext->configData.at("url").get<std::string>()};

        // TODO implement behavior
        // 1. Connect to the S3 bucket using the url
        // 2. Download the content
        // 2.1 If the content is compressed, save it in the output folder (context.spUpdaterBaseContext->outputFolder)
        // 2.2 If the content is not compressed, save it in the context (context.data)
        std::ignore = url;
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
