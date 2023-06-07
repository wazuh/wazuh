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

#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <iostream>
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
        const std::string outputFolder {context.spUpdaterBaseContext->outputFolder};
        const auto fileName {context.spUpdaterBaseContext->configData.at("fileName").get<std::string>()};

        // TODO implement behavior
        // 1. Decompress the content (outputFolder + fileName)
        // 2. Save the decompressed content in the context (context.data)
        std::ignore = outputFolder;
        std::ignore = fileName;
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

        decompress(*context);

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(context);
    }
};

#endif // _XZ_DECOMPRESSOR_HPP
