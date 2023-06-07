/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * April 14, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_DECOMPRESSOR_HPP
#define _FACTORY_DECOMPRESSOR_HPP

#include "XZDecompressor.hpp"
#include "skipStep.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <memory>
#include <string>

/**
 * @class FactoryDecompressor
 *
 * @brief Class in charge of creating a content decompressor.
 *
 */
class FactoryDecompressor final
{
public:
    /**
     * @brief Creates a content decompressor based on the compressorType value.
     *
     * @param config Configurations.
     * @return std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>>
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> create(const nlohmann::json& config)
    {

        auto const decompressorType {config.at("compressionType").get<std::string>()};

        if (decompressorType.compare("xz") == 0)
        {
            std::cout << "Creating '" << decompressorType << "' content decompressor" << std::endl;
            return std::make_shared<XZDecompressor>();
        }
        if (decompressorType.compare("raw") == 0)
        {
            std::cout << "Content decompressor not needed" << std::endl;
            return std::make_shared<SkipStep>();
        }
        else
        {
            throw std::invalid_argument {"Invalid 'compressionType': " + decompressorType};
        }
    }
};

#endif // _FACTORY_DECOMPRESSOR_HPP
