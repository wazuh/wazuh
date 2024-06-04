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

#include "../sharedDefs.hpp"
#include "XZDecompressor.hpp"
#include "gzipDecompressor.hpp"
#include "skipStep.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "zipDecompressor.hpp"
#include <filesystem>
#include <map>
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
private:
    /**
     * @brief Deduces and returns the compression type given an input file extension.
     *
     * @param inputFile Input file whose compression type will be deduced.
     * @return std::string Compression type.
     */
    static std::string deduceCompressionType(const std::string& inputFile)
    {
        const std::map<std::string, std::string> COMPRESSED_EXTENSIONS {
            {".gz", "gzip"}, {".xz", "xz"}, {".zip", "zip"}};
        const auto& fileExtension {std::filesystem::path(inputFile).extension()};

        if (const auto& it {COMPRESSED_EXTENSIONS.find(fileExtension)}; it != COMPRESSED_EXTENSIONS.end())
        {
            return it->second;
        }

        return "raw";
    }

public:
    /**
     * @brief Creates a content decompressor based on the compressorType value.
     *
     * @param config Configurations.
     * @return std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>>
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> create(nlohmann::json& config)
    {
        auto& decompressorType {config.at("compressionType").get_ref<std::string&>()};

        if ("offline" == config.at("contentSource").get_ref<const std::string&>())
        {
            // When using an offline downloader, the compression type is automatically deduced.
            decompressorType = deduceCompressionType(config.at("url").get_ref<const std::string&>());
        }

        logDebug1(WM_CONTENTUPDATER, "Creating '%s' decompressor", decompressorType.c_str());

        if ("xz" == decompressorType)
        {
            return std::make_shared<XZDecompressor>();
        }

        if ("gzip" == decompressorType)
        {
            return std::make_shared<GzipDecompressor>();
        }

        if ("zip" == decompressorType)
        {
            return std::make_shared<ZipDecompressor>();
        }

        if ("raw" == decompressorType)
        {
            return std::make_shared<SkipStep>();
        }

        throw std::invalid_argument {"Invalid 'compressionType': " + decompressorType};
    }
};

#endif // _FACTORY_DECOMPRESSOR_HPP
