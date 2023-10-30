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

#ifndef _FACTORY_DOWNLOADER_HPP
#define _FACTORY_DOWNLOADER_HPP

#include "APIDownloader.hpp"
#include "CtiApiDownloader.hpp"
#include "HTTPRequest.hpp"
#include "S3Downloader.hpp"
#include "json.hpp"
#include "offlineDownloader.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <string>

/**
 * @class FactoryDownloader
 *
 * @brief Class in charge of creating the content downloader.
 *
 */
class FactoryDownloader final
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
        const std::map<std::string, std::string> COMPRESSED_EXTENSIONS {{".gz", "gzip"}, {".xz", "xz"}};
        const auto& fileExtension {std::filesystem::path(inputFile).extension()};

        if (const auto& it {COMPRESSED_EXTENSIONS.find(fileExtension)}; it != COMPRESSED_EXTENSIONS.end())
        {
            return it->second;
        }

        return "raw";
    }

public:
    /**
     * @brief Create the content downloader based on the contentSource value.
     *
     * @param config Configurations.
     * @return std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>>
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> create(nlohmann::json& config)
    {
        auto const downloaderType {config.at("contentSource").get<std::string>()};
        std::cout << "Creating '" << downloaderType << "' downloader" << std::endl;

        if (downloaderType.compare("api") == 0)
        {
            return std::make_shared<APIDownloader>(HTTPRequest::instance());
        }
        if (downloaderType.compare("cti-api") == 0)
        {
            return std::make_shared<CtiApiDownloader>(HTTPRequest::instance());
        }
        if (downloaderType.compare("s3") == 0)
        {
            return std::make_shared<S3Downloader>();
        }
        if ("offline" == downloaderType)
        {
            // When using an offline downloader, the compression type is automatically deduced.
            config["compressionType"] = deduceCompressionType(config.at("url").get_ref<const std::string&>());
            return std::make_shared<OfflineDownloader>();
        }
        else
        {
            throw std::invalid_argument {"Invalid 'contentSource' type: " + downloaderType};
        }
    }
};

#endif // _FACTORY_DOWNLOADER_HPP
