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

#include "../sharedDefs.hpp"
#include "APIDownloader.hpp"
#include "CtiOffsetDownloader.hpp"
#include "CtiSnapshotDownloader.hpp"
#include "HTTPRequest.hpp"
#include "fileDownloader.hpp"
#include "json.hpp"
#include "offlineDownloader.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
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
public:
    /**
     * @brief Create the content downloader based on the contentSource value.
     *
     * @param config Configurations.
     * @return std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>>
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> create(const nlohmann::json& config)
    {
        const auto& downloaderType {config.at("contentSource").get_ref<const std::string&>()};
        logDebug1(WM_CONTENTUPDATER, "Creating '%s' downloader", downloaderType.c_str());

        if ("api" == downloaderType)
        {
            return std::make_shared<APIDownloader>(HTTPRequest::instance());
        }
        if ("cti-offset" == downloaderType)
        {
            return std::make_shared<CtiOffsetDownloader>(HTTPRequest::instance());
        }
        if ("cti-snapshot" == downloaderType)
        {
            return std::make_shared<CtiSnapshotDownloader>(HTTPRequest::instance());
        }
        if ("file" == downloaderType)
        {
            return std::make_shared<FileDownloader>();
        }
        if ("offline" == downloaderType)
        {
            return std::make_shared<OfflineDownloader>(HTTPRequest::instance());
        }

        throw std::invalid_argument {"Invalid 'contentSource' type: " + downloaderType};
    }
};

#endif // _FACTORY_DOWNLOADER_HPP
