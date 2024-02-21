/*
 * Wazuh Content Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 30, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CTI_SNAPSHOT_DOWNLOADER_HPP
#define _CTI_SNAPSHOT_DOWNLOADER_HPP

#include "../sharedDefs.hpp"
#include "CtiDownloader.hpp"
#include "IURLRequest.hpp"
#include "updaterContext.hpp"
#include <filesystem>
#include <string>

/**
 * @class CtiSnapshotDownloader
 *
 * @brief Class in charge of downloading a content snapshot from the CTI API as a step of a chain of responsibility.
 *
 */
class CtiSnapshotDownloader final : public CtiDownloader
{
private:
    /**
     * @brief Download the content from the API.
     *
     * @param context Updater context.
     */
    void download(UpdaterContext& context) override
    {
        const auto& baseURL {context.spUpdaterBaseContext->configData.at("url").get_ref<const std::string&>()};

        // Get and use the CTI base parameters.
        const auto baseParameters {getCtiBaseParameters(baseURL)};

        if (!baseParameters.lastSnapshotLink.has_value() || !baseParameters.lastSnapshotOffset.has_value())
        {
            throw std::runtime_error {"Can't download snapshot due to missing CTI metadata"};
        }

        const auto lastSnapshotURL {std::filesystem::path(baseParameters.lastSnapshotLink.value())};
        context.currentOffset = baseParameters.lastSnapshotOffset.value();

        // Set output path. The snapshot is always compressed, so the output folder is the downloads folder.
        const auto outputFilepath {context.spUpdaterBaseContext->downloadsFolder / lastSnapshotURL.filename()};

        // On success routine. Append output file path to the to-publish paths.
        const auto onSuccess {[&context, outputFilepath]([[maybe_unused]] const std::string& data)
                              {
                                  context.data.at("paths").push_back(outputFilepath);
                                  context.data.at("offset") = context.currentOffset;
                              }};

        logDebug2(WM_CONTENTUPDATER, "Downloading snapshot from '%s'", lastSnapshotURL.string().c_str());

        // Download the content.
        performQueryWithRetry(lastSnapshotURL, onSuccess, "", outputFilepath);
    }

public:
    /**
     * @brief Class constructor.
     *
     * @param urlRequest Object to perform the HTTP requests to the CTI API.
     */
    explicit CtiSnapshotDownloader(IURLRequest& urlRequest)
        : CtiDownloader(urlRequest, "CtiSnapshotDownloader")
    {
    }
};

#endif // _CTI_SNAPSHOT_DOWNLOADER_HPP
