/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 12, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_CONTENT_UPDATER_HPP
#define _FACTORY_CONTENT_UPDATER_HPP

#include "IndexerDownloader.hpp"
#include "sharedDefs.hpp"
#include "updateIndexerCursor.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <memory>

/**
 * @class FactoryContentUpdater
 *
 * @brief Creates all the corresponding instances for the orchestration in charge of processing certain contents at
 * runtime.
 *
 */
class FactoryContentUpdater final
{
public:
    /**
     * @brief Creates the corresponding instances for the orchestration in charge of processing certain contents based
     * on the config values.
     *
     * @param config Configurations.
     * @return std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>>
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> create(nlohmann::json& config)
    {
        logDebug1(WM_CONTENTUPDATER, "FactoryContentUpdater - Starting process");

        auto indexerDownloader = std::make_shared<IndexerDownloader>(config);
        auto cursorUpdater = std::make_shared<UpdateIndexerCursor>();

        indexerDownloader->setNext(cursorUpdater);
        return indexerDownloader;
    }
};

#endif //_FACTORY_CONTENT_UPDATER_HPP
