/*
 * Wazuh Content Manager
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_OFFSET_UPDATER_HPP
#define _FACTORY_OFFSET_UPDATER_HPP

#include "../sharedDefs.hpp"
#include "updateCtiApiOffset.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <memory>

/**
 * @class FactoryOffsetUpdater
 *
 * @brief Creates all the corresponding instances for the orchestration in charge of processing certain contents at
 * runtime.
 *
 */
class FactoryOffsetUpdater final
{
public:
    /**
     * @brief Creates the corresponding instances for the orchestration in charge of processing certain contents based
     * on the config values.
     *
     * @param config Configurations.
     * @return std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>>
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>>
    create([[maybe_unused]] const nlohmann::json& config)
    {
        logDebug1(WM_CONTENTUPDATER, "FactoryOffsetUpdater - Starting process");

        auto updateCtiApiOffset {std::make_shared<UpdateCtiApiOffset>()};
        auto const& updaterChain {updateCtiApiOffset};

        return updaterChain;
    }
};

#endif //_FACTORY_OFFSET_UPDATER_HPP
