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

#ifndef _FACTORY_CLEANER_HPP
#define _FACTORY_CLEANER_HPP

#include "../sharedDefs.hpp"
#include "cleanUpContent.hpp"
#include "skipStep.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include <memory>

/**
 * @class FactoryCleaner
 *
 * @brief Class in charge of creating the content cleaner.
 *
 */
class FactoryCleaner final
{
public:
    /**
     * @brief Creates the content cleaner based on the deleteDownloadedContent value.
     *
     * @param config Configurations.
     * @return std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>>
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> create(const nlohmann::json& config)
    {
        if (config.at("deleteDownloadedContent").get_ref<const bool&>())
        {
            logDebug1(WM_CONTENTUPDATER, "Content cleaner created");
            return std::make_shared<CleanUpContent>();
        }
        else
        {
            return std::make_shared<SkipStep>();
        }
    }
};

#endif // _FACTORY_CLEANER_HPP
