/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 13, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "inventoryHarvester.hpp"
#include "cjsonSmartDeleter.hpp"
#include "harvesterConfiguration.hpp"
#include "inventoryHarvesterFacade.hpp"
#include "inventory_harvester.h"
#include "loggerHelper.h"
#include <string>

namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

void InventoryHarvester::start(
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction,
    const HarvesterConfiguration& configuration) const
{
    InventoryHarvesterFacade::instance().start(logFunction, configuration);
}

void InventoryHarvester::stop() const
{
    InventoryHarvesterFacade::instance().stop();
}

#ifdef __cplusplus
extern "C"
{
#endif
    void inventory_harvester_start(full_log_fnc_t callbackLog, const cJSON* configuration)
    {
        // nlohmann::json configurationNlohmann;
        // if (configuration)
        // {
        //     const std::unique_ptr<char, CJsonSmartFree> spJsonBytes {cJSON_Print(configuration)};
        //     configurationNlohmann = nlohmann::json::parse(spJsonBytes.get());
        // }

        // InventoryHarvester::instance().start(
        //     [callbackLog](const int logLevel,
        //                   const std::string& tag,
        //                   const std::string& file,
        //                   const int line,
        //                   const std::string& func,
        //                   const std::string& logMessage,
        //                   va_list args)
        //     { callbackLog(logLevel, tag.c_str(), file.c_str(), line, func.c_str(), logMessage.c_str(), args); },
        //     configurationNlohmann);
    }

    void inventory_harvester_stop()
    {
        // InventoryHarvester::instance().stop();
    }

#ifdef __cplusplus
}
#endif
// LCOV_EXCL_STOP
