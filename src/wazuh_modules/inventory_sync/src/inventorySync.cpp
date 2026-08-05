/*
 * Wazuh inventory sync
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "inventorySync.hpp"
#include "cjsonSmartDeleter.hpp"
#include "inventorySyncFacade.hpp"
#include "scanCoordinatorAdapter.hpp"

#include <memory>

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
} // namespace Log

namespace
{
    /// This module's registration in the scanner's neutral coordination registry. Held here so
    /// stop() removes EXACTLY what start() added (the registry matches by pointer identity).
    std::shared_ptr<InventorySyncScanCoordinatorAdapter> gScanCoordinator;
} // namespace

void InventorySync::start(
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction,
    const nlohmann::json& configuration) const
{

    InventorySyncFacade::instance().start(logFunction, configuration);

    // AFTER the facade is up: the adapter answers over its session/lock machinery. This is how
    // the vulnerability scanner keeps coordinating with THIS module's sessions now that its call
    // sites go through the neutral registry instead of including our facade.
    if (!gScanCoordinator)
    {
        gScanCoordinator = std::make_shared<InventorySyncScanCoordinatorAdapter>();
        vd_sync::ScanCoordinatorRegistry::instance().add(gScanCoordinator);
    }
}

void InventorySync::stop() const
{
    // BEFORE the facade goes down, so no scanner call races the teardown.
    if (gScanCoordinator)
    {
        vd_sync::ScanCoordinatorRegistry::instance().remove(gScanCoordinator);
        gScanCoordinator.reset();
    }

    InventorySyncFacade::instance().stop();
}

#ifdef __cplusplus
extern "C"
{
#endif
    void inventory_sync_start(full_log_fnc_t callbackLog, const cJSON* configuration)
    {
        try
        {
            nlohmann::json configurationNlohmann;
            if (configuration)
            {
                const std::unique_ptr<char, CJsonSmartFree> spJsonBytes {cJSON_Print(configuration)};
                configurationNlohmann = nlohmann::json::parse(spJsonBytes.get());
            }

            InventorySync::instance().start([callbackLog](const int logLevel,
                                                          const char* tag,
                                                          const char* file,
                                                          const int line,
                                                          const char* func,
                                                          const char* logMessage,
                                                          va_list args)
                                            { callbackLog(logLevel, tag, file, line, func, logMessage, args); },
                                            configurationNlohmann);
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(LogFn {WM_INVENTORY_SYNC_LOGTAG}, "Error starting inventory sync: %s", e.what());
        }
    }

    void inventory_sync_stop()
    {
        InventorySync::instance().stop();
    }

#ifdef __cplusplus
}
#endif
