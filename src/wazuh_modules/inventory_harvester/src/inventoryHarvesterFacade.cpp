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

#include "inventoryHarvesterFacade.hpp"
#include "defs.h"
#include "loggerHelper.h"
//#include "messageBuffer_generated.h"

// LCOV_EXCL_START
void InventoryHarvesterFacade::start(
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction,
    const HarvesterConfiguration& configuration)
{
    try
    {
        // Initialize logging
        Log::assignLogFunction(logFunction);

        // Socket client initialization to send vulnerability reports.

        // logInfo(WM_VULNSCAN_LOGTAG, "Vulnerability scanner module started.");
    }
    catch (const std::exception& e)
    {
        // logError(WM_VULNSCAN_LOGTAG, "InventoryHarvesterFacade::start: %s.", e.what());
    }
    catch (...)
    {
        // logError(WM_VULNSCAN_LOGTAG, "InventoryHarvesterFacade::start: Unknown exception.");
    }
}
// LCOV_EXCL_STOP

void InventoryHarvesterFacade::stop()
{
    // Atomic flag section
    if (m_noWaitToStop)
    {
        // m_shouldStop.store(true);
    }

    // Reset shared pointers
    m_indexerConnector.reset();
    m_syscollectorRsyncSubscription.reset();
    m_syscollectorDeltasSubscription.reset();
    m_wdbAgentEventsSubscription.reset();

    // Policy manager teardown
    m_eventDispatcher.reset();
}
