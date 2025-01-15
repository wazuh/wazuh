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

/**
 * @brief Start the inventory deltas subscription
 *
 */
void InventoryHarvesterFacade::initInventoryDeltasSubscription()
{
    // Subscription to syscollector delta events.
    m_inventoryDeltasSubscription =
        std::make_unique<RouterSubscriber>("deltas-syscollector", "inventory_harvester_deltas");
    m_inventoryDeltasSubscription->subscribe(
        // coverity[copy_constructor_call]
        [this](const std::vector<char>& message)
        {
            // pushEvent(message, BufferType::BufferType_DBSync);
        });
}

/**
 * @brief Start the inventory rsync events subscription.
 *
 */
void InventoryHarvesterFacade::initInventoryRsyncSubscription()
{
    // Subscription to syscollector rsync events.
    m_inventoryRsyncSubscription =
        std::make_unique<RouterSubscriber>("rsync-syscollector", "inventory_harvester_rsync");
    m_inventoryRsyncSubscription->subscribe(
        // coverity[copy_constructor_call]
        [this](const std::vector<char>& message)
        {
            // pushEvent(message, BufferType::BufferType_RSync);
        });
}

/**
 * @brief Start the fim deltas subscription
 *
 */
void InventoryHarvesterFacade::initFimDeltasSubscription()
{
    // Subscription to syscollector delta events.
    m_fimDeltasSubscription = std::make_unique<RouterSubscriber>("deltas-fim", "inventory_harvester_deltas");
    m_fimDeltasSubscription->subscribe(
        // coverity[copy_constructor_call]
        [this](const std::vector<char>& message)
        {
            // pushEvent(message, BufferType::BufferType_DBSync);
        });
}

/**
 * @brief Start the fim rsync events subscription.
 *
 */
void InventoryHarvesterFacade::initFimRsyncSubscription()
{
    // Subscription to syscollector rsync events.
    m_fimRsyncSubscription = std::make_unique<RouterSubscriber>("rsync-fim", "inventory_harvester_rsync");
    m_fimRsyncSubscription->subscribe(
        // coverity[copy_constructor_call]
        [this](const std::vector<char>& message)
        {
            // pushEvent(message, BufferType::BufferType_RSync);
        });
}

void InventoryHarvesterFacade::initWazuhDBEventSubscription()
{
    m_wdbAgentEventsSubscription =
        std::make_unique<RouterSubscriber>("wdb-agent-events", "inventory_harvester_database");
    m_wdbAgentEventsSubscription->subscribe(
        [this](const std::vector<char>& message)
        {
            // pushEvent(message, BufferType::BufferType_JSON);
        });
}

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
    m_inventoryRsyncSubscription.reset();
    m_inventoryDeltasSubscription.reset();
    m_fimRsyncSubscription.reset();
    m_fimDeltasSubscription.reset();
    m_wdbAgentEventsSubscription.reset();

    // Policy manager teardown
    m_eventDispatcher.reset();
}
