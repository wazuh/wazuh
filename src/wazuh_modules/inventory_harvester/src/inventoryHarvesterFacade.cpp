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
#include "fimInventoryOrchestrator.hpp"
#include "loggerHelper.h"
#include "systemInventoryOrchestrator.hpp"

constexpr auto FIM_EVENTS_QUEUE_PATH {"queue/harvester/fim_event"};
constexpr auto SYSTEM_EVENTS_QUEUE_PATH {"queue/harvester/system_event"};
constexpr auto EVENTS_BULK_SIZE {1};

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
        [this](const std::vector<char>& message) { pushSystemEvent(message, BufferType::BufferType_DBSync); });
}

/**
 * @brief Start the fim deltas subscription
 *
 */
void InventoryHarvesterFacade::initFimDeltasSubscription()
{
    // Subscription to syscollector delta events.
    m_fimDeltasSubscription = std::make_unique<RouterSubscriber>("deltas-syscheck", "inventory_harvester_deltas");
    m_fimDeltasSubscription->subscribe(
        // coverity[copy_constructor_call]
        [this](const std::vector<char>& message) { pushFimEvent(message, BufferType::BufferType_DBSync); });
}

/**
 * @brief Start the inventory rsync events subscription.
 *
 */
void InventoryHarvesterFacade::initInventoryRsyncSubscription()
{
    // Subscription to syscollector rsync events.
    m_inventoryRsyncSubscription = std::make_unique<RouterSubscriber>("rsync", "inventory_harvester_rsync");
    m_inventoryRsyncSubscription->subscribe(
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
            flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(message.data()), message.size());
            if (VerifyMessageBufferBuffer(verifier))
            {
            }
        });
}

/**
 * @brief Start the system event dispatcher
 *
 */
void InventoryHarvesterFacade::initSystemEventDispatcher()
{
    // Init Orchestrator
    auto systemInventoryOrchestrator = std::make_shared<SystemInventoryOrchestrator>();

    m_eventSystemInventoryDispatcher->startWorker(
        // coverity[copy_constructor_call]
        [systemInventoryOrchestrator](std::queue<rocksdb::PinnableSlice>& dataQueue)
        {
            // const auto parseEventMessage = [](const rocksdb::PinnableSlice& element)
            // {
            //     if (const auto eventMessageBuffer = GetMessageBuffer(element.data()); eventMessageBuffer)
            //     {
            //         return std::string(eventMessageBuffer->data()->begin(), eventMessageBuffer->data()->end());
            //     }

            //     return std::string("unable to parse");
            // };

            const auto& element = dataQueue.front();
            try
            {
                if (flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(element.data()), element.size());
                    VerifyMessageBufferBuffer(verifier))
                {
                    systemInventoryOrchestrator->processEvent(element);
                }
            }
            catch (const nlohmann::json::exception& e)
            {
                // logError(WM_VULNSCAN_LOGTAG,
                //          "VulnerabilityScannerFacade::initEventDispatcher: json exception (%d) - Event message: %s",
                //          e.id,
                //          parseEventMessage(element).c_str());
            }
            catch (const std::exception& e)
            {
                // logError(WM_VULNSCAN_LOGTAG,
                //          "VulnerabilityScannerFacade::initEventDispatcher: %s - Event message: %s",
                //          e.what(),
                //          parseEventMessage(element).c_str());
            }
        });
}

/**
 * @brief Start the system event dispatcher
 *
 */
void InventoryHarvesterFacade::initFimEventDispatcher()
{
    // Init Orchestrator
    auto fimInventoryOrchestrator = std::make_shared<FimInventoryOrchestrator>();

    m_eventFimInventoryDispatcher->startWorker(
        // coverity[copy_constructor_call]
        [fimInventoryOrchestrator](std::queue<rocksdb::PinnableSlice>& dataQueue)
        {
            // const auto parseEventMessage = [](const rocksdb::PinnableSlice& element) -> std::string
            // {
            //     if (const auto eventMessageBuffer = GetMessageBuffer(element.data()); eventMessageBuffer)
            //     {
            //         return {eventMessageBuffer->data()->begin(), eventMessageBuffer->data()->end()};
            //     }

            //     return "unable to parse";
            // };

            const auto& element = dataQueue.front();
            try
            {
                if (flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(element.data()), element.size());
                    VerifyMessageBufferBuffer(verifier))
                {
                    fimInventoryOrchestrator->processEvent(element);
                }
            }
            catch (const nlohmann::json::exception& e)
            {
                // logError(WM_VULNSCAN_LOGTAG,
                //          "VulnerabilityScannerFacade::initEventDispatcher: json exception (%d) - Event message: %s",
                //          e.id,
                //          parseEventMessage(element).c_str());
            }
            catch (const std::exception& e)
            {
                // logError(WM_VULNSCAN_LOGTAG,
                //          "VulnerabilityScannerFacade::initEventDispatcher: %s - Event message: %s",
                //          e.what(),
                //          parseEventMessage(element).c_str());
            }
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

        // Initialize all event dispatchers.
        m_eventFimInventoryDispatcher = std::make_shared<EventDispatcher>(FIM_EVENTS_QUEUE_PATH, EVENTS_BULK_SIZE);
        m_eventSystemInventoryDispatcher =
            std::make_shared<EventDispatcher>(SYSTEM_EVENTS_QUEUE_PATH, EVENTS_BULK_SIZE);

        // Initialize all subscriptions.
        initInventoryDeltasSubscription();
        initInventoryRsyncSubscription();
        initFimDeltasSubscription();

        initSystemEventDispatcher();
        initFimEventDispatcher();

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
    m_inventoryRsyncSubscription.reset();
    m_inventoryDeltasSubscription.reset();
    m_fimRsyncSubscription.reset();
    m_fimDeltasSubscription.reset();
    m_wdbAgentEventsSubscription.reset();

    // Policy manager teardown
    m_eventSystemInventoryDispatcher.reset();
    m_eventFimInventoryDispatcher.reset();
}
