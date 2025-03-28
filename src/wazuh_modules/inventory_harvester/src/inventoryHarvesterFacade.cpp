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
#include "flatbuffers/include/rsync_generated.h"
#include "loggerHelper.h"
#include "policyHarvesterManager.hpp"
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
    logDebug2(LOGGER_DEFAULT_TAG,
              "InventoryHarvesterFacade::initInventoryDeltasSubscription: Initializing inventory deltas subscription.");
    // Subscription to syscollector delta events.
    m_inventoryDeltasSubscription =
        std::make_unique<RouterSubscriber>("deltas-syscollector", "inventory_harvester_deltas");
    m_inventoryDeltasSubscription->subscribe(
        // coverity[copy_constructor_call]
        [this](const std::vector<char>& message)
        {
            logDebug2(LOGGER_DEFAULT_TAG, "InventoryHarvesterFacade::initInventoryDeltasSubscription: pushEvent");
            pushSystemEvent(message, BufferType::BufferType_DBSync);
        });
}

/**
 * @brief Start the fim deltas subscription
 *
 */
void InventoryHarvesterFacade::initFimDeltasSubscription()
{
    logDebug2(LOGGER_DEFAULT_TAG,
              "InventoryHarvesterFacade::initFimDeltasSubscription: Initializing fim deltas subscription.");
    // Subscription to syscollector delta events.
    m_fimDeltasSubscription = std::make_unique<RouterSubscriber>("deltas-syscheck", "inventory_harvester_deltas");
    m_fimDeltasSubscription->subscribe(
        // coverity[copy_constructor_call]
        [this](const std::vector<char>& message)
        {
            logDebug2(LOGGER_DEFAULT_TAG, "InventoryHarvesterFacade::initFimDeltasSubscription: pushEvent");
            pushFimEvent(message, BufferType::BufferType_DBSync);
        });
}

/**
 * @brief Start the inventory rsync events subscription.
 *
 */
void InventoryHarvesterFacade::initRsyncSubscription()
{
    logDebug2(LOGGER_DEFAULT_TAG,
              "InventoryHarvesterFacade::initInventoryRsyncSubscription: Initializing inventory rsync subscription.");
    // Subscription to syscollector rsync events.
    m_harvesterRsyncSubscription = std::make_unique<RouterSubscriber>("rsync", "inventory_harvester_rsync");
    m_harvesterRsyncSubscription->subscribe(
        // coverity[copy_constructor_call]
        [this](const std::vector<char>& message)
        {
            flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(message.data()), message.size());
            if (Synchronization::VerifySyncMsgBuffer(verifier))
            {
                auto data = Synchronization::GetSyncMsg(message.data());
                if (data->data_type() == Synchronization::DataUnion_state)
                {
                    if (data->data_as_state()->attributes_as_fim_file() ||
                        data->data_as_state()->attributes_as_fim_registry_key() ||
                        data->data_as_state()->attributes_as_fim_registry_value())
                    {
                        pushFimEvent(message, BufferType::BufferType_RSync);
                    }
                    else if (data->data_as_state()->attributes_as_syscollector_packages() ||
                             data->data_as_state()->attributes_as_syscollector_processes() ||
                             data->data_as_state()->attributes_as_syscollector_osinfo() ||
                             data->data_as_state()->attributes_as_syscollector_ports() ||
                             data->data_as_state()->attributes_as_syscollector_hotfixes() ||
                             data->data_as_state()->attributes_as_syscollector_hwinfo() ||
                             data->data_as_state()->attributes_as_syscollector_network_protocol() ||
                             data->data_as_state()->attributes_as_syscollector_network_iface())
                    {
                        pushSystemEvent(message, BufferType::BufferType_RSync);
                    }
                }
                else if (data->data_type() == Synchronization::DataUnion_integrity_clear)
                {
                    auto attributesType = data->data_as_integrity_clear()->attributes_type()->string_view();
                    if (attributesType.compare("fim_file") == 0 || attributesType.compare("fim_registry_key") == 0 ||
                        attributesType.compare("fim_registry_value") == 0)
                    {
                        pushFimEvent(message, BufferType::BufferType_RSync);
                    }
                    else if (attributesType.compare("syscollector_packages") == 0 ||
                             attributesType.compare("syscollector_processes") == 0 ||
                             attributesType.compare("syscollector_osinfo") == 0 ||
                             attributesType.compare("syscollector_ports") == 0 ||
                             attributesType.compare("syscollector_hotfixes") == 0 ||
                             attributesType.compare("syscollector_hwinfo") == 0 ||
                             attributesType.compare("syscollector_network_protocol") == 0 ||
                             attributesType.compare("syscollector_network_iface") == 0)
                    {
                        pushSystemEvent(message, BufferType::BufferType_RSync);
                    }
                }
                else if (data->data_type() == Synchronization::DataUnion_integrity_check_global)
                {
                    auto attributesType = data->data_as_integrity_check_global()->attributes_type()->string_view();
                    if (attributesType.compare("fim_file") == 0 || attributesType.compare("fim_registry_key") == 0 ||
                        attributesType.compare("fim_registry_value") == 0)
                    {
                        pushFimEvent(message, BufferType::BufferType_RSync);
                    }
                    else if (attributesType.compare("syscollector_packages") == 0 ||
                             attributesType.compare("syscollector_processes") == 0 ||
                             attributesType.compare("syscollector_osinfo") == 0 ||
                             attributesType.compare("syscollector_ports") == 0 ||
                             attributesType.compare("syscollector_hotfixes") == 0 ||
                             attributesType.compare("syscollector_hwinfo") == 0 ||
                             attributesType.compare("syscollector_network_protocol") == 0 ||
                             attributesType.compare("syscollector_network_iface") == 0)
                    {
                        pushSystemEvent(message, BufferType::BufferType_RSync);
                    }
                }
            }
        });
}

void InventoryHarvesterFacade::initWazuhDBAgentEventSubscription()
{
    m_wdbAgentEventsSubscription =
        std::make_unique<RouterSubscriber>("wdb-agent-events", "inventory_harvester_database");
    m_wdbAgentEventsSubscription->subscribe(
        [this](const std::vector<char>& message)
        {
            // Push to both system and fim events, because the agent is being deleted and we need to remove all
            // elements from all indices.
            pushSystemEvent(message, BufferType::BufferType_JSON);
            pushFimEvent(message, BufferType::BufferType_JSON);
        });
}

void InventoryHarvesterFacade::initWazuhDBFimEventSubscription()
{
    m_wdbFimEventsSubscription = std::make_unique<RouterSubscriber>("wdb-fim-events", "inventory_harvester_database");
    m_wdbFimEventsSubscription->subscribe([this](const std::vector<char>& message)
                                          { pushFimEvent(message, BufferType::BufferType_JSON); });
}

void InventoryHarvesterFacade::initWazuhDBInventoryEventSubscription()
{
    m_wdbInventoryEventsSubscription =
        std::make_unique<RouterSubscriber>("wdb-inventory-events", "inventory_harvester_database");
    m_wdbInventoryEventsSubscription->subscribe([this](const std::vector<char>& message)
                                                { pushSystemEvent(message, BufferType::BufferType_JSON); });
}

/**
 * @brief Start the system event dispatcher
 *
 */
void InventoryHarvesterFacade::initSystemEventDispatcher() const
{
    logDebug2(LOGGER_DEFAULT_TAG,
              "InventoryHarvesterFacade::initSystemEventDispatcher: Initializing system event dispatcher.");
    // Init Orchestrator
    auto systemInventoryOrchestrator = std::make_shared<SystemInventoryOrchestrator>();
    const auto parseEventMessage = [](const rocksdb::PinnableSlice& element)
    {
        if (const auto eventMessageBuffer = GetMessageBuffer(element.data()); eventMessageBuffer)
        {
            return std::string(eventMessageBuffer->data()->begin(), eventMessageBuffer->data()->end());
        }

        return std::string("unable to parse");
    };

    m_eventSystemInventoryDispatcher->startWorker(
        // coverity[copy_constructor_call]
        [systemInventoryOrchestrator, &parseEventMessage](std::queue<rocksdb::PinnableSlice>& dataQueue)
        {
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
                logError(LOGGER_DEFAULT_TAG,
                         "InventoryHarvesterFacade::initSystemEventDispatcher: json exception (%d) - Event message: %s",
                         e.id,
                         parseEventMessage(element).c_str());
            }
            catch (const std::exception& e)
            {
                logError(LOGGER_DEFAULT_TAG, "InventoryHarvesterFacade::initSystemEventDispatcher: %s.", e.what());
            }
        });
}

/**
 * @brief Start the system event dispatcher
 *
 */
void InventoryHarvesterFacade::initFimEventDispatcher() const
{
    logDebug2(LOGGER_DEFAULT_TAG,
              "InventoryHarvesterFacade::initFimEventDispatcher: Initializing fim event dispatcher.");
    // Init Orchestrator
    auto fimInventoryOrchestrator = std::make_shared<FimInventoryOrchestrator>();

    const auto parseEventMessage = [](const rocksdb::PinnableSlice& element) -> std::string
    {
        if (const auto eventMessageBuffer = GetMessageBuffer(element.data()); eventMessageBuffer)
        {
            return {eventMessageBuffer->data()->begin(), eventMessageBuffer->data()->end()};
        }

        return "unable to parse";
    };

    m_eventFimInventoryDispatcher->startWorker(
        // coverity[copy_constructor_call]
        [fimInventoryOrchestrator, &parseEventMessage](std::queue<rocksdb::PinnableSlice>& dataQueue)
        {
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
                logError(LOGGER_DEFAULT_TAG,
                         "InventoryHarvesterFacade::initFimEventDispatcher: json exception (%d) - Event message: %s",
                         e.id,
                         parseEventMessage(element).c_str());
            }
            catch (const std::exception& e)
            {
                logError(LOGGER_DEFAULT_TAG, "InventoryHarvesterFacade::initFimEventDispatcher: %s", e.what());
            }
        });
}

// LCOV_EXCL_START
void InventoryHarvesterFacade::start(
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction,
    const nlohmann::json& configuration)
{
    try
    {
        // Initialize logging
        Log::assignLogFunction(logFunction);

        PolicyHarvesterManager::instance().initialize(configuration);

        // Initialize all event dispatchers.
        m_eventFimInventoryDispatcher = std::make_shared<EventDispatcher>(FIM_EVENTS_QUEUE_PATH, EVENTS_BULK_SIZE);
        m_eventSystemInventoryDispatcher =
            std::make_shared<EventDispatcher>(SYSTEM_EVENTS_QUEUE_PATH, EVENTS_BULK_SIZE);

        // Initialize all subscriptions.
        initInventoryDeltasSubscription();
        initFimDeltasSubscription();
        initRsyncSubscription();
        initWazuhDBAgentEventSubscription();
        initWazuhDBInventoryEventSubscription();
        initWazuhDBFimEventSubscription();

        initSystemEventDispatcher();
        initFimEventDispatcher();

        // Socket client initialization to send vulnerability reports.

        logInfo(LOGGER_DEFAULT_TAG, "InventoryHarvesterFacade module started.");
    }
    catch (const std::exception& e)
    {
        logError(LOGGER_DEFAULT_TAG, "InventoryHarvesterFacade::start: %s.", e.what());
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
    m_harvesterRsyncSubscription.reset();
    m_inventoryDeltasSubscription.reset();
    m_fimDeltasSubscription.reset();
    m_wdbAgentEventsSubscription.reset();

    // Policy manager teardown
    m_eventSystemInventoryDispatcher.reset();
    m_eventFimInventoryDispatcher.reset();

    logInfo(LOGGER_DEFAULT_TAG, "Inventory harvester module stopped.");
}
