/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 21, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSTEM_INVENTORY_ORCHESTRATOR_HPP
#define _SYSTEM_INVENTORY_ORCHESTRATOR_HPP

#include "flatbuffers/include/messageBuffer_generated.h"
#include "flatbuffers/include/rsync_generated.h"
#include "flatbuffers/include/syscollector_deltas_generated.h"
#include "indexerConnector.hpp"
#include "loggerHelper.h"
#include "policyHarvesterManager.hpp"
#include "systemInventory/systemContext.hpp"
#include "systemInventory/systemFactoryOrchestrator.hpp"
#include <memory>
#include <variant>

/**
 * @brief InventoryOrchestrator class.
 *
 */
class SystemInventoryOrchestrator final
{
    std::map<SystemContext::AffectedComponentType, std::unique_ptr<IndexerConnector>, std::less<>>
        m_indexerConnectorInstances;
    std::map<SystemContext::Operation, std::shared_ptr<AbstractHandler<std::shared_ptr<SystemContext>>>>
        m_orchestrations;

    void
    run(const std::variant<const SyscollectorDeltas::Delta*, const Synchronization::SyncMsg*, const nlohmann::json*>&
            data)
    {
        auto context = std::make_shared<SystemContext>(data);
        logDebug2(LOGGER_DEFAULT_TAG,
                  "SystemInventoryOrchestrator::run for agent: '%s', operation: '%u', component: '%u'",
                  context->agentId().data(),
                  context->operation(),
                  context->affectedComponentType());
        m_orchestrations.at(context->operation())->handleRequest(context);
    }

public:
    void processEvent(const rocksdb::PinnableSlice& input)
    {
        logDebug2(LOGGER_DEFAULT_TAG, "SystemInventoryOrchestrator::processEvent");
        auto message = GetMessageBuffer(input.data());

        if (message->type() == BufferType::BufferType_RSync)
        {
            run(Synchronization::GetSyncMsg(message->data()->data()));
        }
        else if (message->type() == BufferType::BufferType_DBSync)
        {
            run(SyscollectorDeltas::GetDelta(message->data()->data()));
        }
        else if (message->type() == BufferType::BufferType_JSON)
        {
            const auto* dataPtr = message->data()->data();
            const auto dataSize = message->data()->size();

            // Create a std::string (copy) for safer UTF-8 parsing
            std::string jsonStr(dataPtr, dataPtr + dataSize);

            const auto jsonData = nlohmann::json::parse(jsonStr);

            run(&jsonData);
        }
        else
        {
            throw std::runtime_error("Unknown event type");
        }
        logDebug2(LOGGER_DEFAULT_TAG, "SystemInventoryOrchestrator::processEvent finished");
    }

    SystemInventoryOrchestrator()
    {
        logDebug2(LOGGER_DEFAULT_TAG, "SystemInventoryOrchestrator constructor");

        m_indexerConnectorInstances[SystemContext::AffectedComponentType::Package] = std::make_unique<IndexerConnector>(
            PolicyHarvesterManager::instance().buildIndexerConfig("packages", InventoryType::SYSTEM_INVENTORY),
            PolicyHarvesterManager::instance().buildIndexerTemplatePath("packages", InventoryType::SYSTEM_INVENTORY),
            PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("packages",
                                                                              InventoryType::SYSTEM_INVENTORY),
            Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[SystemContext::AffectedComponentType::System] = std::make_unique<IndexerConnector>(
            PolicyHarvesterManager::instance().buildIndexerConfig("system", InventoryType::SYSTEM_INVENTORY),
            PolicyHarvesterManager::instance().buildIndexerTemplatePath("system", InventoryType::SYSTEM_INVENTORY),
            PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("system",
                                                                              InventoryType::SYSTEM_INVENTORY),
            Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[SystemContext::AffectedComponentType::Process] = std::make_unique<IndexerConnector>(
            PolicyHarvesterManager::instance().buildIndexerConfig("processes", InventoryType::SYSTEM_INVENTORY),
            PolicyHarvesterManager::instance().buildIndexerTemplatePath("processes", InventoryType::SYSTEM_INVENTORY),
            PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("processes",
                                                                              InventoryType::SYSTEM_INVENTORY),
            Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[SystemContext::AffectedComponentType::Port] = std::make_unique<IndexerConnector>(
            PolicyHarvesterManager::instance().buildIndexerConfig("ports", InventoryType::SYSTEM_INVENTORY),
            PolicyHarvesterManager::instance().buildIndexerTemplatePath("ports", InventoryType::SYSTEM_INVENTORY),
            PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("ports", InventoryType::SYSTEM_INVENTORY),
            Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[SystemContext::AffectedComponentType::Hotfix] = std::make_unique<IndexerConnector>(
            PolicyHarvesterManager::instance().buildIndexerConfig("hotfixes", InventoryType::SYSTEM_INVENTORY),
            PolicyHarvesterManager::instance().buildIndexerTemplatePath("hotfixes", InventoryType::SYSTEM_INVENTORY),
            PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("hotfixes",
                                                                              InventoryType::SYSTEM_INVENTORY),
            Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[SystemContext::AffectedComponentType::Hardware] =
            std::make_unique<IndexerConnector>(
                PolicyHarvesterManager::instance().buildIndexerConfig("hardware", InventoryType::SYSTEM_INVENTORY),
                PolicyHarvesterManager::instance().buildIndexerTemplatePath("hardware",
                                                                            InventoryType::SYSTEM_INVENTORY),
                PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("hardware",
                                                                                  InventoryType::SYSTEM_INVENTORY),
                Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[SystemContext::AffectedComponentType::NetProto] =
            std::make_unique<IndexerConnector>(
                PolicyHarvesterManager::instance().buildIndexerConfig("protocols", InventoryType::SYSTEM_INVENTORY),
                PolicyHarvesterManager::instance().buildIndexerTemplatePath("protocols",
                                                                            InventoryType::SYSTEM_INVENTORY),
                PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("protocols",
                                                                                  InventoryType::SYSTEM_INVENTORY),
                Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[SystemContext::AffectedComponentType::NetIface] =
            std::make_unique<IndexerConnector>(
                PolicyHarvesterManager::instance().buildIndexerConfig("interfaces", InventoryType::SYSTEM_INVENTORY),
                PolicyHarvesterManager::instance().buildIndexerTemplatePath("interfaces",
                                                                            InventoryType::SYSTEM_INVENTORY),
                PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("interfaces",
                                                                                  InventoryType::SYSTEM_INVENTORY),
                Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[SystemContext::AffectedComponentType::NetworkAddress] =
            std::make_unique<IndexerConnector>(
                PolicyHarvesterManager::instance().buildIndexerConfig("networks", InventoryType::SYSTEM_INVENTORY),
                PolicyHarvesterManager::instance().buildIndexerTemplatePath("networks",
                                                                            InventoryType::SYSTEM_INVENTORY),
                PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("networks",
                                                                                  InventoryType::SYSTEM_INVENTORY),
                Log::GLOBAL_LOG_FUNCTION);

        m_orchestrations[SystemContext::Operation::Upsert] =
            SystemFactoryOrchestrator::create(SystemContext::Operation::Upsert, m_indexerConnectorInstances);

        m_orchestrations[SystemContext::Operation::Delete] =
            SystemFactoryOrchestrator::create(SystemContext::Operation::Delete, m_indexerConnectorInstances);

        m_orchestrations[SystemContext::Operation::DeleteAgent] =
            SystemFactoryOrchestrator::create(SystemContext::Operation::DeleteAgent, m_indexerConnectorInstances);

        m_orchestrations[SystemContext::Operation::DeleteAllEntries] =
            SystemFactoryOrchestrator::create(SystemContext::Operation::DeleteAllEntries, m_indexerConnectorInstances);

        m_orchestrations[SystemContext::Operation::IndexSync] =
            SystemFactoryOrchestrator::create(SystemContext::Operation::IndexSync, m_indexerConnectorInstances);

        m_orchestrations[SystemContext::Operation::UpgradeAgentDB] =
            SystemFactoryOrchestrator::create(SystemContext::Operation::UpgradeAgentDB, m_indexerConnectorInstances);

        logDebug2(LOGGER_DEFAULT_TAG, "SystemInventoryOrchestrator finished");
    }
};

#endif // _SYSTEM_INVENTORY_ORCHESTRATOR_HPP
