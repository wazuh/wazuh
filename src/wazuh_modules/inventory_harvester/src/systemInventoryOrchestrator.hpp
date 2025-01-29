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

        m_orchestrations.at(context->operation())->handleRequest(context);
    }

public:
    void processEvent(const rocksdb::PinnableSlice& input)
    {
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
            const auto jsonData =
                nlohmann::json::parse(message->data()->data(), message->data()->data() + message->data()->size());

            run(&jsonData);
        }
        else
        {
            throw std::runtime_error("Unknown event type");
        }
    }

    SystemInventoryOrchestrator()
    {
        logDebug2(LOGGER_DEFAULT_TAG, "SystemInventoryOrchestrator constructor");

        m_indexerConnectorInstances[SystemContext::AffectedComponentType::Package] =
            std::make_unique<IndexerConnector>(PolicyHarvesterManager::instance().buildIndexerConfig("packages"),
                                               PolicyHarvesterManager::instance().buildIndexerTemplatePath("packages"),
                                               Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[SystemContext::AffectedComponentType::System] =
            std::make_unique<IndexerConnector>(PolicyHarvesterManager::instance().buildIndexerConfig("system"),
                                               PolicyHarvesterManager::instance().buildIndexerTemplatePath("system"),
                                               Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[SystemContext::AffectedComponentType::Process] =
            std::make_unique<IndexerConnector>(PolicyHarvesterManager::instance().buildIndexerConfig("processes"),
                                               PolicyHarvesterManager::instance().buildIndexerTemplatePath("processes"),
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
        logDebug2(LOGGER_DEFAULT_TAG, "SystemInventoryOrchestrator finished");
    }
};

#endif // _SYSTEM_INVENTORY_ORCHESTRATOR_HPP
