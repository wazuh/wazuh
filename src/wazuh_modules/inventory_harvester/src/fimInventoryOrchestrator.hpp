/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIM_INVENTORY_ORCHESTRATOR_HPP
#define _FIM_INVENTORY_ORCHESTRATOR_HPP

#include "chainOfResponsability.hpp"
#include "fimInventory/fimContext.hpp"
#include "fimInventory/fimFactoryOrchestrator.hpp"
#include "flatbuffers/include/messageBuffer_generated.h"
#include "flatbuffers/include/rsync_generated.h"
#include "flatbuffers/include/syscheck_deltas_generated.h"
#include "indexerConnector.hpp"
#include "loggerHelper.h"
#include "policyHarvesterManager.hpp"
#include <memory>
#include <variant>

/**
 * @brief InventoryOrchestrator class.
 *
 */
class FimInventoryOrchestrator final
{
    std::map<FimContext::AffectedComponentType, std::unique_ptr<IndexerConnector>, std::less<>>
        m_indexerConnectorInstances;
    std::map<FimContext::Operation, std::shared_ptr<AbstractHandler<std::shared_ptr<FimContext>>>> m_orchestrations;

    void
    run(const std::variant<const SyscheckDeltas::Delta*, const Synchronization::SyncMsg*, const nlohmann::json*>& data)
    {
        auto context = std::make_shared<FimContext>(data);
        logDebug2(LOGGER_DEFAULT_TAG,
                  "FimInventoryOrchestrator::run for agent: '%s', operation: '%u', component: '%u'",
                  context->agentId().data(),
                  context->operation(),
                  context->affectedComponentType());
        m_orchestrations[context->operation()]->handleRequest(context);
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
            run(SyscheckDeltas::GetDelta(message->data()->data()));
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

    FimInventoryOrchestrator()
    {
        logDebug2(LOGGER_DEFAULT_TAG, "FimInventoryOrchestrator constructor");
        m_indexerConnectorInstances[FimContext::AffectedComponentType::File] = std::make_unique<IndexerConnector>(
            PolicyHarvesterManager::instance().buildIndexerConfig("files"),
            PolicyHarvesterManager::instance().buildIndexerTemplatePath("files"),
            PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("files"),
            Log::GLOBAL_LOG_FUNCTION);
        m_indexerConnectorInstances[FimContext::AffectedComponentType::Registry] = std::make_unique<IndexerConnector>(
            PolicyHarvesterManager::instance().buildIndexerConfig("registries"),
            PolicyHarvesterManager::instance().buildIndexerTemplatePath("registries"),
            PolicyHarvesterManager::instance().buildIndexerUpdateTemplatePath("registries"),
            Log::GLOBAL_LOG_FUNCTION);

        m_orchestrations[FimContext::Operation::Upsert] =
            FimFactoryOrchestrator::create(FimContext::Operation::Upsert, m_indexerConnectorInstances);

        m_orchestrations[FimContext::Operation::Delete] =
            FimFactoryOrchestrator::create(FimContext::Operation::Delete, m_indexerConnectorInstances);

        m_orchestrations[FimContext::Operation::DeleteAgent] =
            FimFactoryOrchestrator::create(FimContext::Operation::DeleteAgent, m_indexerConnectorInstances);

        m_orchestrations[FimContext::Operation::DeleteAllEntries] =
            FimFactoryOrchestrator::create(FimContext::Operation::DeleteAllEntries, m_indexerConnectorInstances);

        m_orchestrations[FimContext::Operation::IndexSync] =
            FimFactoryOrchestrator::create(FimContext::Operation::IndexSync, m_indexerConnectorInstances);

        logDebug2(LOGGER_DEFAULT_TAG, "FimInventoryOrchestrator constructor finished");
    }
};

#endif // _FIM_INVENTORY_ORCHESTRATOR_HPP
