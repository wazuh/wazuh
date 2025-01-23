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
#include <memory>
#include <variant>

/**
 * @brief InventoryOrchestrator class.
 *
 */
class FimInventoryOrchestrator final
{
    std::map<std::string, std::unique_ptr<IndexerConnector>, std::less<>> m_indexerConnectorInstances;
    std::map<FimContext::Operation, std::shared_ptr<AbstractHandler<std::shared_ptr<FimContext>>>> m_orchestrations;

    void
    run(const std::variant<const SyscheckDeltas::Delta*, const Synchronization::SyncMsg*, const nlohmann::json*>& data,
        const rocksdb::PinnableSlice& input)
    {
        auto context = std::make_shared<FimContext>(data);
    }

public:
    void processEvent(const rocksdb::PinnableSlice& input)
    {
        auto message = GetMessageBuffer(input.data());

        if (message->type() == BufferType::BufferType_RSync)
        {
            run(Synchronization::GetSyncMsg(message->data()->data()), input);
        }
        else if (message->type() == BufferType::BufferType_DBSync)
        {
            run(SyscheckDeltas::GetDelta(message->data()->data()), input);
        }
        else if (message->type() == BufferType::BufferType_JSON)
        {
            const auto jsonData = nlohmann::json::parse(message->data()->data());
            run(&jsonData, input);
        }
        else
        {
            throw std::runtime_error("Unknown event type");
        }
    }

    FimInventoryOrchestrator()
    {
        m_indexerConnectorInstances["packages"] = std::make_unique<IndexerConnector>("packages", "template");
        m_indexerConnectorInstances["system"] = std::make_unique<IndexerConnector>("system", "template");
        m_indexerConnectorInstances["processes"] = std::make_unique<IndexerConnector>("processes", "template");

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
    }
};

#endif // _FIM_INVENTORY_ORCHESTRATOR_HPP
