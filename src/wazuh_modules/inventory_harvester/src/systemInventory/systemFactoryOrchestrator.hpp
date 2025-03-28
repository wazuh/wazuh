/*
 * Wazuh Inventory Harvester - System Factory Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYSTEM_FACTORY_ORCHESTRATOR_HPP
#define _SYSTEM_FACTORY_ORCHESTRATOR_HPP

#include "../common/clearAgent.hpp"
#include "../common/clearElements.hpp"
#include "../common/elementDispatch.hpp"
#include "../common/indexSync.hpp"
#include "chainOfResponsability.hpp"
#include "deleteElement.hpp"
#include "indexerConnector.hpp"
#include "systemContext.hpp"
#include "upsertElement.hpp"
#include <memory>

/**
 * @brief SystemFactoryOrchestrator class.
 *
 */
class SystemFactoryOrchestrator final
{
private:
    SystemFactoryOrchestrator() = default;

public:
    /**
     * @brief Creates an orchestrator and returns it.
     *
     * @param type Scanner type.
     * @param indexerConnector Indexer connector object.
     * @return std::shared_ptr<ScanContext> Abstract handler.
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<SystemContext>>>
    create(SystemContext::Operation operation,
           const std::map<SystemContext::AffectedComponentType, std::unique_ptr<IndexerConnector>, std::less<>>&
               indexerConnectorInstances)
    {
        std::shared_ptr<AbstractHandler<std::shared_ptr<SystemContext>>> orchestration;
        if (operation == SystemContext::Operation::Upsert)
        {
            orchestration = std::make_shared<UpsertSystemElement<SystemContext>>();
            orchestration->setLast(std::make_shared<ElementDispatch<SystemContext>>(indexerConnectorInstances));
        }
        else if (operation == SystemContext::Operation::Delete)
        {
            orchestration = std::make_shared<DeleteSystemElement<SystemContext>>();
            orchestration->setLast(std::make_shared<ElementDispatch<SystemContext>>(indexerConnectorInstances));
        }
        else if (operation == SystemContext::Operation::DeleteAgent)
        {
            orchestration = std::make_shared<ClearAgent<SystemContext>>(indexerConnectorInstances);
        }
        else if (operation == SystemContext::Operation::DeleteAllEntries)
        {
            orchestration = std::make_shared<ClearElements<SystemContext>>(indexerConnectorInstances);
        }
        else if (operation == SystemContext::Operation::IndexSync)
        {
            orchestration = std::make_shared<IndexSync<SystemContext>>(indexerConnectorInstances);
        }
        else
        {
            throw std::runtime_error("Invalid orchestration operation");
        }

        return orchestration;
    }
};

#endif // _SYSTEM_FACTORY_ORCHESTRATOR_HPP
