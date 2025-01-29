/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIM_FACTORY_ORCHESTRATOR_HPP
#define _FIM_FACTORY_ORCHESTRATOR_HPP

#include "../common/clearAgent.hpp"
#include "../common/clearElements.hpp"
#include "../common/elementDispatch.hpp"
#include "../common/indexSync.hpp"
#include "chainOfResponsability.hpp"
#include "deleteElement.hpp"
#include "fimContext.hpp"
#include "indexerConnector.hpp"
#include "upsertElement.hpp"
#include <memory>

/**
 * @brief FimFactoryOrchestrator class.
 *
 */
class FimFactoryOrchestrator final
{
private:
    FimFactoryOrchestrator() = default;

public:
    /**
     * @brief Creates an orchestrator and returns it.
     *
     * @param type Scanner type.
     * @param indexerConnector Indexer connector object.
     * @return std::shared_ptr<ScanContext> Abstract handler.
     */
    static std::shared_ptr<AbstractHandler<std::shared_ptr<FimContext>>>
    create(FimContext::Operation operation,
           const std::map<FimContext::AffectedComponentType, std::unique_ptr<IndexerConnector>, std::less<>>&
               indexerConnectorInstances)
    {
        std::shared_ptr<AbstractHandler<std::shared_ptr<FimContext>>> orchestration;
        if (operation == FimContext::Operation::Upsert)
        {
            orchestration = std::make_shared<UpsertFimElement<FimContext>>();
            orchestration->setLast(std::make_shared<ElementDispatch<FimContext>>(indexerConnectorInstances));
        }
        else if (operation == FimContext::Operation::Delete)
        {
            orchestration = std::make_shared<DeleteFimElement<FimContext>>();
            orchestration->setLast(std::make_shared<ElementDispatch<FimContext>>(indexerConnectorInstances));
        }
        else if (operation == FimContext::Operation::DeleteAgent)
        {
            orchestration = std::make_shared<ClearAgent<FimContext>>(indexerConnectorInstances);
        }
        else if (operation == FimContext::Operation::DeleteAllEntries)
        {
            orchestration = std::make_shared<ClearElements<FimContext>>(indexerConnectorInstances);
        }
        else if (operation == FimContext::Operation::IndexSync)
        {
            orchestration = std::make_shared<IndexSync<FimContext>>(indexerConnectorInstances);
        }
        else
        {
            throw std::runtime_error("Invalid orchestration operation");
        }
        return orchestration;
    }
};

#endif // _FIM_FACTORY_ORCHESTRATOR_HPP
