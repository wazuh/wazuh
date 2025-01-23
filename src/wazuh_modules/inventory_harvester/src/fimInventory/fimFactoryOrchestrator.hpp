/*
 * Wazuh Vulnerability scanner
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIM_FACTORY_ORCHESTRATOR_HPP
#define _FIM_FACTORY_ORCHESTRATOR_HPP

#include "../common/elementDispatch.hpp"
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
           const std::map<std::string, std::unique_ptr<IndexerConnector>, std::less<>>& indexerConnectorInstances)
    {
        std::shared_ptr<AbstractHandler<std::shared_ptr<FimContext>>> orchestration;
        if (operation == FimContext::Operation::Upsert)
        {
            orchestration = std::make_shared<UpsertFimElement<FimContext>>();
        }
        else if (operation == FimContext::Operation::Delete)
        {
            orchestration = std::make_shared<DeleteFimElement<FimContext>>();
        }
        // else if (operation == FimContext::Operation::DeleteAgent)
        // {
        // }
        // else if (operation == FimContext::Operation::DeleteAllEntries)
        // {
        //     switch (type)
        //     {
        //         case FimContext::AffectedComponentType::Package:
        //         case FimContext::AffectedComponentType::System:
        //         case FimContext::AffectedComponentType::Process: break;

        //         default: break;
        //     }
        // }
        // else if (operation == FimContext::Operation::IndexSync)
        // {
        //     switch (type)
        //     {
        //         case FimContext::AffectedComponentType::Package:
        //         case FimContext::AffectedComponentType::System:
        //         case FimContext::AffectedComponentType::Process: break;

        //         default: break;
        //     }
        // }
        else
        {
            throw std::runtime_error("Invalid orchestration operation");
        }
        orchestration->setLast(std::make_shared<ElementDispatch<FimContext>>(indexerConnectorInstances));
        return orchestration;
    }
};

#endif // _FIM_FACTORY_ORCHESTRATOR_HPP
