/*
 * Wazuh Inventory Harvester - Clear agent
 * Copyright (C) 2015, Wazuh Inc.
 * February 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CLEAR_AGENT_HPP
#define _CLEAR_AGENT_HPP

#include <map>
#include <memory>

#include "chainOfResponsability.hpp"
#include "indexerConnector.hpp"
#include "noData.hpp"

template<typename TContext, typename TIndexerConnector = IndexerConnector>
class ClearAgent final : public AbstractHandler<std::shared_ptr<TContext>>
{
    const std::map<typename TContext::AffectedComponentType, std::unique_ptr<TIndexerConnector>, std::less<>>&
        m_indexerConnectorInstances;

public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~ClearAgent() = default;

    explicit ClearAgent(
        const std::map<typename TContext::AffectedComponentType, std::unique_ptr<TIndexerConnector>, std::less<>>&
            indexerConnectorInstances)
        : m_indexerConnectorInstances(indexerConnectorInstances)
    {
    }
    // LCOV_EXCL_STOP

    /**
     * @brief Handles request and passes control to the next step of the chain.
     *
     * @param data Scan context.
     * @return std::shared_ptr<ScanContext> Abstract handler.
     */
    std::shared_ptr<TContext> handleRequest(std::shared_ptr<TContext> data) override
    {
        for (const auto& [_, indexer] : m_indexerConnectorInstances)
        {
            NoDataHarvester deleteAgent;
            deleteAgent.operation = "DELETED_BY_QUERY";
            deleteAgent.id = data->agentId();
            indexer->publish(serializeToJSON(deleteAgent));
        }
        return AbstractHandler<std::shared_ptr<TContext>>::handleRequest(std::move(data));
    }
};

#endif // _CLEAR_AGENT_HPP
