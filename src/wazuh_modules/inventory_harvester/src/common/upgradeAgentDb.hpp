/*
 * Wazuh Inventory Harvester - Upgrade agent DB
 * Copyright (C) 2015, Wazuh Inc.
 * April 03, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UPGRADE_AGENT_DB_HPP
#define _UPGRADE_AGENT_DB_HPP

#include <map>
#include <memory>

#include "chainOfResponsability.hpp"
#include "indexerConnector.hpp"
#include "noData.hpp"

template<typename TContext, typename TIndexerConnector = IndexerConnector>
class UpgradeAgentDB final : public AbstractHandler<std::shared_ptr<TContext>>
{
    const std::map<typename TContext::AffectedComponentType, std::unique_ptr<TIndexerConnector>, std::less<>>&
        m_indexerConnectorInstances;

public:
    // LCOV_EXCL_START
    /**
     * @brief Class destructor.
     *
     */
    ~UpgradeAgentDB() = default;

    explicit UpgradeAgentDB(
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
        // Inventory harvester ignores the upgrade agent DB event.
        return nullptr;
    }
};

#endif // _UPGRADE_AGENT_DB_HPP
