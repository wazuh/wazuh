/*
 * Wazuh Content Manager
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OFFSET_UPDATER_ORCHESTRATOR_HPP
#define _OFFSET_UPDATER_ORCHESTRATOR_HPP

#include "components/executionContext.hpp"
#include "components/factoryOffsetUpdater.hpp"
#include "components/updaterContext.hpp"
#include "json.hpp"
#include "sharedDefs.hpp"
#include <atomic>
#include <memory>
#include <string>

/**
 * @brief In charge of initializing the content updater orchestration.
 *
 */
class OffsetUpdaterOrchestrator final
{
public:
    /**
     * @brief Creates a new instance of OffsetUpdaterOrchestrator.
     *
     * @param parameters Parameters used to create the orchestration.
     * @param shouldRun Flag used to interrupt the orchestration stages.
     * @param spDatabaseConnector RocksDB driver.
     */
    explicit OffsetUpdaterOrchestrator(const nlohmann::json& parameters,
                                       const std::atomic<bool>& shouldRun,
                                       const std::shared_ptr<Utils::RocksDBWrapper> spDatabaseConnector)
    {
        try
        {
            // Create context.
            m_spBaseContext = std::make_shared<UpdaterBaseContext>(shouldRun);
            m_spBaseContext->topicName = parameters.at("offsetUpdaterTopicName");
            m_spBaseContext->configData = parameters.at("configData");
            m_spBaseContext->spRocksDB = spDatabaseConnector;

            logDebug1(
                WM_CONTENTUPDATER, "Creating '%s' offset updater orchestration", m_spBaseContext->topicName.c_str());

            // Create and run the execution context.
            auto executionContext {std::make_shared<ExecutionContext>()};
            executionContext->handleRequest(m_spBaseContext);

            // Create chain.
            m_spUpdaterOrchestration = FactoryOffsetUpdater::create(m_spBaseContext->configData);

            logDebug1(WM_CONTENTUPDATER, "Offset updater orchestration created");
        }
        catch (const std::exception& e)
        {
            throw std::invalid_argument {"Offset updater creation failed: " + std::string {e.what()}};
        }
    }

    /**
     * @brief Run the offset updater orchestration.
     *
     * @param offset Offset value to be updated on the database.
     */
    void run(const int offset) const
    {
        try
        {
            logDebug2(WM_CONTENTUPDATER, "Running '%s' offset updater", m_spBaseContext->topicName.c_str());

            // Create a updater context
            auto spUpdaterContext {std::make_shared<UpdaterContext>()};
            spUpdaterContext->spUpdaterBaseContext = m_spBaseContext;
            spUpdaterContext->currentOffset = offset;

            // Run the updater chain
            m_spUpdaterOrchestration->handleRequest(spUpdaterContext);
        }
        catch (const std::exception& e)
        {
            throw std::invalid_argument {"Offset updater run failed: " + std::string {e.what()}};
        }
    }

private:
    /**
     * @brief Content updater orchestration.
     */
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> m_spUpdaterOrchestration;

    /**
     * @brief Context used on the content updater orchestration.
     */
    std::shared_ptr<UpdaterBaseContext> m_spBaseContext;
};

#endif // _OFFSET_UPDATER_ORCHESTRATOR_HPP
