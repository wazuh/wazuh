/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * April 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ACTION_ORCHESTRATOR_HPP
#define _ACTION_ORCHESTRATOR_HPP

#include "components/executionContext.hpp"
#include "components/factoryContentUpdater.hpp"
#include "components/updaterContext.hpp"
#include "routerProvider.hpp"
#include "utils/rocksDBWrapper.hpp"
#include <memory>

/**
 * @brief In charge of initializing the content updater orchestration.
 *
 */
class ActionOrchestrator final
{
public:
    /**
     * @brief Creates a new instance of ActionOrchestrator.
     *
     * @param channel Channel where the orchestration will publish the data.
     * @param parameters Parameters used to create the orchestration.
     */
    explicit ActionOrchestrator(const std::shared_ptr<RouterProvider> channel, const nlohmann::json& parameters)
    {
        try
        {
            // Create a context
            m_spBaseContext = std::make_shared<UpdaterBaseContext>();
            m_spBaseContext->topicName = parameters.at("topicName");
            m_spBaseContext->configData = parameters.at("configData");
            m_spBaseContext->spChannel = channel;

            logDebug1(
                WM_CONTENTUPDATER, "Creating '%s' Content Updater orchestration", m_spBaseContext->topicName.c_str());

            // Create and run the execution context
            auto executionContext {std::make_shared<ExecutionContext>()};
            executionContext->handleRequest(m_spBaseContext);

            // Create a updater chain
            m_spUpdaterOrchestration = FactoryContentUpdater::create(m_spBaseContext->configData);

            logDebug1(WM_CONTENTUPDATER, "Content updater orchestration created");
        }
        catch (const std::exception& e)
        {
            throw std::invalid_argument {"Orchestration creation failed. " + std::string {e.what()}};
        }
    }

    /**
     * @brief Run the content updater orchestration.
     */
    void run() const
    {

        try
        {
            // Create a updater context
            auto spUpdaterContext {std::make_shared<UpdaterContext>()};
            spUpdaterContext->spUpdaterBaseContext = m_spBaseContext;

            logInfo(WM_CONTENTUPDATER, "Running '%s' content update", m_spBaseContext->topicName.c_str());

            // If the database exists, get the last offset
            if (m_spBaseContext->spRocksDB)
            {
                spUpdaterContext->currentOffset =
                    std::stoi(m_spBaseContext->spRocksDB->getLastKeyValue().second.ToString());
            }

            // Run the updater chain
            m_spUpdaterOrchestration->handleRequest(spUpdaterContext);
        }
        catch (const std::exception& e)
        {
            cleanContext();
            throw std::invalid_argument {"Orchestration run failed: " + std::string {e.what()}};
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

    /**
     * @brief Clean ContentUpdater persistent data. Useful for cleaning the context when an exception is thrown.
     *
     */
    void cleanContext() const
    {
        m_spBaseContext->downloadedFileHash.clear();
    }
};

#endif // _ACTION_ORCHESTRATOR_HPP
