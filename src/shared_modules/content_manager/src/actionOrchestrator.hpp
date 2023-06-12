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
#include <iostream>
#include <memory>

/**
 * @brief In charge of initializing the content updater orchestration.
 *
 */
class ActionOrchestrator final
{
private:
    /**
     * @brief Content updater orchestration.
     */
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> m_spUpdaterOrchestration;

    /**
     * @brief Context used on the content updater orchestration.
     */
    std::shared_ptr<UpdaterBaseContext> m_spBaseContext;

public:
    /**
     * @brief Creates a new instance of ActionOrchestrator.
     *
     * @param channel Channel where the orchestration will publish the data.
     * @param parameters Parameters used to create the orchestration.
     */
    explicit ActionOrchestrator(const std::shared_ptr<RouterProvider> channel, const nlohmann::json& parameters)
    {
        std::cout << "ActionOrchestrator - Starting process" << std::endl;

        try
        {
            // Create a context
            m_spBaseContext = std::make_shared<UpdaterBaseContext>();
            m_spBaseContext->configData = parameters.at("configData");
            m_spBaseContext->spChannel = channel;

            // Create and run the execution context
            auto executionContext {std::make_shared<ExecutionContext>()};
            executionContext->handleRequest(m_spBaseContext);

            // Create a updater chain
            m_spUpdaterOrchestration = FactoryContentUpdater::create(m_spBaseContext->configData);

            std::cout << "ActionOrchestrator - Finishing process" << std::endl;
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
        std::cout << "ActionOrchestrator - Running process" << std::endl;

        try
        {
            // Create a updater context
            auto spUpdaterContext {std::make_shared<UpdaterContext>()};
            spUpdaterContext->spUpdaterBaseContext = m_spBaseContext;

            // Run the updater chain
            m_spUpdaterOrchestration->handleRequest(spUpdaterContext);
        }
        catch (const std::exception& e)
        {
            throw std::invalid_argument {"Orchestration run failed. " + std::string {e.what()}};
        }
    }
};

#endif // _ACTION_ORCHESTRATOR_HPP
