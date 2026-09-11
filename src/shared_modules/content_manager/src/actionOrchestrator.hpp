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

#include "components/contentCycle.hpp"
#include "components/executionContext.hpp"
#include "components/factoryContentUpdater.hpp"
#include "components/indexerQueryPort.hpp"
#include "components/rocksDbTokenStore.hpp"
#include "contentSink.hpp"
#include "contentTokenStore.hpp"
#include "contentTypes.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

/**
 * @brief Owns one topic's cycle and the state it needs between runs.
 *
 * Thin by design: validate at construction, then hand every run to @ref ContentCycle. It no longer
 * throws from `run` — a cycle's failure is a value now, not an exception, which is what lets it be
 * driven from a scheduler worker that must not be unwound through.
 */
class ActionOrchestrator final
{
public:
    /**
     * @brief Prepare a topic.
     *
     * @param parameters Registration parameters (`topicName`, `configData`, …).
     * @param stopActionCondition Cooperative stop flag shared with the driver.
     * @param sink Where the content goes.
     * @param tokenStore Host-supplied token store. When null, one is built over
     *                   `configData.databasePath` if that key is present.
     * @param port Indexer access.
     * @throws std::invalid_argument if the configuration is not usable.
     */
    ActionOrchestrator(const nlohmann::json& parameters,
                       std::shared_ptr<ConditionSync> stopActionCondition,
                       std::shared_ptr<content_manager::IContentSink> sink,
                       std::shared_ptr<content_manager::IContentTokenStore> tokenStore,
                       std::shared_ptr<IIndexerQueryPort> port)
    {
        try
        {
            m_topicName = parameters.at("topicName").get<std::string>();
            const auto& configData = parameters.at("configData");

            auto context = ExecutionContext::prepare(configData, m_topicName);
            m_database = std::move(context.database);

            m_tokenStore = std::move(tokenStore);
            if (!m_tokenStore && m_database)
            {
                m_tokenStore = std::make_shared<RocksDbTokenStore>(m_database);
            }

            // Intent through configuration rather than a reach-in: hosts used to delete the
            // library's storage directory behind its back to force a rebuild, which could only work
            // before the registration existed.
            if (m_tokenStore && configData.value("resetStateOnRegister", false))
            {
                logInfo(WM_CONTENTUPDATER,
                        "Clearing the stored content token for '%s' as requested at registration.",
                        m_topicName.c_str());
                m_tokenStore->clear(m_topicName);
            }

            m_cycle = FactoryContentUpdater::create(
                configData, m_topicName, std::move(sink), m_tokenStore, std::move(stopActionCondition), std::move(port));
        }
        catch (const std::exception& e)
        {
            throw std::invalid_argument {"Orchestration creation failed. " + std::string {e.what()}};
        }
    }

    /**
     * @brief Run one cycle.
     *
     * @param request What the caller wants from it.
     * @return What happened. Never throws.
     */
    content_manager::CycleOutcome run(const content_manager::RunRequest& request) noexcept
    {
        return m_cycle->run(request);
    }

    /// @return The token in force for this topic, or "" when there is none.
    std::string currentToken() const noexcept
    {
        return m_tokenStore ? m_tokenStore->load(m_topicName) : std::string {};
    }

private:
    std::string m_topicName;
    std::shared_ptr<Utils::RocksDBWrapper> m_database;
    std::shared_ptr<content_manager::IContentTokenStore> m_tokenStore;
    std::unique_ptr<ContentCycle> m_cycle;
};

#endif // _ACTION_ORCHESTRATOR_HPP
