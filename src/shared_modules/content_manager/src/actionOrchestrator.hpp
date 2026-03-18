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
#include "componentsHelper.hpp"
#include "utils/rocksDBWrapper.hpp"
#include <memory>
#include <utility>

/**
 * @brief In charge of initializing the content updater orchestration.
 *
 * The orchestration fetches CVE data from the Wazuh Indexer (via IndexerDownloader)
 * and persists it to the local RocksDB feed database.
 */
class ActionOrchestrator final
{
public:
    /**
     * @brief Enum that represents the type of update.
     *
     */
    enum UpdateType
    {
        CONTENT
    };

    /**
     * @brief Struct containing the necessary members to execute the orchestration.
     *
     */
    struct UpdateData
    {
        UpdateType type; ///< Orchestration update type.
        int offset;      ///< Reserved for interface compatibility; not used by Indexer path.

        /**
         * @brief Creates an UpdateData struct for content update.
         *
         * @param offset Reserved parameter (kept for API compatibility). Pass -1 for normal
         *               scheduler-driven updates; pass 0 to force a full reload.
         * @return UpdateData Struct ready to be used by the orchestrator.
         */
        static UpdateData createContentUpdateData(const int offset)
        {
            return UpdateData(UpdateType::CONTENT, offset);
        }

    private:
        UpdateData(const UpdateType type, const int offset)
            : type(type)
            , offset(offset) {};
    };

    /**
     * @brief Creates a new instance of ActionOrchestrator.
     *
     * @param parameters            Parameters used to create the orchestration.
     * @param stopActionCondition   Condition wrapper used to interrupt the orchestration stages.
     * @param fileProcessingCallback Callback function in charge of the file processing task.
     */
    explicit ActionOrchestrator(const nlohmann::json& parameters,
                                std::shared_ptr<ConditionSync> stopActionCondition,
                                const FileProcessingCallback fileProcessingCallback)
    {
        try
        {
            m_spBaseContext = std::make_shared<UpdaterBaseContext>(stopActionCondition, fileProcessingCallback);
            m_spBaseContext->topicName = parameters.at("topicName");
            m_spBaseContext->configData = parameters.at("configData");

            logDebug1(
                WM_CONTENTUPDATER, "Creating '%s' Content Updater orchestration", m_spBaseContext->topicName.c_str());

            auto executionContext {std::make_shared<ExecutionContext>()};
            executionContext->handleRequest(m_spBaseContext);

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
     *
     * @param updateData Update orchestration data.
     */
    void run(const UpdateData& updateData) const
    {
        auto spUpdaterContext {std::make_shared<UpdaterContext>()};
        spUpdaterContext->spUpdaterBaseContext = m_spBaseContext;

        try
        {
            runContentUpdate(spUpdaterContext, updateData.offset == 0);
        }
        catch (const std::exception& e)
        {
            cleanContext();
            throw std::runtime_error {"Orchestration run failed: " + std::string {e.what()}};
        }
    }

private:
    std::shared_ptr<AbstractHandler<std::shared_ptr<UpdaterContext>>> m_spUpdaterOrchestration;
    std::shared_ptr<UpdaterBaseContext> m_spBaseContext;

    /**
     * @brief Clean ContentUpdater persistent data and the updater context if provided.
     */
    void cleanContext(std::shared_ptr<UpdaterContext> spUpdaterContext = nullptr) const
    {
        if (spUpdaterContext)
        {
            spUpdaterContext->initialize();
            spUpdaterContext->spUpdaterBaseContext = m_spBaseContext;
        }

        m_spBaseContext->downloadedFileHash.clear();
    }

    /**
     * @brief Triggers the content update pipeline (IndexerDownloader → UpdateIndexerCursor).
     *
     * When forceFullReload is true the stored cursor is cleared so that IndexerDownloader
     * performs a full initial load on the next run.
     *
     * @param spUpdaterContext Updater context.
     * @param forceFullReload  If true, clears the stored cursor to trigger a full reload.
     */
    void runContentUpdate(std::shared_ptr<UpdaterContext> spUpdaterContext, const bool forceFullReload) const
    {
        logDebug2(WM_CONTENTUPDATER,
                  "Running '%s' content update (forceFullReload=%s)",
                  spUpdaterContext->spUpdaterBaseContext->topicName.c_str(),
                  forceFullReload ? "true" : "false");

        if (forceFullReload && spUpdaterContext->spUpdaterBaseContext->spRocksDB)
        {
            // Clear the stored cursor so IndexerDownloader performs a full PIT load.
            logDebug2(WM_CONTENTUPDATER,
                      "Clearing stored cursor for '%s' to force full reload",
                      spUpdaterContext->spUpdaterBaseContext->topicName.c_str());
            spUpdaterContext->spUpdaterBaseContext->spRocksDB->put(
                Utils::getCompactTimestamp(std::time(nullptr)), "0", Components::Columns::CURRENT_OFFSET);
        }

        m_spUpdaterOrchestration->handleRequest(spUpdaterContext);
    }
};

#endif // _ACTION_ORCHESTRATOR_HPP
