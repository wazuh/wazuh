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
#include "factoryOffsetUpdater.hpp"
#include "utils/rocksDBWrapper.hpp"
#include <memory>
#include <utility>

/**
 * @brief In charge of initializing the content updater orchestration.
 *
 */
class ActionOrchestrator final
{
public:
    /**
     * @brief Enum that represents the type of update that exists.
     *
     */
    enum UpdateType
    {
        CONTENT,
        OFFSET,
        FILE_HASH
    };

    /**
     * @brief Struct containing the necessary members to execute the orchestrations.
     *
     */
    struct UpdateData
    {
        UpdateType type;      ///< Orchestration update type.
        int offset;           ///< Offset value used in the update.
        std::string fileHash; ///< Hash value used in the update.

        /**
         * @brief Creates an UpdateData struct for content update.
         *
         * @param offset Offset used in the update. If zero, the offset value will be reset. Otherwise, its value will
         * be read from the RocksDB database.
         * @return UpdateData Struct ready to be used by the orchestrator.
         */
        static UpdateData createContentUpdateData(const int offset)
        {
            return UpdateData(UpdateType::CONTENT, offset, "");
        }

        /**
         * @brief Creates an UpdateData struct for offset update.
         *
         * @param offset Offset used in the update that will be written in the RocksDB database to be used in posterior
         * content updates. Should be nonnegative.
         * @return UpdateData Struct ready to be used by the orchestrator.
         */
        static UpdateData createOffsetUpdateData(const int offset)
        {
            if (0 > offset)
            {
                throw std::invalid_argument {"Offset value (" + std::to_string(offset) + ") shouldn't be negative"};
            }
            return UpdateData(UpdateType::OFFSET, offset, "");
        }

        /**
         * @brief Creates an UpdateData struct for file hash update.
         *
         * @param fileHash Hash used in the update that will be written in the RocksDB database to be used in posterior
         * content updates. Should be nonnegative.
         * @return UpdateData Struct ready to be used by the orchestrator.
         */
        static UpdateData createHashUpdateData(const std::string& fileHash)
        {
            if (fileHash.empty())
            {
                throw std::invalid_argument {"Invalid hash value: The hash is empty"};
            }
            return UpdateData(UpdateType::FILE_HASH, -1, fileHash);
        }

    private:
        /**
         * @brief Private struct constructor called from the static methods of this struct.
         *
         */
        UpdateData(const UpdateType type, const int offset, const std::string& fileHash)
            : type(type)
            , offset(offset)
            , fileHash(fileHash) {};
    };

    /**
     * @brief Creates a new instance of ActionOrchestrator.
     *
     * @param parameters Parameters used to create the orchestration.
     * @param stopActionCondition Condition wrapper used to interrupt the orchestration stages.
     * @param fileProcessingCallback Callback function in charge of the file processing task.
     */
    explicit ActionOrchestrator(const nlohmann::json& parameters,
                                std::shared_ptr<ConditionSync> stopActionCondition,
                                const FileProcessingCallback fileProcessingCallback)
    {
        try
        {
            // Create a context
            m_spBaseContext = std::make_shared<UpdaterBaseContext>(stopActionCondition, fileProcessingCallback);
            m_spBaseContext->topicName = parameters.at("topicName");
            m_spBaseContext->configData = parameters.at("configData");

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
     *
     * @param updateData Update orchestration data.
     */
    void run(const UpdateData& updateData) const
    {
        // Create a updater context
        auto spUpdaterContext {std::make_shared<UpdaterContext>()};
        spUpdaterContext->spUpdaterBaseContext = m_spBaseContext;

        try
        {
            if (UpdateType::OFFSET == updateData.type)
            {
                runOffsetUpdate(spUpdaterContext, updateData.offset);
            }
            else if (UpdateType::FILE_HASH == updateData.type)
            {
                runFileHashUpdate(spUpdaterContext, updateData.fileHash);
            }
            else if (UpdateType::CONTENT == updateData.type)
            {
                runContentUpdate(spUpdaterContext, updateData.offset == 0);
            }
            else
            {
                // LCOV_EXCL_START
                logDebug1(WM_CONTENTUPDATER, "Invalid update type, the orchestration will be skipped");
                // LCOV_EXCL_STOP
            }
        }
        catch (const OffsetProcessingException& e)
        {
            logWarn(WM_CONTENTUPDATER, "Offset processing failed. Triggered a snapshot download.");
            cleanContext(spUpdaterContext);
            runContentUpdate(spUpdaterContext, true);
        }
        catch (const std::exception& e)
        {
            cleanContext();
            throw std::runtime_error {"Orchestration run failed: " + std::string {e.what()}};
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
     * @brief Clean ContentUpdater persistent data and the updater context if provided.
     *
     * @note Useful for cleaning the contexts when an exception is thrown.
     *
     * @param updaterContext Updater context to be re-initialized (optional).
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
     * @brief Creates and triggers a new orchestration that updates the offset in the database.
     *
     * @param spUpdaterContext Updater context.
     * @param offset New value of the offset.
     */
    void runOffsetUpdate(std::shared_ptr<UpdaterContext> spUpdaterContext, int offset) const
    {
        logDebug2(WM_CONTENTUPDATER, "Running '%s' offset update", m_spBaseContext->topicName.c_str());

        spUpdaterContext->currentOffset = offset;

        FactoryOffsetUpdater::create(m_spBaseContext->configData)->handleRequest(std::move(spUpdaterContext));
    }

    /**
     * @brief Performs a file hash update in the database with the specified hash.
     *
     * @param spUpdaterContext Updater context.
     * @param fileHash Hash value to be used in the update.
     */
    void runFileHashUpdate(std::shared_ptr<UpdaterContext> spUpdaterContext, const std::string& fileHash) const
    {
        logDebug2(WM_CONTENTUPDATER, "Running '%s' file hash update", m_spBaseContext->topicName.c_str());

        if (spUpdaterContext->spUpdaterBaseContext->spRocksDB)
        {
            spUpdaterContext->spUpdaterBaseContext->spRocksDB->put(
                Utils::getCompactTimestamp(std::time(nullptr)), fileHash, Components::Columns::DOWNLOADED_FILE_HASH);
        }

        spUpdaterContext->spUpdaterBaseContext->downloadedFileHash = fileHash;
    }

    /**
     * @brief Triggers a new orchestration that updates the content.
     *
     * @param spUpdaterContext Updater context.
     * @param resetOffset If true, the current offset is set to zero.
     */
    void runContentUpdate(std::shared_ptr<UpdaterContext> spUpdaterContext, const bool resetOffset) const
    {
        logDebug2(WM_CONTENTUPDATER,
                  "Running '%s' content update",
                  spUpdaterContext->spUpdaterBaseContext->topicName.c_str());

        if (resetOffset)
        {
            spUpdaterContext->currentOffset = 0;
        }
        else if (spUpdaterContext->spUpdaterBaseContext->spRocksDB)
        {
            // If the database exists, get the last offset
            spUpdaterContext->currentOffset = std::stoi(
                spUpdaterContext->spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET)
                    .second.ToString());
        }

        const auto& contentSource {
            spUpdaterContext->spUpdaterBaseContext->configData.at("contentSource").get_ref<const std::string&>()};

        logDebug2(WM_CONTENTUPDATER,
                  "Current offset: '%d'. Current hash: '%s'. ContentSource: '%s'",
                  spUpdaterContext->currentOffset,
                  spUpdaterContext->spUpdaterBaseContext->downloadedFileHash.c_str(),
                  contentSource.c_str());
        // Check if the full content download should be triggered
        // 1. If the current offset is '0' and the content source is 'cti-offset'.
        // 2. If the offset should be reset.
        if ((0 == spUpdaterContext->currentOffset && "cti-offset" == contentSource) || resetOffset)
        {
            logDebug2(WM_CONTENTUPDATER, "Triggering full content download");
            // Copy original data.
            auto originalData = spUpdaterContext->data;

            try
            {
                runFullContentDownload(spUpdaterContext);
            }
            catch (const SnapshotProcessingException& e)
            {
                logWarn(WM_CONTENTUPDATER, "Couldn't run full content download: %s.", e.what());
                throw;
            }
            catch (const std::exception& e)
            {
                logWarn(WM_CONTENTUPDATER, "Couldn't run full content download: %s.", e.what());
            }

            // Restore original data.
            spUpdaterContext->data = std::move(originalData);
        }

        try
        {
            // Run the updater chain
            m_spUpdaterOrchestration->handleRequest(spUpdaterContext);
        }
        catch (const std::exception& e)
        {
            throw OffsetProcessingException {e.what()};
        }
    }

    /**
     * @brief Creates and triggers a new orchestration that downloads a snapshot from CTI.
     *
     * @param spUpdaterContext Updater context.
     */
    void runFullContentDownload(std::shared_ptr<UpdaterContext> spUpdaterContext) const
    {
        logDebug1(WM_CONTENTUPDATER, "Performing full-content download");

        // Set new configuration.
        auto fullContentConfig = spUpdaterContext->spUpdaterBaseContext->configData;
        fullContentConfig.at("contentSource") = "cti-snapshot";
        fullContentConfig.at("compressionType") = "zip";

        // Trigger orchestration.
        FactoryContentUpdater::create(fullContentConfig)->handleRequest(std::move(spUpdaterContext));
    }
};

#endif // _ACTION_ORCHESTRATOR_HPP
