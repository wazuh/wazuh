/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ACTION_MODULE_HPP
#define _ACTION_MODULE_HPP

#include "actionOrchestrator.hpp"
#include "conditionSync.hpp"
#include "onDemandManager.hpp"
#include "routerProvider.hpp"
#include "updaterContext.hpp"
#include <atomic>
#include <chrono>
#include <external/nlohmann/json.hpp>
#include <filesystem>
#include <thread>
#include <utility>

enum ActionID
{
    SCHEDULED,
    ON_DEMAND
};

enum UpdaterType
{
    CONTENT,
    OFFSET
};

/**
 * @brief Action class.
 *
 */
class Action final
{
public:
    /**
     * @brief Class constructor.
     *
     * @param channel Router provider.
     * @param topicName Topic name.
     * @param parameters ActionOrchestrator parameters.
     */
    explicit Action(const std::shared_ptr<RouterProvider> channel, std::string topicName, nlohmann::json parameters)
        : m_channel {channel}
        , m_actionInProgress {false}
        , m_cv {}
        , m_topicName {std::move(topicName)}
        , m_interval {0}
        , m_stopActionCondition {std::make_shared<ConditionSync>(false)}
        , m_orchestration {std::make_unique<ActionOrchestrator>(channel, parameters, m_stopActionCondition)}
    {
        m_parameters = parameters;

        // Init RocksDB connector.
        std::shared_ptr<Utils::RocksDBWrapper> spDatabaseConnector;
        if (m_parameters.at("configData").contains("databasePath"))
        {
            const auto& databasePath {m_parameters.at("configData").at("databasePath").get_ref<const std::string&>()};
            spDatabaseConnector = std::make_shared<Utils::RocksDBWrapper>(databasePath);
        }

        // Create content updater orchestration.
        m_orchestration = std::make_unique<ActionOrchestrator>(channel, parameters, m_shouldRun, spDatabaseConnector);

        // Create offset updater orchestration.
        m_offsetUpdaterTopicName = "offset_updater";
        parameters.at("topicName") = m_offsetUpdaterTopicName;
        m_offsetUpdaterOrchestration =
            std::make_unique<OffsetUpdaterOrchestrator>(std::move(parameters), m_shouldRun, spDatabaseConnector);
    }

    /**
     * @brief Class destructor. Stops the action execution if it's in progress.
     *
     */
    ~Action()
    {
        // Stop running action, if any.
        m_stopActionCondition->set(true);

        unregisterActionOnDemand(m_topicName);
        unregisterActionOnDemand(m_offsetUpdaterTopicName);
        stopActionScheduler();
    }

    /**
     * @brief Action execution with exclusivity: The action is only executed if there isn't another action in progress.
     *
     * @param id Action ID.
     * @param offset Manually set current offset to process.
     *
     * @return True if the execution was made, false otherwise.
     */
    bool runActionExclusively(const ActionID id, const UpdaterType type, const int offset = -1)
    {
        auto expectedValue {false};
        if (m_actionInProgress.compare_exchange_strong(expectedValue, true))
        {
            runAction(id, type, offset);
        }
        return !expectedValue;
    }

    /**
     * @brief Action scheduler start.
     *
     * @param interval Scheduler interval.
     */
    void startActionScheduler(const size_t interval)
    {
        m_schedulerRunning = true;
        m_interval = interval;
        m_schedulerThread = std::thread(
            [this]()
            {
                // Use while with condition variable to avoid spurious wakeups.
                std::unique_lock<std::mutex> lock(m_mutex);

                // Run action on start, independently of the interval time.
                runActionScheduled();

                while (m_schedulerRunning)
                {
                    m_cv.wait_for(lock, std::chrono::seconds(this->m_interval));
                    if (m_schedulerRunning)
                    {
                        runActionScheduled();
                    }
                }
            });
    }

    /**
     * @brief Runs scheduled action. Wrapper of runActionExclusively().
     *
     */
    void runActionScheduled()
    {
        logInfo(WM_CONTENTUPDATER, "Starting scheduled action for '%s'", m_topicName.c_str());
        if (!runActionExclusively(ActionID::SCHEDULED, UpdaterType::CONTENT))
        {
            logInfo(WM_CONTENTUPDATER, "Action in progress for '%s', scheduled request ignored", m_topicName.c_str());
        }
    }

    /**
     * @brief Stops action scheduler.
     *
     */
    void stopActionScheduler()
    {
        m_schedulerRunning = false;
        m_cv.notify_one();

        if (m_schedulerThread.joinable())
        {
            m_schedulerThread.join();
        }
        logInfo(WM_CONTENTUPDATER, "Scheduler stopped for '%s'", m_topicName.c_str());
    }

    /**
     * @brief Registers new ondemand action.
     *
     */
    void registerActionOnDemand(const UpdaterType type)
    {
        OnDemandManager::instance().addEndpoint(m_topicName,
                                                [&type, this](int offset) { this->runActionOnDemand(type, offset); });
    }

    /**
     * @brief Unregisters ondemand action.
     *
     */
    void unregisterActionOnDemand(const std::string& topicName)
    {
        OnDemandManager::instance().removeEndpoint(topicName);
    }

    /**
     * @brief Clear all endpoints.
     *
     */
    void clearEndpoints()
    {
        OnDemandManager::instance().clearEndpoints();
    }

    /**
     * @brief Runs ondemand action. Wrapper of runActionExclusively().
     *
     * @param offset Manually set current offset to process. Default -1
     */
    void runActionOnDemand(const UpdaterType type, const int offset = -1)
    {
        logInfo(WM_CONTENTUPDATER, "Starting on-demand action for '%s'", m_topicName.c_str());
        if (!runActionExclusively(ActionID::ON_DEMAND, type, offset))
        {
            logInfo(WM_CONTENTUPDATER, "Action in progress for '%s', on-demand request ignored", m_topicName.c_str());
        }
    }

    /**
     * @brief Changes scheduler interval.
     *
     * @param interval New interval value.
     */
    void changeSchedulerInterval(size_t interval)
    {
        m_interval = interval;
        m_cv.notify_one();
    }

private:
    std::shared_ptr<RouterProvider> m_channel;
    std::thread m_schedulerThread;
    std::atomic<bool> m_schedulerRunning = false;
    std::atomic<bool> m_actionInProgress;
    std::atomic<size_t> m_interval;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::string m_topicName;
    std::string m_offsetUpdaterTopicName;
    nlohmann::json m_parameters;
    std::shared_ptr<ConditionSync> m_stopActionCondition;
    std::unique_ptr<ActionOrchestrator> m_orchestration;

    void runAction(const ActionID id, const UpdaterType type, const int offset = -1)
    {
        logInfo(WM_CONTENTUPDATER, "Action for '%s' started", m_topicName.c_str());

        try
        {
            if (type == UpdaterType::CONTENT)
            {
                m_orchestration->run(offset);
            }
            else
            {
                m_offsetUpdaterOrchestration->run(offset);
            }
        }
        catch (const std::exception& e)
        {
            logError(WM_CONTENTUPDATER, "Action for '%s' failed: %s", m_topicName.c_str(), e.what());
        }

        logInfo(WM_CONTENTUPDATER, "Action for '%s' finished", m_topicName.c_str());
        m_actionInProgress = false;
    }
};

#endif // _ACTION_MODULE_HPP
