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
#include "onDemandManager.hpp"
#include "routerProvider.hpp"
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
        , m_orchestration {std::make_unique<ActionOrchestrator>(channel, parameters)}
    {
        m_parameters = std::move(parameters);
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
                runAction(ActionID::SCHEDULED);

                while (m_schedulerRunning)
                {
                    m_cv.wait_for(lock, std::chrono::seconds(this->m_interval));
                    if (m_schedulerRunning)
                    {
                        bool expected = false;
                        if (m_actionInProgress.compare_exchange_strong(expected, true))
                        {
                            logInfo(WM_CONTENTUPDATER, "Initiating scheduling action for %s", m_topicName.c_str());
                            runAction(ActionID::SCHEDULED);
                        }
                        else
                        {
                            // LCOV_EXCL_START
                            logInfo(WM_CONTENTUPDATER,
                                    "Request scheduling - Download in progress. The scheduling is ignored for %s",
                                    m_topicName.c_str());
                            // LCOV_EXCL_STOP
                        }
                    }
                }
            });
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
    void registerActionOnDemand()
    {
        OnDemandManager::instance().addEndpoint(m_topicName, [this]() { this->runActionOnDemand(); });
    }

    /**
     * @brief Unregisters ondemand action.
     *
     */
    void unregisterActionOnDemand()
    {
        OnDemandManager::instance().removeEndpoint(m_topicName);
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
     * @brief Runs ondemand action.
     *
     */
    void runActionOnDemand()
    {
        auto expected = false;
        if (m_actionInProgress.compare_exchange_strong(expected, true))
        {
            logInfo(WM_CONTENTUPDATER, "Ondemand request - Starting action for %s", m_topicName.c_str());
            runAction(ActionID::ON_DEMAND);
        }
        else
        {
            // LCOV_EXCL_START
            logInfo(WM_CONTENTUPDATER, "Ondemand request - Another action in progress for %s", m_topicName.c_str());
            // LCOV_EXCL_STOP
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
    bool m_schedulerRunning = false;
    std::atomic<bool> m_actionInProgress;
    std::atomic<size_t> m_interval;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::string m_topicName;
    nlohmann::json m_parameters;
    std::unique_ptr<ActionOrchestrator> m_orchestration;

    void runAction(const ActionID id)
    {
        try
        {
            m_orchestration->run();
        }
        catch (const std::exception& e)
        {
            logError(WM_CONTENTUPDATER, "Action for '%s' failed: %s", m_topicName.c_str(), e.what());
        }

        m_actionInProgress = false;
    }
};

#endif // _ACTION_MODULE_HPP
