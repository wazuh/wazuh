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
#include <iostream>
#include <thread>
#include <utility>

enum ActionID
{
    SCHEDULED,
    ON_DEMAND
};

/**
 * @brief Action
 *
 */
class Action final
{
public:
    /**
     * @brief Construct a new Action object
     *
     * @param channel
     * @param topicName
     * @param parameters
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
     * @brief
     *
     * @param interval
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
                while (m_schedulerRunning)
                {
                    m_cv.wait_for(lock, std::chrono::seconds(this->m_interval));
                    if (m_schedulerRunning)
                    {
                        bool expected = false;
                        if (m_actionInProgress.compare_exchange_strong(expected, true))
                        {
                            std::cout << "Action: Initiating scheduling action for " << m_topicName << std::endl;
                            runAction(ActionID::SCHEDULED);
                        }
                        else
                        {
                            std::cerr << "Action: Request scheduling - Download in progress. "
                                         "The scheduling is ignored for "
                                      << m_topicName << std::endl;
                        }
                    }
                }
            });
    }

    /**
     * @brief stopActionScheduler
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
        std::cout << "Action: Scheduler stopped for " << m_topicName << std::endl;
    }

    /**
     * @brief registerActionOnDemand
     *
     */
    void registerActionOnDemand()
    {
        OnDemandManager::instance().addEndpoint(m_topicName, [this]() { this->runActionOnDemand(); });
    }

    /**
     * @brief unregisterActionOnDemand
     *
     */
    void unregisterActionOnDemand()
    {
        OnDemandManager::instance().removeEndpoint(m_topicName);
    }

    /**
     * @brief runActionOnDemand
     *
     */
    void runActionOnDemand()
    {
        auto expected = false;
        if (m_actionInProgress.compare_exchange_strong(expected, true))
        {
            std::cout << "Action: Ondemand request - starting action for " << m_topicName << std::endl;
            runAction(ActionID::ON_DEMAND);
        }
        else
        {
            std::cerr << "Action: Ondemand request - another action in progress for " << m_topicName << std::endl;
        }
    }

    /**
     * @brief
     *
     * @param interval
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
        m_orchestration->run();

        m_actionInProgress = false;
    }
};

#endif // _ACTION_MODULE_HPP
