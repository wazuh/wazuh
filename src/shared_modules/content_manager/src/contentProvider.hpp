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

#ifndef _CONTENT_PROVIDER_HPP
#define _CONTENT_PROVIDER_HPP

#include "action.hpp"
#include <external/nlohmann/json.hpp>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>

/**
 * @brief ContentProvider class.
 *
 */
class ContentProvider final
{
private:
    std::shared_ptr<Action> m_action;

public:
    /**
     * @brief Class constructor.
     *
     * @param topicName Topic name.
     * @param parameters Action orchestrator parameters.
     * @param fileProcessingCallback Callback function in charge of the file processing task.
     */
    explicit ContentProvider(const std::string& topicName,
                             const nlohmann::json& parameters,
                             FileProcessingCallback fileProcessingCallback)
    {
        m_action = std::make_shared<Action>(topicName, parameters, fileProcessingCallback);
    }

    ~ContentProvider()
    {
        m_action.reset();
    }

    /**
     * @brief Starts action scheduler.
     *
     * @param interval Scheduler interval.
     */
    void startActionScheduler(const size_t interval)
    {
        m_action->startActionScheduler(interval);
    }

    /**
     * @brief Starts ondeman action.
     *
     */
    void startOnDemandAction()
    {
        m_action->registerActionOnDemand();
    }

    /**
     * @brief Changes scheduler interval.
     *
     * @param interval New scheduler interval.
     */
    void changeSchedulerInterval(const size_t interval)
    {
        m_action->changeSchedulerInterval(interval);
    }
};

#endif //_CONTENT_PROVIDER_HPP
