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
#include "routerProvider.hpp"
#include "routerSubscriber.hpp"
#include <external/nlohmann/json.hpp>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

/**
 * @brief ContentProvider
 *
 */
class ContentProvider final
{
private:
    std::shared_ptr<Action> m_action;
    std::shared_ptr<RouterProvider> m_routerProvider;

public:
    /**
     * @brief Construct a new Content Provider object
     *
     * @param topicName
     * @param parameters
     */
    explicit ContentProvider(const std::string& topicName, const nlohmann::json& parameters)
        : m_routerProvider(std::make_shared<RouterProvider>(topicName))
    {
        m_routerProvider->start();
        m_action = std::make_shared<Action>(m_routerProvider, topicName, parameters);
    }

    ~ContentProvider()
    {
        m_action->unregisterActionOnDemand();
        m_action->stopActionScheduler();
        m_routerProvider.reset();
    }

    /**
     * @brief
     *
     * @param interval
     */
    void startActionScheduler(const size_t interval)
    {
        m_action->startActionScheduler(interval);
    }

    /**
     * @brief startOnDemandAction
     *
     */
    void startOnDemandAction()
    {
        m_action->registerActionOnDemand();
    }

    /**
     * @brief
     *
     * @param interval
     */
    void changeSchedulerInterval(const size_t interval)
    {
        m_action->changeSchedulerInterval(interval);
    }
};

#endif //_CONTENT_PROVIDER_HPP
