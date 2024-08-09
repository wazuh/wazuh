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

#ifndef _CONTENT_MODULE_IMPLEMENTATION_HPP
#define _CONTENT_MODULE_IMPLEMENTATION_HPP

#include "contentProvider.hpp"
#include <filesystem>

constexpr auto CONTENT_MODULE_ENDPOINT_NAME {"content"};

/**
 * @brief ContentModuleFacade class.
 *
 */
class ContentModuleFacade final : public Singleton<ContentModuleFacade>
{
private:
    std::unordered_map<std::string, std::unique_ptr<ContentProvider>> m_providers;
    std::shared_mutex m_mutex;

public:
    /**
     * @brief Register endpoint to receive initialization of modules from other processes.
     *
     * @param logFunction Log function.
     */
    void start(const std::function<void(const int,
                                        const std::string&,
                                        const std::string&,
                                        const int,
                                        const std::string&,
                                        const std::string&,
                                        va_list)>& logFunction);

    /**
     * @brief Clear providers.
     *
     */
    void stop();

    /**
     * @brief Adds a new provider.
     *
     * @param name Provider name.
     * @param parameters Provider parameters.
     */
    void addProvider(const std::string& name, const nlohmann::json& parameters);

    /**
     * @brief Starts action scheduler.
     *
     * @param name Provider name.
     * @param interval Scheduler interval.
     * @param shouldRun Condition to run or not an action.
     */
    void startScheduling(const std::string& name, size_t interval, const std::atomic<bool>& shouldRun = true);

    /**
     * @brief Starts ondeman action.
     *
     * @param name Provider name.
     */
    void startOndemand(const std::string& name);

    /**
     * @brief Changes scheduler interval.
     *
     * @param name Provider name.
     * @param interval New scheduler interval.
     */
    void changeSchedulerInterval(const std::string& name, size_t interval);

    /**
     * @brief Wakes up scheduled action thread.
     *
     * @param name Provider name.
     */
    void wakeUpThread(const std::string& name);
};

#endif //_CONTENT_MODULE_IMPLEMENTATION_HPP
