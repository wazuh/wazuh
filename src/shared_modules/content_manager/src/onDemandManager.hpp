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

#ifndef _ONDEMAND_MANAGER_HPP
#define _ONDEMAND_MANAGER_HPP

// Define the number of threads in the thread pool for httplib.
#ifndef CPPHTTPLIB_THREAD_POOL_COUNT
#define CPPHTTPLIB_THREAD_POOL_COUNT 2
#endif

#include "actionOrchestrator.hpp"
#include "singleton.hpp"
#include <external/cpp-httplib/httplib.h>
#include <functional>
#include <map>
#include <shared_mutex>

/**
 * @brief OnDemandManager class.
 *
 */
class OnDemandManager final : public Singleton<OnDemandManager>
{
private:
    httplib::Server m_server {};
    std::map<std::string, std::function<void(ActionOrchestrator::UpdateData)>> m_endpoints {};
    std::shared_mutex m_mutex {};
    std::thread m_serverThread {};
    std::atomic<bool> m_runningTrigger {true};
    void startServer();
    void stopServer();

public:
    /**
     * @brief Add an endpoint to the server and start it if it's not running
     *
     * @param endpoint Endpoint to add
     * @param func Function to call when the endpoint is called
     */
    void addEndpoint(const std::string& endpoint, std::function<void(ActionOrchestrator::UpdateData)> func);

    /**
     * @brief Remove an endpoint and stop the server if there are no more endpoints
     *
     * @param endpoint Endpoint to remove
     */
    void removeEndpoint(const std::string& endpoint);

    /**
     * @brief Clear endpoint and stop server.
     *
     */
    void clearEndpoints();
};

#endif // _ONDEMAND_MANAGER_HPP
