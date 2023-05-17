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

#include "singleton.hpp"
#include <external/cpp-httplib/httplib.h>
#include <functional>
#include <map>
#include <shared_mutex>

class OnDemandManager final : public Singleton<OnDemandManager>
{
private:
    httplib::Server m_server {};
    std::map<std::string, std::function<void()>> m_endpoints {};
    std::shared_mutex m_mutex {};
    std::thread m_serverThread {};
    void startServer();
    void stopServer();

public:
    void addEndpoint(const std::string& endpoint, std::function<void()> func);
    void removeEndpoint(const std::string& endpoint);
    void clearEndpoints();
};

#endif // _ONDEMAND_MANAGER_HPP
