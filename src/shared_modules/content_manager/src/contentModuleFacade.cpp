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

#include "contentModuleFacade.hpp"
namespace Log
{
    std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
        GLOBAL_LOG_FUNCTION;
};

void ContentModuleFacade::start(
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction)
{
    Log::assignLogFunction(logFunction);
}

void ContentModuleFacade::stop()
{
    std::lock_guard<std::shared_mutex> lock {m_mutex};
    m_providers.clear();
}

void ContentModuleFacade::removeProvider(const std::string& name)
{
    std::lock_guard lock {m_mutex};
    m_providers.erase(name);
}

void ContentModuleFacade::addProvider(const std::string& name,
                                      const nlohmann::json& parameters,
                                      const FileProcessingCallback fileProcessingCallback)
{
    std::lock_guard<std::shared_mutex> lock {m_mutex};
    // If already exist throw exception
    if (m_providers.find(name) != m_providers.end())
    {
        throw std::runtime_error("Provider already exist");
    }

    m_providers.emplace(name, std::make_unique<ContentProvider>(name, parameters, fileProcessingCallback));
}

void ContentModuleFacade::startScheduling(const std::string& name, size_t interval)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        if (const auto providerIt {m_providers.find(name)}; providerIt != m_providers.end())
        {
            providerIt->second->startActionScheduler(interval);
            return;
        }
        logDebug1(WM_CONTENTUPDATER, "Couldn't start scheduled action: Provider '%s' not found.", name.c_str());
    }
    catch (const std::exception& e)
    {
        logError(WM_CONTENTUPDATER, "Couldn't start scheduled action: %s.", e.what());
    }
}
void ContentModuleFacade::startOndemand(const std::string& name)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        if (const auto providerIt {m_providers.find(name)}; providerIt != m_providers.end())
        {
            providerIt->second->startOnDemandAction();
            return;
        }
        logDebug1(WM_CONTENTUPDATER, "Couldn't start on-demand action: Provider '%s' not found.", name.c_str());
    }
    catch (const std::exception& e)
    {
        logError(WM_CONTENTUPDATER, "Couldn't start on-demand action: %s.", e.what());
    }
}

void ContentModuleFacade::changeSchedulerInterval(const std::string& name, const size_t interval)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        if (const auto providerIt {m_providers.find(name)}; providerIt != m_providers.end())
        {
            std::cout << "Changing scheduler interval for provider: " << name << " to " << interval << std::endl;
            providerIt->second->changeSchedulerInterval(interval);
            return;
        }
        std::cout << "Provider not found: " << name << std::endl;
        logDebug1(WM_CONTENTUPDATER, "Couldn't change scheduled interval: Provider '%s' not found.", name.c_str());
    }
    catch (const std::exception& e)
    {
        logError(WM_CONTENTUPDATER, "Couldn't change scheduled interval: %s.", e.what());
    }
}
