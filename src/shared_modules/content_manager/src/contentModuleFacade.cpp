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
//#include "factoryDecoder.hpp"

void ContentModuleFacade::start()
{
    // Register endpoint to receive initialization of modules from other processes.
    /*    RouterProvider::instance().initLocal(CONTENT_MODULE_ENDPOINT_NAME);
        RouterSubscriber::instance().subscriberLocal(CONTENT_MODULE_ENDPOINT_NAME,
                                                     [&](std::shared_ptr<std::vector<char>> data)
                                                     {
                                                         try
                                                         {
                                                             FactoryDecoder::create(data)->decode();
                                                         }
                                                         catch (const std::exception& e)
                                                         {
                                                             std::cerr << "start: " << e.what() << std::endl;
                                                         }
                                                     });*/
}

void ContentModuleFacade::stop()
{
    std::lock_guard<std::shared_mutex> lock {m_mutex};
    m_providers.clear();
}

void ContentModuleFacade::addProvider(const std::string& name, const nlohmann::json& parameters)
{
    std::lock_guard<std::shared_mutex> lock {m_mutex};
    // If already exist throw exception
    if (m_providers.find(name) != m_providers.end())
    {
        throw std::runtime_error("Provider already exist");
    }

    m_providers.emplace(name, std::make_unique<ContentProvider>(name, parameters));
}

void ContentModuleFacade::startScheduling(const std::string& name, size_t interval)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        m_providers.at(name)->startActionScheduler(interval);
    }
    catch (const std::exception& e)
    {
        std::cerr << "startScheduling: " << e.what() << std::endl;
    }
}
void ContentModuleFacade::startOndemand(const std::string& name)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        m_providers.at(name)->startOnDemandAction();
    }
    catch (const std::exception& e)
    {
        std::cerr << "startOndemand: " << e.what() << std::endl;
    }
}

void ContentModuleFacade::changeSchedulerInterval(const std::string& name, const size_t interval)
{
    std::shared_lock<std::shared_mutex> lock {m_mutex};
    try
    {
        m_providers.at(name)->changeSchedulerInterval(interval);
    }
    catch (const std::exception& e)
    {
        std::cerr << "changeSchedulingTime: " << e.what() << std::endl;
    }
}

