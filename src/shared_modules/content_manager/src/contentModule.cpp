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

#include "contentManager.hpp"
#include "contentModuleFacade.hpp"
#include "contentRegister.hpp"
#include "content_manager.h"
#include <utility>

void ContentModule::start(const std::function<void(const modules_log_level_t, const std::string&)>& /*logFunction*/)
{
    ContentModuleFacade::instance().start();
}

void ContentModule::stop()
{
    ContentModuleFacade::instance().stop();
}

ContentRegister::ContentRegister(std::string name, const nlohmann::json& parameters)
    : m_name {std::move(name)}
{
    ContentModuleFacade::instance().addProvider(m_name, parameters);

    if (parameters.contains("interval"))
    {
        ContentModuleFacade::instance().startScheduling(m_name, parameters.at("interval").get<size_t>());
    }

    if (parameters.contains("ondemand"))
    {
        if (parameters.at("ondemand").get<bool>())
        {
            ContentModuleFacade::instance().startOndemand(m_name);
        }
    }
}

void ContentRegister::changeSchedulerInterval(const size_t newInterval)
{
    ContentModuleFacade::instance().changeSchedulerInterval(m_name, newInterval);
}

#ifdef __cplusplus
extern "C"
{
#endif

    void content_manager_start(log_callback_t callbackLog)
    {
        std::ignore = callbackLog;
        ContentModuleFacade::instance().start();
    }

    void content_manager_stop()
    {
        ContentModuleFacade::instance().stop();
    }

#ifdef __cplusplus
}
#endif

