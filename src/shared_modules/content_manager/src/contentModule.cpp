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
#include <stdexcept>
#include <utility>

void ContentModule::start(
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction)
{
    ContentModuleFacade::instance().start(logFunction);
}

void ContentModule::stop()
{
    ContentModuleFacade::instance().stop();
}

ContentRegister::ContentRegister(std::string name,
                                 const nlohmann::json& parameters,
                                 std::shared_ptr<content_manager::IContentSink> sink,
                                 std::shared_ptr<content_manager::IContentTokenStore> tokenStore,
                                 std::uint32_t contractVersion)
    : m_name {std::move(name)}
{
    // The host compiled `contractVersion` in from its own copy of contentTypes.hpp. A mismatch means
    // the two sides disagree about the layout of the structs they are about to exchange across a
    // DSO boundary, which is not something either of them can detect later.
    if (contractVersion != content_manager::CONTRACT_ABI_VERSION)
    {
        throw std::invalid_argument {"Content contract version mismatch: the caller was built against version " +
                                     std::to_string(contractVersion) + ", this library implements version " +
                                     std::to_string(content_manager::CONTRACT_ABI_VERSION)};
    }

    if (!sink)
    {
        throw std::invalid_argument {"A content sink is required to register '" + m_name + "'"};
    }

    ContentModuleFacade::instance().addProvider(m_name, parameters, std::move(sink), std::move(tokenStore));

    if (parameters.contains("interval"))
    {
        ContentModuleFacade::instance().startScheduling(m_name, parameters.at("interval").get<size_t>());
    }

    if (parameters.value("ondemand", false))
    {
        ContentModuleFacade::instance().startOndemand(m_name);
    }
}

ContentRegister::~ContentRegister()
{
    ContentModuleFacade::instance().removeProvider(m_name);
}

content_manager::CycleOutcome ContentRegister::runOnce(content_manager::RunRequest req) noexcept
{
    return ContentModuleFacade::instance().runOnce(m_name, req);
}

std::string ContentRegister::currentToken() const noexcept
{
    return ContentModuleFacade::instance().currentToken(m_name);
}

void ContentRegister::requestStop() noexcept
{
    ContentModuleFacade::instance().requestStop(m_name);
}

void ContentRegister::changeSchedulerInterval(const size_t newInterval)
{
    ContentModuleFacade::instance().changeSchedulerInterval(m_name, newInterval);
}
