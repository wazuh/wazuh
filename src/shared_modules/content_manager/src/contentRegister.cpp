/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include "contentRegister.hpp"
#include "contentLogging.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include "topicDriver.hpp"
#include <utility>

namespace Log
{
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
}; // namespace Log

void content_manager::setLogFunction(const LogFunction& logFunction, const std::string& tag)
{
    content_manager::detail::logTag() = tag;
    Log::assignLogFunction(logFunction);
}

ContentRegister::ContentRegister(std::string topicName,
                                 const content_manager::TopicSpec& spec,
                                 std::shared_ptr<content_manager::IContentSink> sink,
                                 std::shared_ptr<content_manager::IContentIndexer> indexer,
                                 std::shared_ptr<content_manager::IContentTokenStore> tokenStore)
    : m_driver {std::make_unique<TopicDriver>(
          std::move(topicName), spec, std::move(sink), std::move(indexer), std::move(tokenStore))}
{
}

ContentRegister::~ContentRegister() = default;

content_manager::CycleOutcome ContentRegister::runOnce(content_manager::RunRequest req) noexcept
{
    return m_driver->runOnce(req);
}

void ContentRegister::requestRun(content_manager::RunRequest req,
                                 std::function<void(content_manager::OnDemandResult)> completion) noexcept
{
    m_driver->requestRun(req, std::move(completion));
}

std::string ContentRegister::currentToken() const noexcept
{
    return m_driver->currentToken();
}

void ContentRegister::requestStop() noexcept
{
    m_driver->requestStop();
}
