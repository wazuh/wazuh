/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// sync_message_transport.hpp
#pragma once

#include <memory>
#include <functional>
#include <string>
#include <vector>

#include "isync_message_transport.hpp"
#include "agent_sync_protocol_c_interface_types.h" // for MQ_Functions, LoggerFunc

namespace SyncTransportFactory {

#if CLIENT
// Agent build (MQ)
std::unique_ptr<ISyncMessageTransport> createDefaultTransport(
    const std::string& moduleName,
    const MQ_Functions& mqFuncs,
    LoggerFunc logger,
    std::function<void(const std::vector<char>&)> /*responseCallback*/ = nullptr);
#else
// Manager build (Router)
std::unique_ptr<ISyncMessageTransport> createDefaultTransport(
    const std::string& agentId,
    const std::string& agentName,
    const std::string& agentIp,
    const std::string& moduleName,
    LoggerFunc logger,
    std::function<void(const std::vector<char>&)> responseCallback);
#endif

} // namespace SyncTransportFactory
