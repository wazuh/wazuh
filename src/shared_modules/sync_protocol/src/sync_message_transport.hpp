/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <memory>
#include <functional>
#include <string>
#include <vector>

#include "isync_message_transport.hpp"
#include "agent_sync_protocol_c_interface_types.h"
#include "agent_sync_protocol_types.hpp"

namespace SyncTransportFactory
{
    std::unique_ptr<ISyncMessageTransport> createDefaultTransport(
        const std::string& moduleName,
        const MQ_Functions& mqFuncs,
        LoggerFunc logger,
        std::function<void(const std::vector<char>&)> responseCallback = nullptr);
} // namespace SyncTransportFactory
