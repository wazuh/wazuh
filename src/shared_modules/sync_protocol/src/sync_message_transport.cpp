/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sync_message_transport.hpp"
#include "mqueue_transport.hpp"

namespace SyncTransportFactory
{
    std::unique_ptr<ISyncMessageTransport> createDefaultTransport(
        const std::string& moduleName,
        [[maybe_unused]] const MQ_Functions& mqFuncs,
        LoggerFunc logger,
        [[maybe_unused]] std::function<void(const std::vector<char>&)> responseCallback)
    {
        return std::make_unique<MQueueTransport>(moduleName, mqFuncs, std::move(logger));
    }
} // namespace SyncTransportFactory
