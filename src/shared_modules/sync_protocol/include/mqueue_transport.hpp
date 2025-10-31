/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "agent_sync_protocol_c_interface_types.h"
#include "agent_sync_protocol_types.hpp"
#include "isync_message_transport.hpp"
#include <atomic>

/**
 * @brief MQueue-based transport for remote agents.
 */
class MQueueTransport : public ISyncMessageTransport
{
    public:
        MQueueTransport(const std::string& moduleName, MQ_Functions mqFuncs, LoggerFunc logger);
        bool sendMessage(const std::vector<uint8_t>& message, size_t maxEps) override;
        void shutdown() override;
        bool checkStatus() override;

    private:
        bool ensureQueueAvailable();
        std::string m_moduleName;
        MQ_Functions m_mqFuncs;
        LoggerFunc m_logger;
        int m_queue = -1;
        std::atomic<size_t> m_msgSent {0};
};
