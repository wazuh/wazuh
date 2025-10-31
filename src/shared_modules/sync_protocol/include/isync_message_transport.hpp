/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstdint>
#include <vector>

/**
 * @brief Abstract interface for sending sync messages.
 *
 * Separates sync protocol logic from transport mechanism.
 */
class ISyncMessageTransport
{
    public:
        virtual ~ISyncMessageTransport() = default;

        /**
         * @brief Send a sync message.
         * @param message FlatBuffer message to send
         * @param maxEps Max events per second (0 = unlimited)
         * @return true on success, false on failure
         */
        virtual bool sendMessage(const std::vector<uint8_t>& message, size_t maxEps) = 0;

        /**
         * @brief Shutdown the transport.
         */
        virtual void shutdown() = 0;

        /**
         * @brief Check the status of the transport.
         */
        virtual bool checkStatus() = 0;
};
