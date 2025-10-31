/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "mqueue_transport.hpp"
#include "defs.h"
#include <thread>

constexpr char SYNC_MQ = 's';

MQueueTransport::MQueueTransport(const std::string& moduleName, MQ_Functions mqFuncs, LoggerFunc logger)
    : m_moduleName(moduleName)
    , m_mqFuncs(mqFuncs)
    , m_logger(std::move(logger))
{
}

void MQueueTransport::shutdown()
{
    // MQueue does not have a shutdown function
}

bool MQueueTransport::checkStatus()
{
    if (!ensureQueueAvailable())
    {
        m_logger(LOG_ERROR, "Failed to open queue: " + std::string(DEFAULTQUEUE));
        return false;
    }

    return true;
}

bool MQueueTransport::sendMessage(const std::vector<uint8_t>& message, size_t maxEps)
{
    if (m_mqFuncs.send_binary(m_queue, message.data(), message.size(), m_moduleName.c_str(), SYNC_MQ) < 0)
    {
        m_logger(LOG_ERROR, "SendMSG failed, attempting to reinitialize queue...");
        m_queue = m_mqFuncs.start(DEFAULTQUEUE, WRITE, 0);

        if (m_queue < 0 ||
                m_mqFuncs.send_binary(m_queue, message.data(), message.size(), m_moduleName.c_str(), SYNC_MQ) < 0)
        {
            m_logger(LOG_ERROR, "SendMSG failed to send message after retry");
            return false;
        }
    }

    if (maxEps > 0)
    {
        if (++m_msgSent >= maxEps)
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            m_msgSent.store(0);
        }
    }

    return true;
}

bool MQueueTransport::ensureQueueAvailable()
{
    try
    {
        if (m_queue < 0)
        {
            m_queue = m_mqFuncs.start(DEFAULTQUEUE, WRITE, 0);

            if (m_queue < 0)
            {
                return false;
            }
        }

        return true;
    }
    catch (const std::exception& e)
    {
        m_logger(LOG_ERROR, std::string("Exception when checking queue availability: ") + e.what());
    }

    return false;
}
