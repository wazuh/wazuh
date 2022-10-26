/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "server/wazuhStreamProtocol.hpp"

#include <iostream>
#include <optional>
#include <string>

#include <logging/logging.hpp>
#include <profile/profile.hpp>

using std::string;
using std::vector;

namespace engineserver
{

bool WazuhStreamProtocol::hasHeader()
{
    bool retval = false;

    if (sizeof(int) == m_buff.size())
    {
        // TODO: make this safe
        memcpy(&m_pending, m_buff.data(), sizeof(int));
        // TODO: Max message size config option
        if ((1 << 20) < m_pending)
        {
            throw std::runtime_error(
                fmt::format("Engine protocol handler: Invalid message. The size "
                            "contained on the message header is probably wrong: {}",
                            m_pending));
        }

        retval = true;
    }

    return retval;
}

std::optional<vector<string>> WazuhStreamProtocol::process(const char* data,
                                                           const size_t length)
{
    vector<string> events;

    for (size_t i = 0; length > i; i++)
    {
        switch (m_stage)
        {
            // header
            case 0:
                m_buff.push_back(data[i]);
                try
                {
                    if (hasHeader())
                    {
                        m_stage = 1;
                    }
                }
                catch (std::exception& e)
                {
                    WAZUH_LOG_ERROR("Engine protocol handler: An error ocurred while "
                                    "trying to process a message's header: {}",
                                    e.what());
                    return std::nullopt;
                }
                break;

            // payload
            case 1:
                m_buff.push_back(data[i]);
                m_pending--;
                if (0 == m_pending)
                {
                    try
                    {
                        // TODO: Are we moving the buffer? we should
                        events.push_back(
                            string(m_buff.begin() + sizeof(int), m_buff.end()));
                        m_buff.clear();
                    }
                    catch (std::exception& e)
                    {
                        WAZUH_LOG_ERROR(
                            "Engine protocol handler: Processing message error: {}",
                            e.what());
                        return std::nullopt;
                    }
                    m_stage = 0;
                }
                break;

            default:
                WAZUH_LOG_ERROR("Engine protocol handler: Invalid stage state: {}",
                                m_stage);
                return std::nullopt;
        }
    }

    return std::optional<vector<string>>(std::move(events));
}

} // namespace engineserver
