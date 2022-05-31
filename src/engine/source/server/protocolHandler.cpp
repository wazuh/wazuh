/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "protocolHandler.hpp"

#include <iostream>
#include <optional>
#include <string>

#include <logging/logging.hpp>
#include <profile/profile.hpp>

namespace engineserver
{

bool ProtocolHandler::hasHeader()
{
    if (m_buff.size() == sizeof(int))
    {
        // TODO: make this safe
        memcpy(&m_pending, m_buff.data(), sizeof(int));
        // TODO: Max message size config option
        if (m_pending > 1 << 20)
        {
            throw std::runtime_error("Invalid message. Size probably wrong");
        }
        return true;
    }
    return false;
}

base::Event ProtocolHandler::parse(const std::string& event)
{
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType& allocator = doc.GetAllocator();

    auto queuePos = event.find(":");
    try
    {
        int queue = std::stoi(event.substr(0, queuePos));
        doc.AddMember("queue", queue, allocator);
    }
    // std::out_of_range and std::invalid_argument
    catch (...)
    {
        std::throw_with_nested(std::invalid_argument("Error parsing queue id"));
    }

    auto locPos = event.find(":", queuePos + 1);
    try
    {
        rapidjson::Value loc;
        std::string location = event.substr(queuePos + 1, locPos - queuePos - 1);
        loc.SetString(location.c_str(), location.length(), allocator);
        doc.AddMember("location", loc, allocator);
    }
    catch (std::out_of_range& e)
    {
        std::throw_with_nested(("Error parsing location using token sep :" + event));
    }

    try
    {
        rapidjson::Value msg;
        std::string message = event.substr(locPos + 1, std::string::npos);
        msg.SetString(message.c_str(), message.length(), allocator);
        doc.AddMember("message", msg, allocator);
    }
    catch (std::out_of_range& e)
    {
        std::throw_with_nested(("Error parsing location using token sep :" + event));
    }

    // TODO Create event here
    return  std::make_shared<json::Json>(std::move(doc));
}

std::optional<std::vector<std::string>> ProtocolHandler::process(const char* data,
                                                                 const size_t length)
{
    std::vector<std::string> events;

    for (size_t i = 0; i < length; i++)
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
                catch (...)
                {
                    // TODO: improve this try-catch
                    return std::nullopt;
                }
                break;

            // payload
            case 1:
                m_buff.push_back(data[i]);
                m_pending--;
                if (m_pending == 0)
                {
                    try
                    {
                        // TODO: Are we moving the buffer? we should
                        events.push_back(
                            std::string(m_buff.begin() + sizeof(int), m_buff.end()));
                        m_buff.clear();
                    }
                    catch (std::exception& e)
                    {
                        WAZUH_LOG_ERROR("{}", e.what());
                        return std::nullopt;
                    }
                    m_stage = 0;
                }
                break;

            default: WAZUH_LOG_ERROR("Invalid stage value."); return std::nullopt;
        }
    }

    return std::optional<std::vector<std::string>>(std::move(events));
}

} // namespace engineserver
