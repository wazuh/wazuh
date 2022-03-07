/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "protocolHandler.hpp"

using std::optional;
using std::string;
using std::throw_with_nested;
using std::vector;

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

json::Document ProtocolHandler::parse(const string & event)
{
    json::Document doc;
    doc.m_doc.SetObject();
    rapidjson::Document::AllocatorType & allocator = doc.getAllocator();

    auto queuePos = event.find(":");
    try
    {
        int queue = std::stoi(event.substr(0, queuePos));
        doc.m_doc.AddMember("queue", queue, allocator);
    }
    // std::out_of_range and std::invalid_argument
    catch (...)
    {
        throw_with_nested(std::invalid_argument("Error parsing queue id"));
    }

    auto locPos = event.find(":", queuePos + 1);
    try
    {
        rapidjson::Value loc;
        string location = event.substr(queuePos, locPos);
        loc.SetString(location.c_str(), location.length(), allocator);
        doc.m_doc.AddMember("location", loc, allocator);
    }
    catch (std::out_of_range & e)
    {
        throw_with_nested(("Error parsing location using token sep :" + event));
    }

    try
    {
        rapidjson::Value msg;
        string message = event.substr(locPos + 1, string::npos);
        msg.SetString(message.c_str(), message.length(), allocator);
        doc.m_doc.AddMember("message", msg, allocator);
    }
    catch (std::out_of_range & e)
    {
        throw_with_nested(("Error parsing location using token sep :" + event));
    }

    return doc;
}

optional<vector<string>> ProtocolHandler::process(char * data, size_t length)
{
    vector<string> events;

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
                        events.push_back(string(m_buff.begin() + sizeof(int), m_buff.end()));
                        m_buff.clear();
                    }
                    catch (std::exception & e)
                    {
                        LOG(ERROR) << e.what() << std::endl;
                        return std::nullopt;
                    }
                    m_stage = 0;
                }
                break;

            default:
                LOG(ERROR) << "Invalid stage value." << std::endl;
                return std::nullopt;
        }
    }

    return optional<vector<string>>(std::move(events));
}

} // namespace engineserver
