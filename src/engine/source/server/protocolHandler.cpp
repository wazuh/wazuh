/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "protocolHandler.hpp"
#include "glog/logging.h"

namespace engineserver
{

bool ProtocolHandler::hasHeader()
{
    if (m_buff.size() == sizeof(int))
    {
        // TODO: make this safe
        std::memcpy(&m_pending, m_buff.data(), sizeof(int));
        // TODO: Max message size config option
        if (m_pending > 1 << 20)
        {
            throw std::runtime_error("Invalid message. Size probably wrong");
        }
        return true;
    }
    return false;
}

void ProtocolHandler::send(const rxcpp::subscriber<rxcpp::observable<std::string>> s)
{
    std::string evt;
    try
    {
        evt = std::string(m_buff.begin() + sizeof(int), m_buff.end());
        m_buff.clear();
    }
    catch (std::exception & e)
    {
        LOG(ERROR) << e.what() << std::endl;
        s.on_error(std::current_exception());
        return;
    }

    s.on_next(rxcpp::observable<>::just(evt));
}

json::Document ProtocolHandler::parse(const std::string & event) const
{
    json::Document doc;
    doc.m_doc.SetObject();
    rapidjson::Document::AllocatorType & allocator = doc.getAllocator();

    // auto event = std::string(m_buff.begin() + sizeof(int), m_buff.end());

    auto queuePos = event.find(":");
    try
    {
        int queue = std::stoi(event.substr(0, queuePos));
        doc.m_doc.AddMember("queue", queue, allocator);
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
        std::string location = event.substr(queuePos, locPos);
        loc.SetString(location.c_str(), location.length(), allocator);
        doc.m_doc.AddMember("location", loc, allocator);
    }
    catch (std::out_of_range & e)
    {
        std::throw_with_nested(("Error parsing location using token sep :" + event));
    }

    try
    {
        rapidjson::Value msg;
        std::string message = event.substr(locPos + 1, std::string::npos);
        msg.SetString(message.c_str(), message.length(), allocator);
        doc.m_doc.AddMember("message", msg, allocator);
    }
    catch (std::out_of_range & e)
    {
        std::throw_with_nested(("Error parsing location using token sep :" + event));
    }

    return doc;
}

bool ProtocolHandler::process(char * data, std::size_t length,
                              const rxcpp::subscriber<rxcpp::observable<std::string>> s)
{
    for (std::size_t i = 0; i < length; i++)
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
                    // s.on_error(std::current_exception());
                    return false;
                }
                break;
            // payload
            case 1:
                m_buff.push_back(data[i]);
                m_pending--;
                if (m_pending == 0)
                {
                    send(s);
                    m_stage = 0;
                }
                break;
        }
    }
    return true;
}
} // namespace engineserver
