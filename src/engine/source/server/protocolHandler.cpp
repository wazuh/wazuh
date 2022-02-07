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

/**
 * @brief Update pending value and return true if we have enough data
 * to calculate the message size.
 *
 * @return true
 * @return false
 */
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

/**
 * @brief Process a message, parsing it and sending it to s
 *
 * @param s a subscriber of this connection.
 */
void ProtocolHandler::send(const rxcpp::subscriber<json::Document> s)
{
    json::Document evt;
    try
    {
        evt = parse();
        m_buff.clear();
    }
    catch (std::exception & e)
    {
        LOG(ERROR) << e.what() << std::endl;
        s.on_error(std::current_exception());
    }

    s.on_next(evt);
}

/**
 * @brief generate a json::Document from internal state
 * 
 * @return json::Document 
 */
json::Document ProtocolHandler::parse()
{
    json::Document doc;
    doc.m_doc.SetObject();
    rapidjson::Document::AllocatorType & allocator = doc.getAllocator();

    auto event = std::string(m_buff.begin() + sizeof(int), m_buff.end());

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

/**
 * @brief Process the data chunk and send all complete
 * messages to the subscriber s
 * 
 * @param data data to process
 * @param length length of data
 * @param s subscriber
 */
bool ProtocolHandler::process(char * data, std::size_t length, const rxcpp::subscriber<json::Document> s)
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
                    s.on_error(std::current_exception());
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
