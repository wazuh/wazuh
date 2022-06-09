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

using std::string;
using std::vector;

namespace engineserver
{

enum IPVersion
{
    UNDEFINED,
    IPV4,
    IPV6
};

constexpr char FIRST_FULL_LOCATION_CHAR {'['};

bool ProtocolHandler::hasHeader()
{
    bool retval = false;

    if (m_buff.size() == sizeof(int))
    {
        // TODO: make this safe
        memcpy(&m_pending, m_buff.data(), sizeof(int));
        // TODO: Max message size config option
        if (m_pending > 1 << 20)
        {
            throw std::runtime_error("Invalid message. The size is probably wrong.");
        }

        retval = true;
    }

    return retval;
}

base::Event ProtocolHandler::parse(const string& event)
{
    int msgStartIndex {0};

    auto doc = std::make_shared<json::Document>();
    doc->m_doc.SetObject();
    rapidjson::Document::AllocatorType& allocator = doc->getAllocator();

    const auto firstColonIdx = event.find(":");
    if (1 != firstColonIdx)
    {
        throw std::runtime_error("Invalid event format. A colon should be right after "
                                 "the first character. Received Event: \""
                                 + event + "\"");
    }

    try
    {
        const int queue {event[0]};
        rapidjson::Value queueValue {queue};
        doc->set("/original/queue", queueValue);
    }
    // std::out_of_range and std::invalid_argument
    catch (...)
    {
        std::throw_with_nested(std::invalid_argument("Error parsing queue id."));
    }

    /**
     * There are two possible formats for the event:
     *
     * 1st:
     *  <Queue_ID>:[<Agent_ID>] (<Agent_Name>) <Registered_IP>-><Route>:<Log>
     *
     * 2nd:
     *  <Queue_ID>:<Syslog_Client_IP>:<Log>
     *
     * 2nd Format may be an IPv6 address, which contains ":", so special care has to be
     * taken with this particular case.
     */
    const bool isFullLocation = (FIRST_FULL_LOCATION_CHAR == event[firstColonIdx + 1]);

    const auto secondColonIdx = event.find(":", firstColonIdx + 1);

    // Case: <Queue_ID>:[<Agent_ID>] (<Agent_Name>) <Registered_IP>-><Route>:<Log>
    //                  \                                                  /
    //                   \------------------- LOCATION -------------------/
    if (isFullLocation)
    {
        int startIdx = firstColonIdx;
        int endIdx = firstColonIdx + 1;
        try
        {
            // Agent_ID index is between '[' and ']'
            startIdx += 1; // As the format goes like: ...:[<Agent_ID>....
            endIdx = event.find("]", startIdx);
            uint32_t valueSize = (endIdx - startIdx) - 1;
            const auto agentId = event.substr(startIdx + 1, valueSize).c_str();
            rapidjson::Value agentIdValue {agentId, valueSize, allocator};
            doc->set("/agent/id", agentIdValue);

            // Agent_Name is between '(' and ')'
            startIdx = endIdx + 2; // As the format goes like: ...] (<Agent_Name>...
            endIdx = event.find(")", startIdx);
            valueSize = (endIdx - startIdx) - 1;
            const auto agentName = event.substr(startIdx + 1, valueSize).c_str();
            rapidjson::Value agentNameValue {agentName, valueSize, allocator};
            doc->set("/agent/name", agentNameValue);

            // Registered_IP is between ' ' (a space) and "->" (an arrow)
            startIdx = endIdx + 1; // As the format goes like: ...) <Registered_IP>...
            endIdx = event.find("->", startIdx);
            valueSize = (endIdx - startIdx) - 1;
            const auto registeredIP = event.substr(startIdx + 1, valueSize);
            rapidjson::Value registeredIPValue {
                registeredIP.c_str(), valueSize, allocator};
            doc->set("/agent/registeredIP", registeredIPValue);

            // Route is between "->" (an arrow) and ':'
            startIdx = endIdx + 1; // As the format goes like: ...-><Route>...
            if (registeredIP.find(':') != std::string::npos)
            {
                endIdx = event.find(":", endIdx + 2);
            }
            else
            {
                endIdx = secondColonIdx;
            }
            valueSize = (endIdx - startIdx) - 1;
            const auto Route = event.substr(startIdx + 1, valueSize).c_str();
            rapidjson::Value RouteValue {Route, valueSize, allocator};
            doc->set("/original/route", RouteValue);
        }
        catch (std::out_of_range& e)
        {
            std::throw_with_nested(("Error parsing location using token sep :" + event));
        }

        msgStartIndex = endIdx + 1;
    }
    // Case: <Queue_ID>:<Syslog_Client_IP>:<Log>
    else
    {
        // It is assumed that the ip is an IPV6 unless a "." is found between the colons
        auto ipVersion = IPVersion::IPV6;
        for (int i = firstColonIdx + 1; secondColonIdx > i; i++)
        {
            if (event[i] == '.')
            {
                ipVersion = IPVersion::IPV4;
                break;
            }
        }

        if (IPVersion::IPV6 == ipVersion)
        {
            int endIdx = firstColonIdx + 1;
            for (int colonCount = 0; 8 > colonCount; endIdx++)
            {
                if (':' == event[endIdx])
                {
                    colonCount++;
                }
            }
            --endIdx;
            try
            {
                const auto locationLength = (endIdx - firstColonIdx) - 1;
                const string ipv6 = event.substr(firstColonIdx + 1, locationLength);
                rapidjson::Value ipValue {
                    ipv6.c_str(), (uint32_t)ipv6.length(), allocator};
                doc->set("/original/route", ipValue);
            }
            catch (std::out_of_range& e)
            {
                std::throw_with_nested(
                    ("Error parsing location using token sep :" + event));
            }

            msgStartIndex = endIdx + 1;
        }
        // IPVersion::IPV4
        else
        {
            try
            {
                const auto locationLength = secondColonIdx - firstColonIdx - 1;
                const string ipv4 = event.substr(firstColonIdx + 1, locationLength);
                rapidjson::Value ipValue {
                    ipv4.c_str(), (uint32_t)ipv4.length(), allocator};
                doc->set("/original/route", ipValue);
            }
            catch (std::out_of_range& e)
            {
                std::throw_with_nested(
                    ("Error parsing location using token sep :" + event));
            }

            msgStartIndex = secondColonIdx + 1;
        }
    }

    try
    {
        const string message = event.substr(msgStartIndex, string::npos);
        rapidjson::Value msg {
            message.c_str(), (rapidjson::SizeType)message.length(), allocator};
        doc->set("/original/message", msg);
    }
    catch (std::out_of_range& e)
    {
        std::throw_with_nested(("Error parsing location using token sep :" + event));
    }

    // TODO Create event here
    return  std::make_shared<json::Json>(std::move(doc));
}

std::optional<vector<string>> ProtocolHandler::process(const char* data,
                                                       const size_t length)
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
                        // TODO: Are we moving the buffer? we should
                        events.push_back(
                            string(m_buff.begin() + sizeof(int), m_buff.end()));
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

    return std::optional<vector<string>>(std::move(events));
}

} // namespace engineserver
