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

constexpr int LOCATION_OFFSET = 2; // Given the "q:" prefix.
constexpr char FIRST_FULL_LOCATION_CHAR {'['};

bool ProtocolHandler::hasHeader()
{
    bool retval = false;

    if (m_buff.size() == sizeof(int))
    {
        // TODO: make this safe
        memcpy(&m_pending, m_buff.data(), sizeof(int));
        // TODO: Max message size config option
        if ((1 << 20) < m_pending)
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

    /**
     * There are two possible formats of events:
     *
     * 1st:
     *  <Queue_ID>:[<Agent_ID>] (<Agent_Name>) <Registered_IP>-><Route>:<Log>
     *
     * 2nd:
     *  <Queue_ID>:<Syslog_Client_IP>:<Log>
     *
     *
     * Notes:
     *
     *  - `Queue_ID` is always 1 byte long.
     *
     *  - `Syslog_Client_IP` and `Registered_IP` and can be either IPv4 or IPv6.
     *
     *  - 2nd Format may be an IPv6 address, which contains ":", so special care has to be
     * taken with this particular case.
     */

    if (':' != event[1])
    {
        throw std::runtime_error("Invalid event format. A colon should be right after "
                                 "the first character. Received Event: \""
                                 + event + "\"");
    }

    if (event.length() <= 4)
    {
        throw std::runtime_error(
            "Invalid event format. Event is too short. Received Event: \"" + event
            + "\"");
    }

    const int queue {event[0]};
    rapidjson::Value queueValue {queue};
    doc->set("/original/queue", queueValue);

    const bool isFullLocation = (FIRST_FULL_LOCATION_CHAR == event[2]);

    const auto secondColonIdx = event.find(":", 2);

    // Case: <Queue_ID>:[<Agent_ID>] (<Agent_Name>) <Registered_IP>-><Route>:<Log>
    //                  \                                                  /
    //                   \------------------- LOCATION -------------------/
    if (isFullLocation)
    {
        int startIdx = LOCATION_OFFSET;
        int endIdx = LOCATION_OFFSET;
        try
        {
            // Agent_ID index is between '[' and ']'
            // As the format goes like: ...:[<Agent_ID>....
            endIdx = event.find("]", startIdx);
            uint32_t valueSize = (endIdx - startIdx) - 1;
            const auto agentId = event.substr(startIdx + 1, valueSize).c_str();
            rapidjson::Value agentIdValue {agentId, valueSize, allocator};
            doc->set(EVENT_AGENT_ID, agentIdValue);

            // Agent_Name is between '(' and ')'
            startIdx = endIdx + 2; // As the format goes like: ...] (<Agent_Name>...
            endIdx = event.find(")", startIdx);
            valueSize = (endIdx - startIdx) - 1;
            const auto agentName = event.substr(startIdx + 1, valueSize).c_str();
            rapidjson::Value agentNameValue {agentName, valueSize, allocator};
            doc->set(EVENT_AGENT_NAME, agentNameValue);

            // Registered_IP is between ' ' (a space) and "->" (an arrow)
            startIdx = endIdx + 1; // As the format goes like: ...) <Registered_IP>...
            endIdx = event.find("->", startIdx);
            valueSize = (endIdx - startIdx) - 1;
            const auto registeredIP = event.substr(startIdx + 1, valueSize);
            rapidjson::Value registeredIPValue {
                registeredIP.c_str(), valueSize, allocator};
            doc->set(EVENT_REGISTERED_IP, registeredIPValue);

            // Route is between "->" (an arrow) and ':'
            startIdx = endIdx + 1; // As the format goes like: ...-><Route>...
            if (registeredIP.find(':') != std::string::npos)
            {
                // IPv6 case
                endIdx = event.find(":", endIdx + 2);
            }
            else
            {
                endIdx = secondColonIdx;
            }
            valueSize = (endIdx - startIdx) - 1;
            const auto Route = event.substr(startIdx + 1, valueSize).c_str();
            rapidjson::Value RouteValue {Route, valueSize, allocator};
            doc->set(EVENT_ROUTE, RouteValue);
        }
        catch (std::runtime_error& e)
        {
            const string msg = "An error occurred while parsing the location field of "
                               "the event. Event received: \""
                               + event + "\".";
            std::throw_with_nested(msg);
        }

        msgStartIndex = endIdx + 1;
    }
    // Case: <Queue_ID>:<Syslog_Client_IP>:<Log>
    else
    {
        // It is assumed that, if the ip is an IPv6, it is an EXTENDED IPv6. So, in the
        // sixth position of the event there should be a colon (':'), as the event should
        // have the following format: "q:XXXX:YYYY:ZZZZ:...".
        //                               |   |
        //                            idx=2 idx=6
        const auto ipVersion = (':' == event[6]) ? IPVersion::IPV6 : IPVersion::IPV4;

        if (IPVersion::IPV6 == ipVersion)
        {
            // As using extended IPv6, the actual log should start at the 42th position.
            // IPv6 Event:
            // q:SSSS:TTTT:UUUU:VVVV:WWWW:XXXX:YYYY:ZZZZ:log...
            //   |                                      |
            // idx=2                                 idx=41
            constexpr int LAST_COLON_INDEX = 41;

            if (event.length() < LAST_COLON_INDEX)
            {
                throw std::runtime_error(
                    "Invalid event format. Event is too short. Received Event: \"" + event
                    + "\"");
            }

            try
            {
                const auto locationLength = LAST_COLON_INDEX - LOCATION_OFFSET;
                const string ipv6 = event.substr(LOCATION_OFFSET, locationLength);
                rapidjson::Value ipValue {
                    ipv6.c_str(), (uint32_t)ipv6.length(), allocator};
                doc->set(EVENT_ROUTE, ipValue);
            }
            catch (std::runtime_error& e)
            {
                const string msg = "An error occurred while parsing the location field "
                                   "of the event. Event received: \""
                                   + event + "\".";
                std::throw_with_nested(msg);
            }

            msgStartIndex = LAST_COLON_INDEX + 1;
        }
        // IPVersion::IPV4
        else
        {
            try
            {
                const auto locationLength = secondColonIdx - LOCATION_OFFSET;
                const string ipv4 = event.substr(LOCATION_OFFSET, locationLength);
                rapidjson::Value ipValue {
                    ipv4.c_str(), (uint32_t)ipv4.length(), allocator};
                doc->set(EVENT_ROUTE, ipValue);
            }
            catch (std::runtime_error& e)
            {
                const string msg = "An error occurred while parsing the location field "
                                   "of the event. Event received: \""
                                   + event + "\".";
                std::throw_with_nested(msg);
            }

            msgStartIndex = secondColonIdx + 1;
        }
    }

    try
    {
        const string message = event.substr(msgStartIndex, string::npos);
        rapidjson::Value msg {
            message.c_str(), (rapidjson::SizeType)message.length(), allocator};
        doc->set(EVENT_LOG, msg);
    }
    catch (std::runtime_error& e)
    {
        const string msg = "An error occurred while parsing the location field of the "
                           "event. Event received: \""
                           + event + "\".";
        std::throw_with_nested(msg);
    }

    // TODO Create event here
    return  std::make_shared<json::Json>(std::move(doc));
}

std::optional<vector<string>> ProtocolHandler::process(const char* data,
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
