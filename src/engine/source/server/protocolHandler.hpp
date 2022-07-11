/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROTOCOL_HANDLER_H
#define _PROTOCOL_HANDLER_H

#include <optional>

#include <baseTypes.hpp>

namespace engineserver
{

constexpr char EVENT_AGENT_ID[] {"/agent/id"};
constexpr char EVENT_AGENT_NAME[] {"/agent/name"};
constexpr char EVENT_LOG[] {"/event/original"};
constexpr char EVENT_QUEUE_ID[] {"/original/queue"};
constexpr char EVENT_REGISTERED_IP[] {"/agent/registeredIP"};
constexpr char EVENT_ROUTE[] {"/original/route"};

/**
 * @brief A handler which knows how to parse messages from the network
 * data chunks and send them to a subscriber.
 *
 */
class ProtocolHandler
{
private:
    std::vector<char> m_buff;
    int m_pending {0};
    int m_stage {0};

    /**
     * @brief Update pending value and return true if we have enough data
     * to calculate the message size.
     *
     * @return true
     * @return false
     */
    bool hasHeader();

public:
    /**
     * @brief generate a json::Document from internal state
     *
     * @return json::Document
     */
    static base::Event parse(const std::string& event);

    /**
     * @brief process the chunk of data and send messages to dst when. Return
     * true if all data was processed correctly, or false in case of error.
     * The error will be send to the dst.
     *
     * @param data Array of chars containing the event data
     * @param length Size of the data array
     * @param dst destination subscriber
     * @return true and vector of strings if no errors
     * @return false if errors in processing
     */
    std::optional<std::vector<std::string>> process(const char* data,
                                                    const size_t length);
};

} // namespace engineserver

#endif // _PROTOCOL_HANDLER_H
