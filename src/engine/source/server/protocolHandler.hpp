/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROTOCOL_HANDLER_H_
#define _PROTOCOL_HANDLER_H_

#include <iostream>
#include <string>

#include <json.hpp>

namespace engineserver
{

/**
 * @brief A handler which knows how to parse messages from the network
 * data chunks and send them to a subscriber.
 *
 */
class ProtocolHandler
{
private:
    std::vector<char> m_buff;
    int m_pending{0};
    int m_stage{0};



    /**
     * @brief Update pending value and return true if we have enough data
     * to calculate the message size.
     *
     * @return true
     * @return false
     */
    bool hasHeader();

    /**
     * @brief Process a message, parsing it and sending it to s
     *
     * @param s a subscriber of this connection.
     */
    void send(const rxcpp::subscriber<rxcpp::observable<std::string>> s);

public:
    /**
     * @brief generate a json::Document from internal state
     *
     * @return json::Document
     */
    json::Document parse(const std::string & event) const;
    /**
     * @brief process the chunk of data and send messages to dst when. Return
     * true if all data was processed correctly, or false in case of error.
     * The error will be send to the dst.
     *
     * @param data
     * @param length
     * @param dst destination subscriber
     * @return true no errors
     * @return false errors in processing
     */
    bool process(char * data, std::size_t length, const rxcpp::subscriber<rxcpp::observable<std::string>> dst);
};

} // namespace engineserver

#endif // _PROTOCOL_HANDLER_H_
