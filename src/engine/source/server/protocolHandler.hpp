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

namespace engineserver::protocolhandler
{
/**
 * @brief Used to differenciate the Wazuh events source
 */
enum MessageQueue
{
    UNKNOWN = 0,
    SYSLOG,
    IDS,
    FIREWALL,
    RSV1,
    RSV2,
    RSV3,
    APACHE,
    SQUID,
    WINDOWS,
    HOST_INFO,
    WAZUH_RULES,
    WAZUH_ALERTS
};

/**
 * @brief Extracts the Queue; Location and Message from the Wazuh event and creates a JSON object with them
 *
 * @param event String to be parsed
 * @return nlohmann::json Object containing the event in JSON format
 */
json::Document parseEvent(const std::string & event);
} // namespace engineserver::protocolhandler

#endif // _PROTOCOL_HANDLER_H_
