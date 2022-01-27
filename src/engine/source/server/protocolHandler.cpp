/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "protocolHandler.hpp"

nlohmann::json engineserver::protocolhandler::parseEvent(const std::string & event)
{
    nlohmann::json object;

    auto separator_pos = event.find(":");
    auto event_slice = event.substr(separator_pos + 1);

    int queue;
    try
    {
        queue = std::stoi(event.substr(0, separator_pos));
    }
    catch (const std::exception & e)
    {
        std::cerr << "ERROR (" << e.what() << "): Can not extract queue from the event: \"" << event << "\"\n";
        object["error"] = e.what();
        return object;
    }

    separator_pos = event_slice.find(":");
    auto location = event_slice.substr(0, separator_pos);

    auto message = event_slice.substr(separator_pos + 1);

    object["queue"] = MessageQueue(queue);
    object["location"] = location;
    object["message"] = message;

    return object;
}
