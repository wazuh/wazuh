/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "protocolHandler.hpp"

#include "json.hpp"

json::Document engineserver::protocolhandler::parseEvent(const std::string & event)
{
    json::Document object(R"({})");

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
        std::string errStr = e.what();
        json::Value errVal(errStr.c_str(), errStr.length());
        object.set("/error",  errVal);
        return object;
    }

    separator_pos = event_slice.find(":");
    std::string location = event_slice.substr(0, separator_pos);
    std::string message = event_slice.substr(separator_pos + 1);

    json::Value queueVal(queue);
    object.set("/queue", queueVal);
    json::Value locationVal;
    locationVal.SetString(location.c_str(), location.size(), object.getAllocator());
    object.set("/location", locationVal);
    json::Value messageVal(message.c_str(), message.size(), object.getAllocator());
    object.set("/message", messageVal);

    return object;
}
