/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * March 26, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NET_WCS_MODEL_HPP
#define _NET_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct NetworkAddress final
{
    std::string_view broadcast;
    std::string_view ip;
    std::string_view name;
    std::string_view netmask;
    std::string_view protocol;

    REFLECTABLE(MAKE_FIELD("broadcast", &NetworkAddress::broadcast),
                MAKE_FIELD("ip", &NetworkAddress::ip),
                MAKE_FIELD("name", &NetworkAddress::name),
                MAKE_FIELD("netmask", &NetworkAddress::netmask),
                MAKE_FIELD("protocol", &NetworkAddress::protocol));
};

#endif // _NET_WCS_MODEL_HPP
