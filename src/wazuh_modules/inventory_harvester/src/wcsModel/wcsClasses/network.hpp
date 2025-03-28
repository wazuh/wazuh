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

struct Network final
{
    std::string_view broadcast;
    std::string_view dhcp;
    std::string_view ip;
    std::string_view metric;
    std::string_view name;
    std::string_view netmask;
    std::string_view protocol;

    REFLECTABLE(MAKE_FIELD("broadcast", &Network::broadcast),
                MAKE_FIELD("dhcp", &Network::dhcp),
                MAKE_FIELD("ip", &Network::ip),
                MAKE_FIELD("metric", &Network::metric),
                MAKE_FIELD("name", &Network::name),
                MAKE_FIELD("netmask", &Network::netmask),
                MAKE_FIELD("protocol", &Network::protocol));
};

#endif // _NET_WCS_MODEL_HPP
