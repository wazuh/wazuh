/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * Match 25, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NETIFACE_WCS_MODEL_HPP
#define _NETIFACE_WCS_MODEL_HPP

#include "hash.hpp"
#include "reflectiveJson.hpp"
#include <string_view>

struct NetIface final
{
    std::string_view alias;
    int64_t mtu;
    std::string_view name;
    std::string_view state;
    std::string_view type;

    REFLECTABLE(MAKE_FIELD("alias", &NetIface::alias),
                MAKE_FIELD("mtu", &NetIface::mtu),
                MAKE_FIELD("name", &NetIface::name),
                MAKE_FIELD("state", &NetIface::state),
                MAKE_FIELD("type", &NetIface::type));
};

#endif // _NETIFACE_WCS_MODEL_HPP
