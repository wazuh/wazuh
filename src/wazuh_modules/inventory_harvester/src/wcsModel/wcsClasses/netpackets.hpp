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

#ifndef _NETPACKETS_WCS_MODEL_HPP
#define _NETPACKETS_WCS_MODEL_HPP

#include "hash.hpp"
#include "reflectiveJson.hpp"
#include <string_view>

struct NetPackets final
{
    int64_t bytes;
    int64_t drops;
    int64_t errors;
    int64_t packets;

    REFLECTABLE(MAKE_FIELD("bytes", &NetPackets::bytes),
                MAKE_FIELD("drops", &NetPackets::drops),
                MAKE_FIELD("errors", &NetPackets::errors),
                MAKE_FIELD("packets", &NetPackets::packets));
};

#endif // _NETPACKETS_WCS_MODEL_HPP
