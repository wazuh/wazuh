/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * March 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PORTS_WCS_MODEL_HPP
#define _PORTS_WCS_MODEL_HPP

#include "file.hpp"
#include "nat.hpp"
#include "process.hpp"
#include "reflectiveJson.hpp"
#include <string_view>
#include <vector>

struct NetHost final
{
    struct NetworkPacketCount final
    {
        struct PacketCount final
        {
            int64_t queue = DEFAULT_INT_VALUE;

            REFLECTABLE(MAKE_FIELD("queue", &PacketCount::queue));
        };

        PacketCount egress;
        PacketCount ingress;

        REFLECTABLE(MAKE_FIELD("egress", &NetworkPacketCount::egress),
                    MAKE_FIELD("ingress", &NetworkPacketCount::ingress));
    };

    NetworkPacketCount network;

    REFLECTABLE(MAKE_FIELD("network", &NetHost::network));
};

// Using a custom file struct because of the std::string conversion.
struct PortFile final
{
    std::string inode;

    REFLECTABLE(MAKE_FIELD("inode", &PortFile::inode));
};

// Using a custom process struct because of the int64_t pid.
struct PortProcess final
{
    std::string_view name;
    int64_t pid = DEFAULT_INT_VALUE;

    REFLECTABLE(MAKE_FIELD("name", &PortProcess::name), MAKE_FIELD("pid", &PortProcess::pid));
};

#endif // _PORTS_WCS_MODEL_HPP
