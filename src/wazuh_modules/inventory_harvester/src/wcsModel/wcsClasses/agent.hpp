/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 14, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _AGENT_WCS_MODEL_HPP
#define _AGENT_WCS_MODEL_HPP

#include "host.hpp"
#include "reflectiveJson.hpp"
#include <string_view>
#include <vector>

struct Agent final
{
    std::vector<std::string_view> groups;
    std::string_view id;
    std::string_view name;
    std::string_view ip;
    std::string_view version;

    REFLECTABLE(MAKE_FIELD("groups", &Agent::groups),
                MAKE_FIELD("id", &Agent::id),
                MAKE_FIELD("name", &Agent::name),
                MAKE_FIELD("ip", &Agent::ip),
                MAKE_FIELD("version", &Agent::version));
};

#endif // _AGENT_WCS_MODEL_HPP
