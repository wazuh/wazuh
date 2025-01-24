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

#ifndef _DELETE_AGENT_HARVESTER_HPP
#define _DELETE_AGENT_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct DeleteAgentHarvester
{
    std::string_view id;
    std::string_view operation;

    REFLECTABLE(MAKE_FIELD("id", &DeleteAgentHarvester::id), MAKE_FIELD("operation", &DeleteAgentHarvester::operation));
};

#endif // _DELETE_AGENT_HARVESTER_HPP
