/*
 * Wazuh Inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * January 13, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HARVESTER_CONFIGURATION_HPP
#define _HARVESTER_CONFIGURATION_HPP

#include <string>
#include <vector>

/**
 * @brief HarvesterConfiguration class.
 *
 */
struct HarvesterConfiguration final
{
    std::vector<std::string> modules;
};

#endif // _HARVESTER_CONFIGURATION_HPP
