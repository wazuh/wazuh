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

#ifndef _FIM_FILE_HARVESTER_HPP
#define _FIM_FILE_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include "wcsClasses/agent.hpp"
#include "wcsClasses/file.hpp"

struct FimFileInventoryHarvester final
{
    File file;
    Agent agent;

    REFLECTABLE(MAKE_FIELD("file", &FimFileInventoryHarvester::file),
                MAKE_FIELD("agent", &FimFileInventoryHarvester::agent));
};

#endif // _FIM_FILE_HARVESTER_HPP
