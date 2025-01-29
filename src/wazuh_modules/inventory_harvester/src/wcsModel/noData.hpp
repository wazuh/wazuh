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

#ifndef _NO_DATA_HARVESTER_HPP
#define _NO_DATA_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct NoDataHarvester final
{
    std::string id;
    std::string_view operation;

    REFLECTABLE(MAKE_FIELD("id", &NoDataHarvester::id), MAKE_FIELD("operation", &NoDataHarvester::operation));
};

#endif // _NO_DATA_HARVESTER_HPP
