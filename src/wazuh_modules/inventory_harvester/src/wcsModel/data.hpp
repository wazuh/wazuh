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

#ifndef _DATA_HARVESTER_HPP
#define _DATA_HARVESTER_HPP

#include "reflectiveJson.hpp"
#include <string_view>

template<typename T>
struct DataHarvester
{
    std::string id;
    std::string_view operation;
    T data;

    REFLECTABLE(MAKE_FIELD("id", &DataHarvester::id),
                MAKE_FIELD("operation", &DataHarvester::operation),
                MAKE_FIELD("data", &DataHarvester::data));
};

#endif // _DATA_HARVESTER_HPP
