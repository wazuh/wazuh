/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * May 14, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EVENT_WCS_MODEL_HPP
#define _EVENT_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct Event final
{
    std::string_view category;

    REFLECTABLE(MAKE_FIELD("category", &Event::category));
};

#endif // _EVENT_WCS_MODEL_HPP
