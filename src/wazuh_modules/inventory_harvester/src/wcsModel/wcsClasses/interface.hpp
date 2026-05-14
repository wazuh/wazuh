/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * March 21, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INTERFACE_WCS_MODEL_HPP
#define _INTERFACE_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct NetworkInterface final
{
    std::string_view state;

    REFLECTABLE(MAKE_FIELD("state", &NetworkInterface::state));
};

#endif // _INTERFACE_WCS_MODEL_HPP
