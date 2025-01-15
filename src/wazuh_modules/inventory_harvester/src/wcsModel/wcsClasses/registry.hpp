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

#ifndef _REGISTRY_WCS_MODEL_HPP
#define _REGISTRY_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct Registry final
{
    std::string_view key;
    std::string_view value;

    REFLECTABLE(MAKE_FIELD("key", &Registry::key), MAKE_FIELD("value", &Registry::value));
};

#endif // _REGISTRY_WCS_MODEL_HPP
