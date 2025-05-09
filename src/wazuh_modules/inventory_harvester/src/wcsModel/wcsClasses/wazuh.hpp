/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * April 3, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WAZUH_WCS_MODEL_HPP
#define _WAZUH_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct Wazuh final
{
    struct Cluster final
    {
        std::string_view name;
        std::string_view node;

        REFLECTABLE(MAKE_FIELD("name", &Cluster::name), MAKE_FIELD("node", &Cluster::node));
    };

    struct Schema final
    {
        const std::string_view version = "1.0";

        REFLECTABLE(MAKE_FIELD("version", &Schema::version));
    };

    Cluster cluster;
    Schema schema;

    REFLECTABLE(MAKE_FIELD("cluster", &Wazuh::cluster), MAKE_FIELD("schema", &Wazuh::schema));
};

#endif // _WAZUH_WCS_MODEL_HPP
