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

#include "hash.hpp"
#include "reflectiveJson.hpp"
#include <string_view>

struct Registry final
{
    struct Data final
    {
        Hash hash;
        std::string type;

        REFLECTABLE(MAKE_FIELD("hash", &Data::hash), MAKE_FIELD("type", &Data::type));
    };

    std::string_view key;
    std::string value;
    std::string hive;
    std::string_view path;
    Data data;
    std::string_view gid;
    std::string_view group;
    std::string_view uid;
    std::string_view owner;
    std::string_view architecture;
    std::string mtime;

    REFLECTABLE(MAKE_FIELD("key", &Registry::key),
                MAKE_FIELD("value", &Registry::value),
                MAKE_FIELD("hive", &Registry::hive),
                MAKE_FIELD("path", &Registry::path),
                MAKE_FIELD("data", &Registry::data),
                MAKE_FIELD("gid", &Registry::gid),
                MAKE_FIELD("group", &Registry::group),
                MAKE_FIELD("uid", &Registry::uid),
                MAKE_FIELD("owner", &Registry::owner),
                MAKE_FIELD("architecture", &Registry::architecture),
                MAKE_FIELD("mtime", &Registry::mtime));
};

#endif // _REGISTRY_WCS_MODEL_HPP
