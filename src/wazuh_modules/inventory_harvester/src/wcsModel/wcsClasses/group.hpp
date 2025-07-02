/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * June 16, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WCS_GROUP_HPP
#define _WCS_GROUP_HPP

#include "reflectiveJson.hpp"
#include <cstdint>
#include <string_view>

struct Group final
{
    std::string_view description;
    std::uint64_t id = DEFAULT_INT_VALUE; // Huge positive number.
    std::int64_t id_signed = DEFAULT_INT_VALUE;
    bool is_hidden = false;
    std::string_view name;
    std::vector<std::string_view> users;
    std::string_view uuid;

    REFLECTABLE(MAKE_FIELD("id", &Group::id),
                MAKE_FIELD("name", &Group::name),
                MAKE_FIELD("description", &Group::description),
                MAKE_FIELD("id_signed", &Group::id_signed),
                MAKE_FIELD("uuid", &Group::uuid),
                MAKE_FIELD("is_hidden", &Group::is_hidden),
                MAKE_FIELD("users", &Group::users));
};

#endif // _WCS_GROUP_HPP
