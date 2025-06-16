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
#include <string_view>

struct Group final {
    std::string_view description;
    unsigned long id = 0;
    long id_signed = 0;
    bool is_hidden = false;
    std::string_view name;
    std::string_view users;
    std::string_view uuid;

    REFLECTABLE(MAKE_FIELD("description", &Group::description),
                MAKE_FIELD("id", &Group::id),
                MAKE_FIELD("id_signed", &Group::id_signed),
                MAKE_FIELD("is_hidden", &Group::is_hidden),
                MAKE_FIELD("name", &Group::name),
                MAKE_FIELD("users", &Group::users),
                MAKE_FIELD("uuid", &Group::uuid));
};

#endif // _WCS_GROUP_HPP
