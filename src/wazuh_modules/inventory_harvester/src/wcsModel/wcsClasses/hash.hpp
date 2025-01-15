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

#ifndef _HASH_WCS_MODEL_HPP
#define _HASH_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>
#include <vector>

struct Hash final
{
    std::string_view md5;
    std::string_view sha1;
    std::string_view sha256;

    REFLECTABLE(MAKE_FIELD("md5", &Hash::md5), MAKE_FIELD("sha1", &Hash::sha1), MAKE_FIELD("sha256", &Hash::sha256));
};

#endif // _HASH_WCS_MODEL_HPP
