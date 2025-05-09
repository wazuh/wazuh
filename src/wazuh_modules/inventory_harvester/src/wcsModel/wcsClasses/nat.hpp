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

#ifndef _NAT_WCS_MODEL_HPP
#define _NAT_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct NAT final
{
    std::string_view ip;
    std::int64_t port = DEFAULT_INT_VALUE;

    REFLECTABLE(MAKE_FIELD("ip", &NAT::ip), MAKE_FIELD("port", &NAT::port));
};

#endif // _NAT_WCS_MODEL_HPP
