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

#ifndef _OS_WCS_MODEL_HPP
#define _OS_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct OS final
{
    std::string_view kernel;
    std::string_view full;
    std::string_view name;
    std::string_view platform;
    std::string_view version;
    std::string_view type;

    REFLECTABLE(MAKE_FIELD("kernel",
                           &OS::kernel,
                           MAKE_FIELD("full", &OS::full),
                           MAKE_FIELD("name", &OS::name),
                           MAKE_FIELD("platform", &OS::platform),
                           MAKE_FIELD("version", &OS::version),
                           MAKE_FIELD("type", &OS::type)));
};

#endif // _OS_WCS_MODEL_HPP
