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
    struct Distribution final
    {
        std::string_view release;

        REFLECTABLE(MAKE_FIELD("release", &Distribution::release));
    };

    struct Kernel final
    {
        std::string_view name;
        std::string_view release;
        std::string_view version;

        REFLECTABLE(MAKE_FIELD("name", &Kernel::name),
                    MAKE_FIELD("release", &Kernel::release),
                    MAKE_FIELD("version", &Kernel::version));
    };
    std::string_view build;
    std::string_view codename;
    Distribution distribution;
    std::string_view full;
    Kernel kernel;
    std::string_view major;
    std::string_view minor;
    std::string_view name;
    std::string_view patch;
    std::string_view platform;
    std::string_view version;

    REFLECTABLE(MAKE_FIELD("build", &OS::build),
                MAKE_FIELD("codename", &OS::codename),
                MAKE_FIELD("distribution", &OS::distribution),
                MAKE_FIELD("full", &OS::full),
                MAKE_FIELD("kernel", &OS::kernel),
                MAKE_FIELD("major", &OS::major),
                MAKE_FIELD("minor", &OS::minor),
                MAKE_FIELD("name", &OS::name),
                MAKE_FIELD("patch", &OS::patch),
                MAKE_FIELD("platform", &OS::platform),
                MAKE_FIELD("version", &OS::version));
};

#endif // _OS_WCS_MODEL_HPP
