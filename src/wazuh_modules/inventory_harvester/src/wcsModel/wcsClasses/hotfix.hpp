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

#ifndef _HOTFIXES_WCS_MODEL_HPP
#define _HOTFIXES_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct Hotfix final
{
    struct _Hotfix final
    {
        std::string_view name;

        REFLECTABLE(MAKE_FIELD("name", &_Hotfix::name));
    };

    _Hotfix hotfix;

    REFLECTABLE(MAKE_FIELD("hotfix", &Hotfix::hotfix));
};

#endif // _HOTFIXES_WCS_MODEL_HPP
