/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <grp.h>

class IGroupWrapperDarwin
{
    public:
        virtual ~IGroupWrapperDarwin() = default;

        virtual int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const = 0;
        virtual int getgroupcount(const char* user, gid_t group) const = 0;
};
