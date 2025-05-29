/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "igroup_wrapper.hpp"

#include <grp.h>
#include <unistd.h>

// This symbol is exported from libSystem.B and has been since 10.6.
extern "C" int getgroupcount(const char* name, gid_t basegid);

class GroupWrapperDarwin : public IGroupWrapperDarwin
{
    public:

        int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const override
        {
            return ::getgrouplist(user, group, (int*)groups, ngroups);
        }

        int getgroupcount(const char* user, gid_t group) const override
        {
            return ::getgroupcount(user, group);
        }
};
