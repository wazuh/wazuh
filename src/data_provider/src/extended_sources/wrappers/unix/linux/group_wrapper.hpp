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

class GroupWrapperLinux : public IGroupWrapperLinux
{
    public:

        int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const override
        {
            return ::getgrouplist(user, group, groups, ngroups);
        }
};
