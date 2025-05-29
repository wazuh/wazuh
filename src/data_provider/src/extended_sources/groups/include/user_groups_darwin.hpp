/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <set>

#include "json.hpp"
#include "igroup_wrapper.hpp"
#include "ipasswd_wrapper.hpp"
#include "iopen_directory_utils_wrapper.hpp"

#define EXPECTED_GROUPS_MAX 64

class UserGroupsProvider
{
    public:
        explicit UserGroupsProvider(std::shared_ptr<IGroupWrapperDarwin> groupWrapper,
                                    std::shared_ptr<IPasswdWrapperDarwin> passwdWrapper,
                                    std::shared_ptr<IODUtilsWrapper> odWrapper);
        UserGroupsProvider();
        nlohmann::json collect(const std::set<uid_t>& uids = {});

    private:
        std::shared_ptr<IGroupWrapperDarwin> m_groupWrapper;
        std::shared_ptr<IPasswdWrapperDarwin> m_passwdWrapper;
        std::shared_ptr<IODUtilsWrapper> m_odWrapper;

        struct UserInfo
        {
            const char* name;
            uid_t uid;
            gid_t gid;
        };

        void getGroupsForUser(nlohmann::json& results, const UserInfo& user);
        void addGroupsToResults(nlohmann::json& results, uid_t uid, const gid_t* groups, int ngroups);

};