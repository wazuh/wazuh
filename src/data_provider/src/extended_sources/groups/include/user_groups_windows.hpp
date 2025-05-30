/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "users_utils_wrapper.hpp"
#include "groups_utils_wrapper.hpp"

#include "json.hpp"

/// @brief Class for collecting user groups information on Windows.
///
/// This class provides methods to collect user groups information from the
/// Windows operating system. It uses the Windows API to enumerate local users
/// and their associated groups. The collected data is returned in JSON format
class UserGroupsProvider
{
    public:
        explicit UserGroupsProvider(std::shared_ptr<IWindowsApiWrapper> winapiWrapper,
                                    std::shared_ptr<IUsersHelper> usersHelper,
                                    std::shared_ptr<IGroupsHelper> groupsHelper);
        UserGroupsProvider();
        nlohmann::json collect(const std::set<std::uint32_t>& uids = {});

    private:
        std::shared_ptr<IWindowsApiWrapper> m_winapiWrapper;
        std::shared_ptr<IUsersHelper> m_usersHelper;
        std::shared_ptr<IGroupsHelper> m_groupsHelper;

        void processLocalUserGroups(const User& user, const std::vector<Group>& groups, nlohmann::json& results);
};
