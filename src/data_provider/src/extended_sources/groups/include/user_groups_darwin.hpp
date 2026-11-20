/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <chrono>
#include <set>
#include <unordered_map>

#include "json.hpp"
#include "igroup_wrapper.hpp"
#include "ipasswd_wrapper.hpp"
#include "iopen_directory_utils_wrapper.hpp"
#include "iuuid_wrapper.hpp"
#include "direct_memberships_darwin.hpp"
#include "effective_groups_darwin.hpp"

#define EXPECTED_GROUPS_MAX 64

class UserGroupsProvider
{
    public:
        explicit UserGroupsProvider(std::shared_ptr<IGroupWrapperDarwin> groupWrapper,
                                    std::shared_ptr<IPasswdWrapperDarwin> passwdWrapper,
                                    std::shared_ptr<IODUtilsWrapper> odWrapper,
                                    std::shared_ptr<IUUIDWrapper> uuidWrapper);
        UserGroupsProvider();
        /// @brief One row (uid, gid) for each group the accounts are direct members of, primary group included.
        nlohmann::json collect(const std::set<uid_t>& uids = {});

        /// @brief Names of the accounts that are direct members of each group, as collect() reports them.
        nlohmann::json getUserNamesByGid(const std::set<gid_t>& gids);

        /// @brief Names of the groups each account is a direct member of; nested groups are not followed.
        nlohmann::json getGroupNamesByUid(const std::set<uid_t>& uids);

        /// @brief Names of the groups of one account counting nested groups, as sudo sees them.
        std::set<std::string> getEffectiveGroupNamesByUid(uid_t uid);

        static void resetCache();

    private:
        static bool validateCache();

        std::shared_ptr<IGroupWrapperDarwin> m_groupWrapper;
        std::shared_ptr<IPasswdWrapperDarwin> m_passwdWrapper;
        std::shared_ptr<IODUtilsWrapper> m_odWrapper;
        DirectMemberships m_directMemberships;
        EffectiveGroups m_effectiveGroups;

        struct UserInfo
        {
            const char* name;
            uid_t uid;
            gid_t gid;
        };

        void getGroupsForUser(nlohmann::json& results, const UserInfo& user);
        void addGroupsToResults(nlohmann::json& results, uid_t uid, const gid_t* groups, int ngroups);
        std::vector<gid_t> getGroupIdsForUser(const UserInfo& user);
        std::vector<gid_t> getUserGroups(uid_t uid, const char* username, gid_t gid);

};
