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
#include "reported_groups_darwin.hpp"
#include "effective_groups_darwin.hpp"

#define EXPECTED_GROUPS_MAX 64

class UserGroupsProvider
{
    public:
        explicit UserGroupsProvider(std::shared_ptr<IGroupWrapperDarwin> groupWrapper,
                                    std::shared_ptr<IPasswdWrapperDarwin> passwdWrapper,
                                    std::shared_ptr<IODUtilsWrapper> odWrapper);
        UserGroupsProvider();
        /// @brief One row (uid, gid) for each group reported for the accounts (see ReportedGroups), primary group included.
        nlohmann::json collect(const std::set<uid_t>& uids = {});

        /// @brief Names of the accounts reported in each group, as collect() reports them.
        /// @throws std::runtime_error when the directory memberships could not be read.
        nlohmann::json getUserNamesByGid(const std::set<gid_t>& gids);

        /// @brief Names of the groups reported for each account, as collect() reports them.
        /// @throws std::runtime_error when the directory memberships could not be read.
        nlohmann::json getGroupNamesByUid(const std::set<uid_t>& uids);

        /// @brief Names of the groups of one account counting nested groups, as sudo sees them.
        std::set<std::string> getEffectiveGroupNamesByUid(uid_t uid);

        static void resetCache();

    private:
        /// @brief Throws when this provider read the directory memberships and the read failed:
        /// the accounts looked up since then got no groups, which does not mean they have none.
        /// Reporting them would mark every user or group as modified twice, when the read fails
        /// and when it works again, so the scan of that inventory is dropped instead.
        /// @param inventory The inventory named in the error, such as "users" or "groups".
        void requireReadableMemberships(const std::string& inventory) const;
        static bool validateCache();

        std::shared_ptr<IGroupWrapperDarwin> m_groupWrapper;
        std::shared_ptr<IPasswdWrapperDarwin> m_passwdWrapper;
        std::shared_ptr<IODUtilsWrapper> m_odWrapper;
        ReportedGroups m_reportedGroups;
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
