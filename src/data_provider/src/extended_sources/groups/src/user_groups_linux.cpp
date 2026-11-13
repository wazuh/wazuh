/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "user_groups_linux.hpp"
#include "group_wrapper.hpp"
#include "passwd_wrapper.hpp"
#include "system_wrapper.hpp"
#include <algorithm>
#include <cerrno>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

// Reasonable upper bound for getpw_r buffer
constexpr size_t MAX_GETPW_R_BUF_SIZE = 16 * 1024;

// The local account databases, as opposed to the ones a directory client serves through NSS.
constexpr auto LOCAL_PASSWD_FILE {"/etc/passwd"};
constexpr auto LOCAL_GROUP_FILE {"/etc/group"};

namespace
{
    // glibc reports 1024 for _SC_GETPW_R_SIZE_MAX and _SC_GETGR_R_SIZE_MAX, which a long GECOS
    // field or a long member list does not fit. The reentrant lookups answer ERANGE then, and
    // the buffer is grown up to this size instead of losing the entry.
    constexpr size_t MAX_NSS_BUF_SIZE = 32 * 1024 * 1024;

    // Starting size taken from sysconf(), clamped to (0, MAX_GETPW_R_BUF_SIZE].
    size_t initialBufSize(long sysconfSize)
    {
        return (sysconfSize <= 0 || static_cast<size_t>(sysconfSize) > MAX_GETPW_R_BUF_SIZE)
               ? MAX_GETPW_R_BUF_SIZE
               : static_cast<size_t>(sysconfSize);
    }

    class NssBuffer
    {
        public:
            explicit NssBuffer(size_t size)
                : m_size(size)
                , m_data(new char[size])
            {
            }

            // Calls a reentrant passwd/group function, doubling the buffer while it answers
            // ERANGE. The enumeration functions keep their position on ERANGE, and the file
            // wrappers go back to the start of the line where glibc does not, so the retry reads
            // the same entry.
            template<typename Lookup>
            int call(Lookup&& lookup)
            {
                int ret = lookup(m_data.get(), m_size);

                while (ret == ERANGE && m_size < MAX_NSS_BUF_SIZE)
                {
                    m_size = std::min(m_size * 2, MAX_NSS_BUF_SIZE);
                    m_data.reset(new char[m_size]);
                    ret = lookup(m_data.get(), m_size);
                }

                return ret;
            }

        private:
            size_t m_size;
            std::unique_ptr<char[]> m_data;
    };
}

// Initialize static thread-local cache variables
thread_local std::unordered_map<uid_t, std::vector<gid_t>> UserGroupsProvider::s_userGroupsCache;
thread_local std::unordered_map<gid_t, std::string> UserGroupsProvider::s_groupNamesCache;
thread_local std::chrono::steady_clock::time_point UserGroupsProvider::s_cacheTimestamp;
thread_local bool UserGroupsProvider::s_cacheValid = false;

UserGroupsProvider::UserGroupsProvider(std::shared_ptr<IGroupWrapperLinux> groupWrapper,
                                       std::shared_ptr<IPasswdWrapperLinux> passwdWrapper,
                                       std::shared_ptr<ISystemWrapper> sysWrapper)
    : m_groupWrapper(std::move(groupWrapper))
    , m_passwdWrapper(std::move(passwdWrapper))
    , m_sysWrapper(std::move(sysWrapper))
{
}

UserGroupsProvider::UserGroupsProvider()
    : m_groupWrapper(std::make_shared<GroupWrapperLinux>())
    , m_passwdWrapper(std::make_shared<PasswdWrapperLinux>())
    , m_sysWrapper(std::make_shared<SystemWrapper>())
{
}

void UserGroupsProvider::resetCache()
{
    s_userGroupsCache.clear();
    s_groupNamesCache.clear();
    s_cacheValid = false;
}

void UserGroupsProvider::validateCache()
{
    if (s_cacheValid)
    {
        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - s_cacheTimestamp);

        if (elapsed >= s_cacheTimeout)
        {
            s_userGroupsCache.clear();
            s_groupNamesCache.clear();
            s_cacheValid = false;
        }
    }
}

nlohmann::json UserGroupsProvider::collect(const std::set<uid_t>& uids)
{
    nlohmann::json results = nlohmann::json::array();
    auto usersGroups = getUserGroups(uids);

    for (const auto& [uid, groups] : usersGroups)
    {
        addGroupsToResults(results, uid, groups.data(), static_cast<int>(groups.size()));
    }

    return results;
}

nlohmann::json UserGroupsProvider::getGroupNamesByUid(const std::set<uid_t>& uids)
{
    const bool singleUid = (uids.size() == 1);
    nlohmann::json result = singleUid ? nlohmann::json::array() : nlohmann::json::object();
    auto usersGroups = getUserGroups(uids);

    NssBuffer groupBuf {initialBufSize(m_sysWrapper->sysconf(_SC_GETGR_R_SIZE_MAX))};

    // Resolve each distinct gid once for the whole call instead of once per user that
    // belongs to it. Group membership overlaps heavily, so the previous behaviour cost
    // one lookup per (user, group) pair. On a host where the group database is served by
    // a network directory, every one of those lookups is a round trip.
    // Unresolvable gids are memoised too, otherwise they keep costing a lookup per user.
    // Names the group enumeration of getUserGroups() returned need no lookup. Only a gid it
    // did not list (a primary group missing from the group database, or one the directory
    // does not enumerate) is looked up on its own.
    std::unordered_map<gid_t, std::string> gidToName;
    std::unordered_set<gid_t> unresolvableGids;

    const auto resolveGidName = [&](gid_t gid, std::string & name) -> bool
    {
        if (const auto enumerated = s_groupNamesCache.find(gid); enumerated != s_groupNamesCache.end())
        {
            name = enumerated->second;
            return true;
        }

        if (const auto cached = gidToName.find(gid); cached != gidToName.end())
        {
            name = cached->second;
            return true;
        }

        if (unresolvableGids.count(gid) > 0)
        {
            return false;
        }

        struct group grp {};

        struct group* grpResult = nullptr;

        const auto lookup = groupBuf.call([&](char* buf, size_t size)
        {
            return m_groupWrapper->getgrgid_r(gid, &grp, buf, size, &grpResult);
        });

        if (lookup == 0 && grpResult != nullptr && grpResult->gr_name != nullptr)
        {
            name = grpResult->gr_name;
            gidToName.emplace(gid, name);
            return true;
        }

        // Only an authoritative answer is remembered. A return of 0 with no entry means the
        // group database does not know this gid, which will not change within one scan. A
        // non-zero return is a failed lookup, which may be transient on a host whose group
        // database is served over the network, so it is left unmemoized and the next user
        // that belongs to this gid attempts it again, as it did before this change.
        if (lookup == 0)
        {
            unresolvableGids.insert(gid);
        }

        return false;
    };

    for (const auto& [uid, groups] : usersGroups)
    {
        nlohmann::json groupNames = nlohmann::json::array();

        for (const auto& gid : groups)
        {
            std::string groupName;

            if (resolveGidName(gid, groupName))
            {
                groupNames.push_back(groupName);
            }
        }

        if (singleUid)
        {
            result = groupNames;
        }
        else
        {
            result[std::to_string(uid)] = groupNames;
        }
    }

    return result;
}

nlohmann::json UserGroupsProvider::getUserNamesByGid(const std::set<gid_t>& gids)
{
    const bool allGroups = gids.empty();
    const bool singleGid = (!allGroups && gids.size() == 1);
    nlohmann::json result = singleGid ? nlohmann::json::array() : nlohmann::json::object();

    NssBuffer groupBuf {initialBufSize(m_sysWrapper->sysconf(_SC_GETGR_R_SIZE_MAX))};

    std::map<gid_t, std::set<std::string>> gidToUsernames;

    if (allGroups)
    {
        struct group* grp = nullptr;
        m_groupWrapper->setgrent();

        while ((grp = m_groupWrapper->getgrent()) != nullptr)
        {
            gid_t gid = grp->gr_gid;
            char** members = grp->gr_mem;

            while (members && *members)
            {
                gidToUsernames[gid].insert(*members);
                ++members;
            }
        }

        m_groupWrapper->endgrent();
    }
    else
    {
        for (const auto& gid : gids)
        {
            struct group grp {};
            struct group* grpResult = nullptr;

            const auto ret = groupBuf.call([&](char* buf, size_t size)
            {
                return m_groupWrapper->getgrgid_r(gid, &grp, buf, size, &grpResult);
            });

            if (ret == 0 && grpResult != nullptr)
            {
                char** members = grpResult->gr_mem;

                while (members && *members)
                {
                    gidToUsernames[gid].insert(*members);
                    ++members;
                }
            }
        }
    }

    struct passwd* pwd = nullptr;

    m_passwdWrapper->setpwent();

    while ((pwd = m_passwdWrapper->getpwent()) != nullptr)
    {
        if (pwd->pw_name != nullptr && (allGroups || gids.count(pwd->pw_gid)))
        {
            gidToUsernames[pwd->pw_gid].insert(pwd->pw_name);
        }
    }

    m_passwdWrapper->endpwent();

    for (const auto& [gid, usernames] : gidToUsernames)
    {
        nlohmann::json jsonUsernames = nlohmann::json::array();

        for (const auto& name : usernames)
        {
            jsonUsernames.push_back(name);
        }

        if (singleGid)
        {
            result = jsonUsernames;
        }
        else
        {
            result[std::to_string(gid)] = jsonUsernames;
        }
    }

    return result;
}

std::vector<std::pair<uid_t, std::vector<gid_t>>> UserGroupsProvider::getUserGroups(const std::set<uid_t>& uids)
{
    // Validate cache (auto-invalidates after 60 seconds)
    validateCache();

    std::vector<std::pair<uid_t, std::vector<gid_t>>> userGroups;
    struct passwd pwd {};
    struct passwd* pwdResults = nullptr;
    NssBuffer passwdBuf {initialBufSize(m_sysWrapper->sysconf(_SC_GETPW_R_SIZE_MAX))};

    const auto nextPasswdEntry = [&]()
    {
        return passwdBuf.call([&](char* buf, size_t size)
        {
            return m_passwdWrapper->getpwent_r(&pwd, buf, size, &pwdResults);
        }) == 0 && pwdResults != nullptr;
    };

    const auto passwdEntryOf = [&](uid_t uid)
    {
        return passwdBuf.call([&](char* buf, size_t size)
        {
            return m_passwdWrapper->getpwuid_r(uid, &pwd, buf, size, &pwdResults);
        }) == 0 && pwdResults != nullptr;
    };

    // Membership of every account, read with one group enumeration the first time a user is
    // not in the cache. Asking getgrouplist() per user cost one initgroups request each, and on
    // a host whose accounts come from a directory every one of them can reach the directory
    // once the client's cache has expired. The group names are cached with the memberships so
    // getGroupNamesByUid() does not look every gid up again.
    std::unordered_map<std::string, std::vector<gid_t>> memberGids;
    bool membershipLoaded = false;

    // The enumeration has every membership an account has in /etc/group. The ones it has in a
    // directory are there only if the directory client lists the members of its groups: some
    // enumerate them without members (SSSD's ignore_group_members, for instance), others do not
    // enumerate at all, while initgroups still answers. So getgrouplist() is still asked about
    // a directory account that no group outside /etc/group lists, and about a local account
    // when no group outside /etc/group lists anyone.
    std::unordered_set<std::string> localUsers;
    std::unordered_set<gid_t> localGroups;
    std::unordered_set<std::string> listedByDirectoryGroup;
    bool directoryGroupsListMembers = false;

    // An enumeration that stops on an error instead of ENOENT (a source asking to try again, an
    // entry larger than the buffer cap), or local account files not read to their end, leave the
    // memberships incomplete, so in that scan every account is asked about with getgrouplist(),
    // as before the enumeration was used. A source that is unavailable is skipped by glibc and
    // ends the enumeration as usual; getgrouplist() would not reach it either.
    bool membershipComplete = true;

    // Reads the local account files and tells whether both were read to their end. A file cut
    // short leaves local accounts or groups out, and a local group missing from the set would pass
    // for a directory group that lists members. A file that cannot be opened is not read by
    // nss_files either, so none of its entries reach the enumeration.
    const auto loadLocalAccounts = [&]()
    {
        struct passwd localPwd {};
        struct passwd* localPwdResult = nullptr;
        NssBuffer localPwdBuf {MAX_GETPW_R_BUF_SIZE};
        int passwdRet = ENOENT;

        if (auto* file = m_sysWrapper->fopen(LOCAL_PASSWD_FILE, "r"); file != nullptr)
        {
            const auto nextLocalUser = [&]()
            {
                passwdRet = localPwdBuf.call([&](char* buf, size_t size)
                {
                    return m_passwdWrapper->fgetpwent_r(file, &localPwd, buf, size, &localPwdResult);
                });
                return passwdRet == 0 && localPwdResult != nullptr;
            };

            while (nextLocalUser())
            {
                if (localPwdResult->pw_name != nullptr)
                {
                    localUsers.emplace(localPwdResult->pw_name);
                }
            }

            m_sysWrapper->fclose(file);
        }

        group localGrp {};
        group* localGrpResult = nullptr;
        NssBuffer localGrpBuf {MAX_GETPW_R_BUF_SIZE};
        int groupFileRet = ENOENT;

        if (auto* file = m_sysWrapper->fopen(LOCAL_GROUP_FILE, "r"); file != nullptr)
        {
            const auto nextLocalGroup = [&]()
            {
                groupFileRet = localGrpBuf.call([&](char* buf, size_t size)
                {
                    return m_groupWrapper->fgetgrent_r(file, &localGrp, buf, size, &localGrpResult);
                });
                return groupFileRet == 0 && localGrpResult != nullptr;
            };

            while (nextLocalGroup())
            {
                localGroups.emplace(localGrpResult->gr_gid);
            }

            m_sysWrapper->fclose(file);
        }

        const auto readToEnd = [](int ret)
        {
            return ret == 0 || ret == ENOENT;
        };

        return readToEnd(passwdRet) && readToEnd(groupFileRet);
    };

    const auto loadMembership = [&]()
    {
        if (membershipLoaded)
        {
            return;
        }

        membershipLoaded = true;
        s_groupNamesCache.clear();
        const bool localAccountsRead = loadLocalAccounts();

        struct group grp {};
        struct group* grpResult = nullptr;
        NssBuffer groupBuf {MAX_GETPW_R_BUF_SIZE};

        int groupRet = 0;

        const auto nextGroupEntry = [&]()
        {
            groupRet = groupBuf.call([&](char* buf, size_t size)
            {
                return m_groupWrapper->getgrent_r(&grp, buf, size, &grpResult);
            });
            return groupRet == 0 && grpResult != nullptr;
        };

        m_groupWrapper->setgrent();

        while (nextGroupEntry())
        {
            // The first entry for a gid names it, as with getgrgid_r().
            if (grpResult->gr_name != nullptr)
            {
                s_groupNamesCache.emplace(grpResult->gr_gid, grpResult->gr_name);
            }

            const bool directoryGroup = localGroups.count(grpResult->gr_gid) == 0;

            for (char** member = grpResult->gr_mem; member != nullptr && *member != nullptr; ++member)
            {
                memberGids[*member].push_back(grpResult->gr_gid);

                if (directoryGroup)
                {
                    directoryGroupsListMembers = true;
                    listedByDirectoryGroup.emplace(*member);
                }
            }
        }

        m_groupWrapper->endgrent();
        membershipComplete = localAccountsRead && (groupRet == 0 || groupRet == ENOENT);
    };

    auto processUser = [&](const struct passwd * pwdInfo)
    {
        UserInfo user {pwdInfo->pw_name, pwdInfo->pw_uid, pwdInfo->pw_gid};

        // Check cache first
        auto it = s_userGroupsCache.find(user.uid);

        if (it != s_userGroupsCache.end())
        {
            userGroups.emplace_back(user.uid, it->second);
            return;
        }

        loadMembership();

        // Primary group first, then the rest by ascending gid and without repeats. A directory
        // does not enumerate its groups in a stable order, and reporting them in that order
        // would change the user's row from one scan to the next.
        std::vector<gid_t> groups {user.gid};

        if (user.name != nullptr)
        {
            if (const auto member = memberGids.find(user.name); member != memberGids.end())
            {
                groups.insert(groups.end(), member->second.begin(), member->second.end());
            }
        }

        const auto removeRepeats = [&groups, &user]()
        {
            groups.erase(std::remove(std::next(groups.begin()), groups.end(), user.gid), groups.end());
            std::sort(std::next(groups.begin()), groups.end());
            groups.erase(std::unique(std::next(groups.begin()), groups.end()), groups.end());
        };

        removeRepeats();

        // getgrouplist() is asked about a directory account no directory group lists (also when
        // a local group lists it), and about a local account when no directory group lists
        // anyone, since the enumeration may be missing their directory memberships.
        bool askInitgroups = false;

        if (user.name != nullptr)
        {
            askInitgroups = !membershipComplete
                            || (localUsers.count(user.name) != 0
                                ? !directoryGroupsListMembers
                                : listedByDirectoryGroup.count(user.name) == 0);
        }

        if (askInitgroups)
        {
            std::vector<gid_t> initGroups(EXPECTED_GROUPS_MAX);
            int nGroups = EXPECTED_GROUPS_MAX;

            if (m_groupWrapper->getgrouplist(user.name, user.gid, initGroups.data(), &nGroups) < 0)
            {
                initGroups.resize(static_cast<size_t>(std::max(nGroups, 0)));
                nGroups = static_cast<int>(initGroups.size());

                if (m_groupWrapper->getgrouplist(user.name, user.gid, initGroups.data(), &nGroups) < 0)
                {
                    nGroups = 0;
                }
            }

            initGroups.resize(static_cast<size_t>(std::max(nGroups, 0)));
            groups.insert(groups.end(), initGroups.begin(), initGroups.end());
            removeRepeats();
        }

        // Store in cache
        s_userGroupsCache[user.uid] = groups;
        userGroups.emplace_back(user.uid, std::move(groups));
    };

    if (uids.size() == 1)
    {
        if (passwdEntryOf(*uids.begin()))
        {
            processUser(pwdResults);
        }
    }
    else if (!uids.empty())
    {
        // Resolve the requested uids with one passwd enumeration instead of one getpwuid_r()
        // per uid. On a host whose accounts come from a directory each of those lookups can be
        // a round trip once the directory client's cache has expired. The first entry for a uid
        // wins, as with getpwuid_r(). A uid the enumeration does not return (a directory that
        // does not enumerate its accounts) is still looked up on its own.
        std::set<uid_t> pending {uids};
        m_passwdWrapper->setpwent();

        while (!pending.empty() && nextPasswdEntry())
        {
            if (pending.erase(pwdResults->pw_uid) > 0)
            {
                processUser(pwdResults);
            }
        }

        m_passwdWrapper->endpwent();

        for (const auto& uid : pending)
        {
            if (passwdEntryOf(uid))
            {
                processUser(pwdResults);
            }
        }
    }
    else
    {
        std::set<uid_t> processed_uids;
        m_passwdWrapper->setpwent();

        while (nextPasswdEntry())
        {
            if (processed_uids.insert(pwdResults->pw_uid).second)
            {
                processUser(pwdResults);
            }
        }

        m_passwdWrapper->endpwent();
    }

    // Mark cache as valid and update timestamp
    if (!s_userGroupsCache.empty())
    {
        s_cacheValid = true;
        s_cacheTimestamp = std::chrono::steady_clock::now();
    }

    return userGroups;
}

void UserGroupsProvider::addGroupsToResults(nlohmann::json& results, uid_t uid, const gid_t* groups, int nGroups)
{
    for (int i = 0; i < nGroups; i++)
    {
        nlohmann::json groupJson;

        groupJson["uid"] = uid;
        groupJson["gid"] = groups[i];

        results.push_back(groupJson);
    }
}
