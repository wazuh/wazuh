#pragma once

#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <grp.h>
#include <pwd.h>

#include "json.hpp"
#include "iuser_groups_wrapper.hpp"

#define EXPECTED_GROUPS_MAX 64

#ifdef __APPLE__
// This symbol is exported from libSystem.B and has been since 10.6.
extern "C" int getgroupcount(const char* name, gid_t basegid);
#endif

template <typename T>
static inline void addGroupsToResults(nlohmann::json& results,
                                      int uid,
                                      const T* groups,
                                      int ngroups)
{
    for (int i = 0; i < ngroups; i++)
    {
        nlohmann::json row;
        row["uid"] = uid;
        row["gid"] = groups[i];
        results.push_back(row);
    }

    return;
}

template <typename uid_type, typename gid_type>
struct user_t
{
    const char* name;
    uid_type uid;
    gid_type gid;
};

template <typename uid_type, typename gid_type>
static void getGroupsForUser(nlohmann::json& results,
                             const user_t<uid_type, gid_type>& user,
                             const std::shared_ptr<IUserGroupsWrapper>& wrapper)
{
#ifdef __APPLE__
    int ngroups = getgroupcount(user.name, user.gid);
    gid_type* groups = new gid_type[ngroups];

    if (getgrouplist(user.name, user.gid, groups, &ngroups) < 0)
    {
        std::cerr << "Could not get users group list" << std::endl;
    }
    else
    {
        addGroupsToResults(results, user.uid, groups, ngroups);
    }

    delete[] groups;
#else
    gid_type groups_buf[EXPECTED_GROUPS_MAX];
    gid_type* groups = groups_buf;
    int ngroups = EXPECTED_GROUPS_MAX;

    // GLIBC version before 2.3.3 may have a buffer overrun:
    // http://man7.org/linux/man-pages/man3/getgrouplist.3.html
    if (wrapper->getgrouplist(user.name, user.gid, groups, &ngroups) < 0)
    {
        // EXPECTED_GROUPS_MAX was probably not large enough.
        // Try a larger size buffer.
        groups = new gid_type[ngroups];

        if (groups == nullptr)
        {
            std::cerr << "Could not allocate memory to get user groups" << std::endl;
            return;
        }

        if (wrapper->getgrouplist(user.name, user.gid, groups, &ngroups) < 0)
        {
            std::cerr << "Could not get users group list" << std::endl;
        }
        else
        {
            addGroupsToResults(results, user.uid, groups, ngroups);
        }

        delete[] groups;
    }
    else
    {
        addGroupsToResults(results, user.uid, groups, ngroups);
    }

#endif

}

class UserGroupsProvider
{
    public:
        explicit UserGroupsProvider(std::shared_ptr<IUserGroupsWrapper> userGroupsWrapper);
        UserGroupsProvider();
        nlohmann::json collect(const std::set<uid_t>& uids = {});

    private:
        std::shared_ptr<IUserGroupsWrapper> m_userGroupsWrapper;
};