#pragma once

#include <pwd.h>
#include <grp.h>
#include <set>
#include <memory>
#include "user_groups_types.hpp"

class IUserGroupsWrapper
{
    public:
        virtual ~IUserGroupsWrapper() = default;

        virtual long sysconf(int name) const = 0;
        virtual struct passwd* getpwuid(uid_type uid) const = 0;
        virtual int getpwuid_r(uid_type uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) const = 0;
        virtual struct passwd* getpwent() const = 0;
#ifdef __linux__
        virtual int getpwent_r(struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) const = 0;
#endif
        virtual struct passwd* getpwnam(const char* name) const = 0;
        virtual void setpwent() const = 0;
        virtual void endpwent() const = 0;
        virtual int getgrouplist(const char* user, gid_type group, gid_type* groups, int* ngroups) const = 0;
#ifdef __APPLE__
        virtual int getgroupcount(const char* user, gid_type group) const = 0;
#endif
};
