#pragma once

#include <pwd.h>
#include <grp.h>
#include <set>
#include <memory>

class IUserGroupsWrapper
{
    public:
        virtual ~IUserGroupsWrapper() = default;

        virtual long sysconf(int name) const = 0;
        virtual struct passwd* getpwuid(uid_t uid) const = 0;
        virtual int getpwuid_r(uid_t uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) const = 0;
        virtual struct passwd* getpwent() const = 0;
        virtual int getpwent_r(struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) const = 0;
        virtual void setpwent() const = 0;
        virtual void endpwent() const = 0;
        virtual int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const = 0;
};
