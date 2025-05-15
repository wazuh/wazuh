#include "iuser_groups_wrapper.hpp"
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

class UserGroupsWrapper : public IUserGroupsWrapper
{
    public:
        long sysconf(int name) const override
        {
            return ::sysconf(name);
        }

        struct passwd* getpwuid(uid_t uid) const override
        {
            return ::getpwuid(uid);
        }

        int getpwuid_r(uid_t uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) const override
        {
            return ::getpwuid_r(uid, pwd, buf, buflen, result);
        }

        struct passwd* getpwent() const override
        {
            return ::getpwent();
        }

        int getpwent_r(struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) const override
        {
            return ::getpwent_r(pwd, buf, buflen, result);
        }

        void setpwent() const override
        {
            ::setpwent();
        }

        void endpwent() const override
        {
            ::endpwent();
        }

        int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const override
        {
            return ::getgrouplist(user, group, groups, ngroups);
        }
};
