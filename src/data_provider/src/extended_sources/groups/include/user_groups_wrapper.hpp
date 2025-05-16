#include "iuser_groups_wrapper.hpp"
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#ifdef __APPLE__
// This symbol is exported from libSystem.B and has been since 10.6.
extern "C" int getgroupcount(const char* name, gid_t basegid);
#endif

class UserGroupsWrapper : public IUserGroupsWrapper
{
    public:
        long sysconf(int name) const override
        {
            return ::sysconf(name);
        }

        struct passwd* getpwuid(uid_type uid) const override
        {
            return ::getpwuid(uid);
        }

        int getpwuid_r(uid_type uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) const override
        {
            return ::getpwuid_r(uid, pwd, buf, buflen, result);
        }

        struct passwd* getpwent() const override
        {
            return ::getpwent();
        }

#ifdef __linux__
        int getpwent_r(struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) const override
        {
            return ::getpwent_r(pwd, buf, buflen, result);
        }
#endif

        struct passwd* getpwnam(const char* name) const override
        {
            return ::getpwnam(name);
        }

        void setpwent() const override
        {
            ::setpwent();
        }

        void endpwent() const override
        {
            ::endpwent();
        }

        int getgrouplist(const char* user, gid_type group, gid_type* groups, int* ngroups) const override
        {
            return ::getgrouplist(user, group, groups, ngroups);
        }

        int getgroupcount(const char* user, gid_type group) const override
        {
            return getgroupcount(user, group);
        }
};
