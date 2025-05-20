#include "igroup_wrapper_darwin.hpp"

#include <grp.h>
#include <unistd.h>

// This symbol is exported from libSystem.B and has been since 10.6.
extern "C" int getgroupcount(const char* name, gid_t basegid);

class GroupWrapperDarwin : public IGroupWrapperDarwin
{
    public:

        int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const override
        {
            return ::getgrouplist(user, group, (int*)groups, ngroups);
        }

        int getgroupcount(const char* user, gid_t group) const override
        {
            return ::getgroupcount(user, group);
        }
};
