#include "igroup_wrapper_linux.hpp"

#include <grp.h>

class GroupWrapperLinux : public IGroupWrapperLinux
{
    public:

        int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const override
        {
            return ::getgrouplist(user, group, groups, ngroups);
        }
};
