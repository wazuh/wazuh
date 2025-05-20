#pragma once

#include <grp.h>

class IGroupWrapperDarwin
{
    public:
        virtual ~IGroupWrapperDarwin() = default;

        virtual int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const = 0;
        virtual int getgroupcount(const char* user, gid_t group) const = 0;
};
