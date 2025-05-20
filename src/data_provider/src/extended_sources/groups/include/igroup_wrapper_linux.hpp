#pragma once

#include <grp.h>

class IGroupWrapperLinux
{
    public:
        virtual ~IGroupWrapperLinux() = default;

        virtual int getgrouplist(const char* user, gid_t group, gid_t* groups, int* ngroups) const = 0;
};
