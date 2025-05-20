#pragma once

#include <pwd.h>

class IPasswdWrapperDarwin
{
    public:
        virtual ~IPasswdWrapperDarwin() = default;

        virtual struct passwd* getpwuid(uid_t uid) = 0;
        virtual struct passwd* getpwnam(const char* name) = 0;
};
