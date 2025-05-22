#pragma once

#include <pwd.h>

class IPasswdWrapperDarwin
{
    public:
        virtual ~IPasswdWrapperDarwin() = default;
        virtual struct passwd* getpwnam(const char* name) = 0;
        virtual struct passwd* getpwuid(uid_t uid) = 0;
        virtual void setpwent() = 0;
        virtual struct passwd* getpwent() = 0;
        virtual void endpwent() = 0;
};
