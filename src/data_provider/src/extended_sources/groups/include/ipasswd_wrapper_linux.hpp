#pragma once
#include <sys/types.h>
#include <pwd.h>

class IPasswdWrapperLinux
{
    public:
        virtual ~IPasswdWrapperLinux() = default;

        virtual int getpwuid_r(uid_t uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) = 0;
        virtual int getpwent_r(struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) = 0;
        virtual void setpwent() = 0;
        virtual void endpwent() = 0;
};