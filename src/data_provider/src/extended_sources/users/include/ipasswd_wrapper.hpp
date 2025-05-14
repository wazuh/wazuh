#pragma once
#include <sys/types.h>
#include <pwd.h>

class IPasswdWrapper
{
    public:
        virtual ~IPasswdWrapper() = default;

        virtual int fgetpwent_r(FILE* stream, struct passwd* pwd,
                                char* buf, size_t buflen, struct passwd** result) = 0;
        virtual void setpwent() = 0;
        virtual int getpwent_r(struct passwd* pwd, char* buf,
                               size_t buflen, struct passwd** result) = 0;
        virtual void endpwent() = 0;
        virtual int getpwuid_r(uid_t uid, struct passwd* pwd,
                               char* buf, size_t buflen, struct passwd** result) = 0;
        virtual int getpwnam_r(const char* name, struct passwd* pwd,
                               char* buf, size_t buflen, struct passwd** result) = 0;
};
