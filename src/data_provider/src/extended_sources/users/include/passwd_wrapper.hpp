#include "ipasswd_wrapper.hpp"

class PasswdWrapper : public IPasswdWrapper
{
    public:
        int fgetpwent_r(FILE* stream, struct passwd* pwd,
                        char* buf, size_t buflen, struct passwd** result) override
        {
            return ::fgetpwent_r(stream, pwd, buf, buflen, result);
        }

        void setpwent() override
        {
            ::setpwent();
        }

        int getpwent_r(struct passwd* pwd, char* buf,
                       size_t buflen, struct passwd** result) override
        {
            return ::getpwent_r(pwd, buf, buflen, result);
        }

        void endpwent() override
        {
            ::endpwent();
        }

        int getpwuid_r(uid_t uid, struct passwd* pwd,
                       char* buf, size_t buflen, struct passwd** result) override
        {
            return ::getpwuid_r(uid, pwd, buf, buflen, result);
        }

        int getpwnam_r(const char* name, struct passwd* pwd,
                       char* buf, size_t buflen, struct passwd** result) override
        {
            return ::getpwnam_r(name, pwd, buf, buflen, result);
        }
};
