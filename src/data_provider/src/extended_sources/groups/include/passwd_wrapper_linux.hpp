#include "ipasswd_wrapper_linux.hpp"

class PasswdWrapperLinux : public IPasswdWrapperLinux
{
    public:
        int getpwuid_r(uid_t uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) override
        {
            return ::getpwuid_r(uid, pwd, buf, buflen, result);
        }

        int getpwent_r(struct passwd* pwd, char* buf, size_t buflen, struct passwd** result) override
        {
            return ::getpwent_r(pwd, buf, buflen, result);
        }

        void setpwent() override
        {
            ::setpwent();
        }

        void endpwent() override
        {
            ::endpwent();
        }
};
