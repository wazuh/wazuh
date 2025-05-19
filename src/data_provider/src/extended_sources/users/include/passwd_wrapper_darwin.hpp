#include "ipasswd_wrapper_darwin.hpp"

class PasswdWrapperDarwin : public IPasswdWrapperDarwin
{
    public:
        struct passwd* getpwnam(const char* name) override
        {
            return ::getpwnam(name);
        }
        struct passwd* getpwuid(uid_t uid) override
        {
            return ::getpwuid(uid);
        }
        void setpwent() override
        {
            ::setpwent();
        }
        struct passwd* getpwent() override
        {
            return ::getpwent();
        }
        void endpwent() override
        {
            ::endpwent();
        }
};
