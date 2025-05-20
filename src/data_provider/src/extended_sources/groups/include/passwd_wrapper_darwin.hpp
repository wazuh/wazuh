#include "ipasswd_wrapper_darwin.hpp"

class PasswdWrapperDarwin : public IPasswdWrapperDarwin
{
    public:
        struct passwd* getpwuid(uid_t uid) override
        {
            return ::getpwuid(uid);
        }

        struct passwd* getpwnam(const char* name) override
        {
            return ::getpwnam(name);
        }
};
