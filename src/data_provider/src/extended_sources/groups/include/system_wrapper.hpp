#include "isystem_wrapper.hpp"

#include <unistd.h>

class SystemWrapper : public ISystemWrapper
{
    public:
        long sysconf(int name) const override
        {
            return ::sysconf(name);
        }
};
