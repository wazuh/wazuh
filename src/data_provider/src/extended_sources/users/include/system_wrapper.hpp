#include "isystem_wrapper.hpp"

#include <unistd.h>
#include <cstdio>
#include <cstring>

class SystemWrapper : public ISystemWrapper
{
    public:
        long sysconf(int name) const override
        {
            return ::sysconf(name);
        }

        FILE* fopen(const char* filename, const char* mode) override
        {
            return ::fopen(filename, mode);
        }

        int fclose(FILE* stream) override
        {
            return ::fclose(stream);
        }

        char* strerror(int errnum) override
        {
            return ::strerror(errnum);
        }
};
