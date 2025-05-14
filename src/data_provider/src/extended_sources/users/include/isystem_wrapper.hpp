#pragma once
#include <memory>
#include <string>

class ISystemWrapper
{
    public:
        virtual ~ISystemWrapper() = default;

        virtual long sysconf(int name) const = 0;
        virtual FILE* fopen(const char* filename, const char* mode) = 0;
        virtual int fclose(FILE* stream) = 0;
        virtual char* strerror(int errnum) = 0;
};
