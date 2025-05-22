#pragma once

#include <utmpx.h>

class IUtmpxWrapper
{
    public:
        virtual ~IUtmpxWrapper() = default;

        virtual void utmpxname(const char* file) = 0;
        virtual void setutxent() = 0;
        virtual void endutxent() = 0;
        virtual struct utmpx* getutxent() = 0;
};
