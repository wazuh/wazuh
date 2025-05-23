#pragma once

#include <shadow.h>

class IShadowWrapper
{
    public:
        virtual ~IShadowWrapper() = default;
        virtual int lckpwdf() = 0;
        virtual void setspent() = 0;
        virtual spwd* getspent() = 0;
        virtual void endspent() = 0;
        virtual int ulckpwdf() = 0;
};
