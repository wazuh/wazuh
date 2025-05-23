#pragma once

#include "ishadow_wrapper.hpp"

class ShadowWrapper : public IShadowWrapper
{
    public:
        int lckpwdf()
        {
            return ::lckpwdf();
        }

        void setspent()
        {
            return ::setspent();
        }

        struct spwd* getspent()
        {
            return ::getspent();
        }

        void endspent()
        {
            return ::endspent();
        }

        int ulckpwdf()
        {
            return ::ulckpwdf();
        }

};
