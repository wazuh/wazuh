#include "iutmpx_wrapper.hpp"
#include <utmpx.h>

class UtmpxWrapper : public IUtmpxWrapper
{
    public:
        void utmpxname(const char* file) override
        {
            ::utmpxname(file);
        }

        void setutxent() override
        {
            ::setutxent();
        }

        void endutxent() override
        {
            ::endutxent();
        }

        struct utmpx* getutxent() override
        {
            return ::getutxent();
        }
};
