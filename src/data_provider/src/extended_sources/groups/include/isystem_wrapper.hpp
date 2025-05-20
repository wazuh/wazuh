#pragma once

class ISystemWrapper
{
    public:
        virtual ~ISystemWrapper() = default;

        virtual long sysconf(int name) const = 0;
};
