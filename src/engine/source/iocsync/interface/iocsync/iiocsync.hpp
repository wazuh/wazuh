#ifndef _IOCSYNC_IIOCSYNC_HPP
#define _IOCSYNC_IIOCSYNC_HPP

#include <string>
#include <vector>


namespace ioc::sync
{

class IIocSync {
public:
    virtual ~IIocSync() = default;
};

} // namespace ioc::sync

#endif // _IOCSYNC_IIOCSYNC_HPP
