
#ifndef _CM_SYNC_ICSYNC
#define _CM_SYNC_ICSYNC

#include <cstdint>
#include <string>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>

namespace cm::sync
{

class ICMSync
{
public:
    virtual ~ICMSync() = default;

    virtual void deploy() = 0;
};

} // namespace cm::sync

#endif // _CM_SYNC_ICSYNC
