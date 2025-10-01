
#ifndef _CM_SYNC_ICSYNC
#define _CM_SYNC_ICSYNC

#include <cstdint>
#include <string>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>

#include <ctistore/icmreader.hpp>

namespace cm::sync
{

class ICMSync
{
public:
    virtual ~ICMSync() = default;

    virtual void deploy(const std::shared_ptr<cti::store::ICMReader>& ctiStore) = 0;
};

} // namespace cm::sync

#endif // _CM_SYNC_ICSYNC
