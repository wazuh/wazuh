#ifndef _CMSTORE_ICMSTORE
#define _CMSTORE_ICMSTORE


#include <base/json.hpp>
#include <base/name.hpp>

#include <cmstore/types.hpp>

namespace cm::store
{


class ICMstoreReader
{
public:

    virtual ~ICMstoreReader() = default;

};

} // namespace cm::store

#endif // _CMSTORE_ICMSTORE
