#ifndef _CMSTORE_CMSTORE
#define _CMSTORE_CMSTORE

#include <memory>
#include <string>

#include <cmstore/icmstore.hpp>

namespace cm::store
{

class CMStore : public ICMstore
{
public:

    CMStore() = default;
    ~CMStore() = default;

};

} // namespace cm::store

#endif // _CMSTORE_CMSTORE
