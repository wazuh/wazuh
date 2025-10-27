#ifndef _MOCKS_CM_ISYNC_HPP
#define _MOCKS_CM_ISYNC_HPP

#include <gmock/gmock.h>

#include <cmstore/icmstore.hpp>

namespace cm::store
{
class MockICMstoreReader : public IICMstoreReader
{
public:
    MockICMstoreReader() = default;
    ~MockICMstoreReader() override = default;
};
} // namespace cti::store


#endif // _MOCKS_CM_ISYNC_HPP
