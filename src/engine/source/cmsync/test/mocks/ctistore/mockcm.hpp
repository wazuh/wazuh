#ifndef _MOCKS_CM_ISYNC_HPP
#define _MOCKS_CM_ISYNC_HPP

#include <gmock/gmock.h>

#include <cmsync/icmsync.hpp>

namespace cm::sync
{
class MockCMSync : public ICMSync
{
public:
    MockCMSync() = default;
    ~MockCMSync() override = default;
    MOCK_METHOD(void, deploy, (), (override));
};
} // namespace cti::store


#endif // _MOCKS_CM_ISYNC_HPP
