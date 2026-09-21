#ifndef CMSYNC_MOCK_CMSYNC_HPP
#define CMSYNC_MOCK_CMSYNC_HPP

#include <gmock/gmock.h>

#include <cmsync/icmsync.hpp>

namespace cm::sync::mocks
{

class MockCMSync : public ICMSync
{
public:
    MOCK_METHOD(void, requestShutdown, (), (override));
    MOCK_METHOD(std::vector<SpaceStatus>, getSpacesStatus, (), (const, override));
    MOCK_METHOD(void, requestOnDemandUpdate, (std::string_view space), (override));
};

} // namespace cm::sync::mocks

#endif // CMSYNC_MOCK_CMSYNC_HPP
