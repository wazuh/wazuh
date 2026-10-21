// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef CMSYNC_MOCK_CMSYNC_HPP
#define CMSYNC_MOCK_CMSYNC_HPP

#include <gmock/gmock.h>

#include <cmsync/icmsync.hpp>

namespace cm::sync::mocks
{

class MockCMSync : public ICMSync
{
public:
    MOCK_METHOD(void, synchronize, (), (override));
    MOCK_METHOD(void, requestShutdown, (), (override));
    MOCK_METHOD(std::vector<SpaceStatus>, getSpacesStatus, (), (const, override));
};

} // namespace cm::sync::mocks

#endif // CMSYNC_MOCK_CMSYNC_HPP
