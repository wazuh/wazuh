#ifndef _MOCKS_CM_ISYNC_HPP
#define _MOCKS_CM_ISYNC_HPP

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cmsync/icmsync.hpp>

namespace cm::sync
{

class MockICMSync : public ICMSync
{
public:
    ~MockICMSync() override = default;
};

} // namespace cm::sync

#endif // _MOCKS_CM_ISYNC_HPP
