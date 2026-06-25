#ifndef IOCSYNC_MOCK_IOCSYNC_HPP
#define IOCSYNC_MOCK_IOCSYNC_HPP

#include <gmock/gmock.h>

#include <iocsync/iiocsync.hpp>

namespace ioc::sync::mocks
{

class MockIocSync : public IIocSync
{
public:
    MOCK_METHOD(void, synchronize, (), (override));
    MOCK_METHOD(void, requestShutdown, (), (override));
    MOCK_METHOD(std::vector<IocTypeStatus>, getIocStatus, (), (const, override));
};

} // namespace ioc::sync::mocks

#endif // IOCSYNC_MOCK_IOCSYNC_HPP
