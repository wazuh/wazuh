#ifndef _MOCKS_ISCHEDULER_HPP
#define _MOCKS_ISCHEDULER_HPP

#include <gmock/gmock.h>

#include <scheduler/ischeduler.hpp>

namespace scheduler::mocks
{
class MockIScheduler : public ::scheduler::IScheduler
{
public:
    MOCK_METHOD(void, scheduleTask, (std::string_view taskName, TaskConfig&& config), (override));
    MOCK_METHOD(void, removeTask, (std::string_view taskName), (override));
    MOCK_METHOD(std::size_t, getActiveTasksCount, (), (const, override));
    MOCK_METHOD(std::size_t, getThreadCount, (), (const, override));
};

} // namespace scheduler::mocks

#endif // _MOCKS_ISCHEDULER_HPP
