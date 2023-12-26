#ifndef _MOCK_QUEUE_HPP
#define _MOCK_QUEUE_HPP

#include <gmock/gmock.h>
#include <queue/iqueue.hpp>

using namespace base::queue;

namespace queue::mocks
{
template <typename T>
class MockQueue : public iQueue<T>
{
public:
    MOCK_METHOD(void, push, (T&& element), (override));
    MOCK_METHOD(bool, tryPush, (const T& element), (override));
    MOCK_METHOD(bool, waitPop, (T& element, int64_t timeout), (override));
    MOCK_METHOD(bool, tryPop, (T& element), (override));
    MOCK_METHOD(bool, empty, (), (const, override));
    MOCK_METHOD(size_t, size, (), (const, override));
};

} // namespace queue::mocks

#endif // _MOCK_QUEUE_HPP
