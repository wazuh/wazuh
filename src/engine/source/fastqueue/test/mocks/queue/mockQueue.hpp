#ifndef _MOCK_QUEUE_HPP
#define _MOCK_QUEUE_HPP

#include <fastqueue/iqueue.hpp>
#include <gmock/gmock.h>

using namespace fastqueue;

namespace fastqueue::mocks
{
template<typename T>
class MockQueue : public iQueue<T>
{
public:
    MOCK_METHOD(bool, push, (T && element), (override));
    MOCK_METHOD(bool, tryPush, (const T& element), (override));
    MOCK_METHOD(bool, waitPop, (T & element, int64_t timeout), (override));
    MOCK_METHOD(bool, tryPop, (T & element), (override));
    MOCK_METHOD(bool, empty, (), (const, override));
    MOCK_METHOD(size_t, size, (), (const, override));
    MOCK_METHOD(size_t, aproxFreeSlots, (), (const, override));
};

} // namespace queue::mocks

#endif // _MOCK_QUEUE_HPP
