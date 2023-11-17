#ifndef _MOCK_QUEUE_HPP
#define _MOCK_QUEUE_HPP

#include <gmock/gmock.h>
#include <queue/iqueue.hpp>

using namespace base::queue;

template <typename T>
class MockQueue : public iQueue<T>
{
public:
    MOCK_METHOD((void), push, (T&& element, bool priority), (override));
    MOCK_METHOD((void), waitPop, (T& element, bool priority), (override));
    MOCK_METHOD((bool), empty, (bool priority), (const, override));
    MOCK_METHOD((size_t), size, (bool priority), (const, override));
};

#endif // _MOCK_QUEUE_HPP
