#include <thread>
#include <chrono>
#include "threadDispatcher_test.h"
#include "threadDispatcher.h"

void ThreadDispatcherTest::SetUp() {};

void ThreadDispatcherTest::TearDown() {};

using ::testing::_;
using namespace Utils;

class FunctorWrapper
{
public:
    FunctorWrapper(){}
    ~FunctorWrapper(){}
    MOCK_METHOD(void, Operator, (const int), ());
    void operator()(const int value)
    {
        Operator(value);
    }
};

TEST_F(ThreadDispatcherTest, AsyncDispatcherPushAndRundown)
{
    FunctorWrapper functor;
    AsyncDispatcher<int, std::reference_wrapper<FunctorWrapper>> dispatcher
    {
        std::ref(functor)
    };
    EXPECT_EQ(std::thread::hardware_concurrency(), dispatcher.numberOfThreads());
    for (int i = 0; i < 10; ++i)
    {
        EXPECT_CALL(functor, Operator(i));
    }
    for (int i = 0; i < 10; ++i)
    {
        dispatcher.push(i);
    }
    dispatcher.rundown();
    EXPECT_TRUE(dispatcher.cancelled());
    EXPECT_EQ(0ul, dispatcher.size());
}

TEST_F(ThreadDispatcherTest, AsyncDispatcherCancel)
{
    FunctorWrapper functor;
    AsyncDispatcher<int, std::reference_wrapper<FunctorWrapper>> dispatcher
    {
        std::ref(functor)
    };
    EXPECT_EQ(std::thread::hardware_concurrency(), dispatcher.numberOfThreads());
    dispatcher.cancel();
    for (int i = 0; i < 10; ++i)
    {
        EXPECT_CALL(functor, Operator(i)).Times(0);
        dispatcher.push(i);
    }
    EXPECT_TRUE(dispatcher.cancelled());
    dispatcher.rundown();
    EXPECT_EQ(0ul, dispatcher.size());
}
