#include <gtest/gtest.h>

#include <fastqueue/cqueue.hpp>

using namespace fastqueue;

// Dummy class for testing CQueue
class Dummy
{
public:
    int value;

    Dummy(int v)
        : value(v)
    {
    }

    std::string str() const { return "Dummy: " + std::to_string(value); }
};

class CQueueTest : public ::testing::Test
{
protected:
    CQueueTest() {}

    ~CQueueTest() {}

    void SetUp() override { }

    void TearDown() override {}

    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
};

TEST_F(CQueueTest, CanConstruct)
{
    CQueue<std::shared_ptr<Dummy>> cq(2);
    ASSERT_TRUE(cq.empty());
    ASSERT_EQ(cq.size(), 0);
}

TEST_F(CQueueTest, CanPushAndPop)
{
    CQueue<std::shared_ptr<Dummy>> cq(2);
    ASSERT_TRUE(cq.empty());
    cq.push(std::make_shared<Dummy>(1));
    ASSERT_FALSE(cq.empty());
    ASSERT_EQ(cq.size(), 1);
    auto d = std::make_shared<Dummy>(0);
    ASSERT_TRUE(cq.waitPop(d, WAIT_DEQUEUE_TIMEOUT_USEC));
    ASSERT_EQ(d->value, 1);
    ASSERT_TRUE(cq.empty());
    ASSERT_EQ(cq.size(), 0);
}


TEST_F(CQueueTest, Timeout)
{
    CQueue<std::shared_ptr<Dummy>> cq(2);
    auto d = std::make_shared<Dummy>(0);
    ASSERT_FALSE(cq.waitPop(d, 0));
    ASSERT_EQ(d->value, 0);
}
