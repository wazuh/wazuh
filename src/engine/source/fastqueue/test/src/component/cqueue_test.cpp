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

    void SetUp() override {}

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

TEST_F(CQueueTest, LargeQueueSequentialPop)
{
    // Test with realistic queue size (2^17 = 131072)
    constexpr int QUEUE_SIZE = 1 << 17;
    constexpr int TEST_ELEMENTS = 1000; // Test with subset for speed

    CQueue<std::shared_ptr<Dummy>> cq(QUEUE_SIZE);
    ASSERT_TRUE(cq.empty());

    // Push test elements
    for (int i = 0; i < TEST_ELEMENTS; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    ASSERT_EQ(cq.size(), TEST_ELEMENTS);
    ASSERT_FALSE(cq.empty());

    // Pop elements one by one (realistic usage pattern)
    for (int i = 0; i < TEST_ELEMENTS; ++i)
    {
        auto d = std::make_shared<Dummy>(-1);
        ASSERT_TRUE(cq.waitPop(d, WAIT_DEQUEUE_TIMEOUT_USEC));
        ASSERT_EQ(d->value, i);
    }

    ASSERT_TRUE(cq.empty());
}

TEST_F(CQueueTest, VeryLargeQueue)
{
    // Test with very large queue size (2^20 = 1,048,576)
    constexpr int QUEUE_SIZE = 1 << 20;
    constexpr int TEST_ELEMENTS = 2000; // Test with subset

    CQueue<std::shared_ptr<Dummy>> cq(QUEUE_SIZE);
    ASSERT_TRUE(cq.empty());
    ASSERT_EQ(cq.aproxFreeSlots(), QUEUE_SIZE);

    // Verify capacity works correctly
    for (int i = 0; i < TEST_ELEMENTS; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    ASSERT_EQ(cq.size(), TEST_ELEMENTS);

    // Sequential pop
    for (int i = 0; i < TEST_ELEMENTS; ++i)
    {
        auto d = std::make_shared<Dummy>(-1);
        ASSERT_TRUE(cq.tryPop(d));
        ASSERT_EQ(d->value, i);
    }

    ASSERT_TRUE(cq.empty());
}

TEST_F(CQueueTest, BulkOperations)
{
    CQueue<std::shared_ptr<Dummy>> cq(100);

    // Push elements
    for (int i = 0; i < 10; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    // Pop elements in bulk
    std::shared_ptr<Dummy> elements[5];
    size_t popped = cq.tryPopBulk(elements, 5);
    ASSERT_EQ(popped, 5);

    // Verify values
    for (size_t i = 0; i < popped; ++i)
    {
        ASSERT_EQ(elements[i]->value, static_cast<int>(i));
    }

    ASSERT_EQ(cq.size(), 5);
}

TEST_F(CQueueTest, AproxFreeSlotsWithLargeQueue)
{
    constexpr int CAPACITY = 1 << 17;
    CQueue<std::shared_ptr<Dummy>> cq(CAPACITY);

    ASSERT_EQ(cq.aproxFreeSlots(), CAPACITY);

    // Add some elements
    for (int i = 0; i < 100; ++i)
    {
        cq.push(std::make_shared<Dummy>(i));
    }

    // Should have approximately CAPACITY - 100 free slots
    size_t freeSlots = cq.aproxFreeSlots();
    ASSERT_GE(freeSlots, CAPACITY - 110); // Allow some margin for approximation
    ASSERT_LE(freeSlots, CAPACITY - 90);
}
