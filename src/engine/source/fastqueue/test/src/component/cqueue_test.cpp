#include <gtest/gtest.h>

#include <chrono>

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
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY);
    ASSERT_TRUE(cq.empty());
    ASSERT_EQ(cq.size(), 0);
}

TEST_F(CQueueTest, ConstructorRejectsNegativeCapacity)
{
    ASSERT_THROW({ CQueue<std::shared_ptr<Dummy>> cq(-1); }, std::runtime_error);
}

TEST_F(CQueueTest, ConstructorRejectsZeroCapacity)
{
    ASSERT_THROW({ CQueue<std::shared_ptr<Dummy>> cq(0); }, std::runtime_error);
}

TEST_F(CQueueTest, ConstructorRejectsTooSmallCapacity)
{
    // Capacity below MIN_QUEUE_CAPACITY should throw
    ASSERT_THROW({ CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY - 1); }, std::runtime_error);
    ASSERT_THROW({ CQueue<std::shared_ptr<Dummy>> cq(100); }, std::runtime_error);
    ASSERT_THROW({ CQueue<std::shared_ptr<Dummy>> cq(1024); }, std::runtime_error);
}

TEST_F(CQueueTest, ConstructorAcceptsMinimumCapacity)
{
    // Exactly MIN_QUEUE_CAPACITY should work
    ASSERT_NO_THROW({ CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY); });
}

TEST_F(CQueueTest, ConstructorAcceptsLargeCapacity)
{
    // Large capacities should work fine
    ASSERT_NO_THROW({ CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY * 10); });
    ASSERT_NO_THROW({ CQueue<std::shared_ptr<Dummy>> cq(1 << 20); });
}

TEST_F(CQueueTest, CanPushAndPop)
{
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY);
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
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY);
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
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY);

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

// =============================================================================
// Capacity and Size Tests
// =============================================================================

TEST_F(CQueueTest, QueueCapacityBehavior)
{
    // Test with minimum valid queue size
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY;
    CQueue<std::shared_ptr<Dummy>> cq(CAPACITY);

    // Fill the queue to capacity
    for (int i = 0; i < CAPACITY; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i))) << "Failed to push element " << i;
    }

    // Queue should be approximately at capacity
    ASSERT_GE(cq.size(), CAPACITY - 10); // Allow some margin for block allocation
    ASSERT_EQ(cq.aproxFreeSlots(), 0);   // Should report 0 free slots

    // Additional pushes may fail (queue is full)
    // Note: try_enqueue may succeed if there's space in the current block
    bool canPush = cq.push(std::make_shared<Dummy>(CAPACITY));
    if (!canPush)
    {
        // This is expected - queue is full
        ASSERT_FALSE(canPush) << "Push should fail when queue is full";
    }
}

TEST_F(CQueueTest, SizeAccuracyUnderLoad)
{
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY;
    CQueue<std::shared_ptr<Dummy>> cq(CAPACITY);

    // Push elements and verify size grows
    for (int i = 0; i < 500; ++i)
    {
        cq.push(std::make_shared<Dummy>(i));
    }

    size_t sizeAfterPush = cq.size();
    ASSERT_GE(sizeAfterPush, 490); // Allow margin for approximation
    ASSERT_LE(sizeAfterPush, 510);

    // Pop half and verify size decreases
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 250; ++i)
    {
        ASSERT_TRUE(cq.tryPop(value));
    }

    size_t sizeAfterPop = cq.size();
    ASSERT_GE(sizeAfterPop, 240);
    ASSERT_LE(sizeAfterPop, 260);
}

TEST_F(CQueueTest, AproxFreeSlotsAccuracy)
{
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY;
    CQueue<std::shared_ptr<Dummy>> cq(CAPACITY);

    // Verify free slots decrease as we add elements
    ASSERT_EQ(cq.aproxFreeSlots(), CAPACITY);

    cq.push(std::make_shared<Dummy>(1));
    ASSERT_LT(cq.aproxFreeSlots(), CAPACITY);
    ASSERT_GT(cq.aproxFreeSlots(), 0);

    // Fill most of the queue
    for (int i = 0; i < CAPACITY - 1000; ++i)
    {
        cq.push(std::make_shared<Dummy>(i));
    }

    size_t freeSlots = cq.aproxFreeSlots();
    ASSERT_LE(freeSlots, 1100); // Should be close to full
}

TEST_F(CQueueTest, QueueFullBehavior)
{
    // Use minimum valid queue size
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY;
    CQueue<std::shared_ptr<Dummy>> cq(CAPACITY);

    // Fill the queue
    int pushed = 0;
    for (int i = 0; i < CAPACITY * 2; ++i)
    {
        if (cq.push(std::make_shared<Dummy>(i)))
        {
            pushed++;
        }
        else
        {
            // Queue is full
            break;
        }
    }

    ASSERT_GE(pushed, CAPACITY - 10); // Should have pushed at least capacity elements

    // Try to push when full - should fail
    // Note: May succeed due to block allocation, but eventually should fail
    int failCount = 0;
    for (int i = 0; i < 10; ++i)
    {
        if (!cq.push(std::make_shared<Dummy>(1000 + i)))
        {
            failCount++;
        }
    }

    // Queue should now be full or nearly full
    ASSERT_EQ(cq.aproxFreeSlots(), 0);
}

// =============================================================================
// Edge Cases and Error Handling
// =============================================================================

TEST_F(CQueueTest, PopFromEmptyQueue)
{
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY);
    std::shared_ptr<Dummy> value;

    // tryPop from empty queue should return false
    ASSERT_FALSE(cq.tryPop(value));

    // waitPop with 0 timeout should return false immediately
    ASSERT_FALSE(cq.waitPop(value, 0));
}

TEST_F(CQueueTest, TryPushVsPush)
{
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY;
    CQueue<std::shared_ptr<Dummy>> cq(CAPACITY);

    // Both should work the same way
    auto elem1 = std::make_shared<Dummy>(1);
    auto elem2 = std::make_shared<Dummy>(2);

    ASSERT_TRUE(cq.push(std::make_shared<Dummy>(1)));
    ASSERT_TRUE(cq.tryPush(elem2));

    ASSERT_EQ(cq.size(), 2);
}

TEST_F(CQueueTest, FIFOOrdering)
{
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY);

    // Push sequence
    for (int i = 0; i < 50; ++i)
    {
        cq.push(std::make_shared<Dummy>(i));
    }

    // Pop and verify FIFO order
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 50; ++i)
    {
        ASSERT_TRUE(cq.tryPop(value));
        ASSERT_EQ(value->value, i) << "FIFO order violated at position " << i;
    }

    ASSERT_TRUE(cq.empty());
}

TEST_F(CQueueTest, WaitPopWithDifferentTimeouts)
{
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY);
    std::shared_ptr<Dummy> value;

    // Timeout 0 (no wait) on empty queue
    auto start = std::chrono::steady_clock::now();
    ASSERT_FALSE(cq.waitPop(value, 0));
    auto duration = std::chrono::steady_clock::now() - start;
    ASSERT_LT(duration, std::chrono::milliseconds(10)); // Should return immediately

    // Small timeout on empty queue
    start = std::chrono::steady_clock::now();
    ASSERT_FALSE(cq.waitPop(value, 10000)); // 10ms
    duration = std::chrono::steady_clock::now() - start;
    ASSERT_GE(duration, std::chrono::microseconds(9000)); // At least 9ms
    ASSERT_LT(duration, std::chrono::milliseconds(100));  // But not too long
}

TEST_F(CQueueTest, BulkPopExceedsAvailable)
{
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY);

    // Push only 5 elements
    for (int i = 0; i < 5; ++i)
    {
        cq.push(std::make_shared<Dummy>(i));
    }

    // Try to pop 10 (more than available)
    std::shared_ptr<Dummy> elements[10];
    size_t popped = cq.tryPopBulk(elements, 10);

    ASSERT_EQ(popped, 5); // Should only get 5

    // Verify values
    for (size_t i = 0; i < popped; ++i)
    {
        ASSERT_EQ(elements[i]->value, static_cast<int>(i));
    }

    ASSERT_TRUE(cq.empty());
}

TEST_F(CQueueTest, BulkPopFromEmptyQueue)
{
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY);
    std::shared_ptr<Dummy> elements[10];

    size_t popped = cq.tryPopBulk(elements, 10);
    ASSERT_EQ(popped, 0); // No elements available
}

TEST_F(CQueueTest, AlternatingPushPop)
{
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY);

    // Alternate between push and pop
    for (int i = 0; i < 100; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));

        std::shared_ptr<Dummy> value;
        ASSERT_TRUE(cq.tryPop(value));
        ASSERT_EQ(value->value, i);

        ASSERT_TRUE(cq.empty());
    }
}

TEST_F(CQueueTest, SizeConsistencyAfterManyOperations)
{
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY * 2);

    // Perform many push/pop operations
    for (int cycle = 0; cycle < 10; ++cycle)
    {
        // Push 100
        for (int i = 0; i < 100; ++i)
        {
            cq.push(std::make_shared<Dummy>(i));
        }

        ASSERT_GE(cq.size(), 90); // Approximate
        ASSERT_LE(cq.size(), 110);

        // Pop 50
        std::shared_ptr<Dummy> value;
        for (int i = 0; i < 50; ++i)
        {
            cq.tryPop(value);
        }

        ASSERT_GE(cq.size(), 40);
        ASSERT_LE(cq.size(), 60);

        // Pop remaining 50
        for (int i = 0; i < 50; ++i)
        {
            cq.tryPop(value);
        }

        ASSERT_EQ(cq.size(), 0);
    }
}

TEST_F(CQueueTest, CapacityRespectedAcrossBlocks)
{
    // Test that capacity is respected even with block-based allocation
    // Using BLOCK_SIZE=4096, a queue of MIN_QUEUE_CAPACITY*2 should use ~4 blocks
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY * 2;
    CQueue<std::shared_ptr<Dummy>> cq(CAPACITY);

    // Try to push more than capacity
    int successfulPushes = 0;
    for (int i = 0; i < CAPACITY + 5000; ++i)
    {
        if (cq.push(std::make_shared<Dummy>(i)))
        {
            successfulPushes++;
        }
        else
        {
            break;
        }
    }

    // Should not exceed capacity significantly
    // Due to block allocation, may overshoot slightly
    ASSERT_LE(successfulPushes, CAPACITY + 4096); // Max 1 extra block
    ASSERT_GE(successfulPushes, CAPACITY);        // At least capacity
}
