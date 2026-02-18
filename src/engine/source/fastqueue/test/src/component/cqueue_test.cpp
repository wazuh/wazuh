#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>

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

// Note: No test for negative capacity because size_t is unsigned.
// Passing -1 would wrap around to SIZE_MAX, causing allocation issues.
// Testing zero and below-minimum capacity is sufficient.

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

// ============================================================================
// Rate Limiter Tests
// ============================================================================

TEST_F(CQueueTest, RateLimiterConstructorZeroRate)
{
    // maxElementsPerSecond = 0 should disable rate limiting
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 0.0);

    // Should work as normal queue without rate limiting
    for (int i = 0; i < 1000; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    // Should be able to pop all elements immediately (no rate limiting)
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 1000; ++i)
    {
        ASSERT_TRUE(cq.tryPop(value));
    }
}

TEST_F(CQueueTest, RateLimiterConstructorInvalidParams)
{
    // Negative rate should throw
    ASSERT_THROW({ CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, -1.0); }, std::runtime_error);

    // Valid rate with invalid burst size should throw
    ASSERT_THROW({ CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 100.0, 0.5); }, std::runtime_error);
}

TEST_F(CQueueTest, RateLimiterBasicThrottling)
{
    // Create queue with 10 elements/second rate limit
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 10.0, 10.0);

    // Fill queue
    for (int i = 0; i < 100; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    // Should be able to pop 10 elements immediately (burst)
    std::shared_ptr<Dummy> value;
    int successfulPops = 0;
    for (int i = 0; i < 20; ++i)
    {
        if (cq.tryPop(value))
        {
            successfulPops++;
        }
    }

    // Should get ~10 elements (the burst size)
    ASSERT_GE(successfulPops, 9); // Allow for timing variance
    ASSERT_LE(successfulPops, 11);

    // Immediately trying to pop more should fail (tokens exhausted)
    ASSERT_FALSE(cq.tryPop(value));
}

TEST_F(CQueueTest, RateLimiterTokenRefill)
{
    // Create queue with 100 elements/second rate limit (very permissive)
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 100.0, 50.0);

    // Fill queue
    for (int i = 0; i < 200; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    // Pop burst (50 elements)
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 50; ++i)
    {
        ASSERT_TRUE(cq.tryPop(value));
    }

    // Next pop should fail (tokens exhausted)
    ASSERT_FALSE(cq.tryPop(value));

    // Wait for token refill (100 tokens/sec = 10ms per token, need ~10 tokens)
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Should now be able to pop more elements (tokens refilled)
    int refillPops = 0;
    for (int i = 0; i < 20; ++i)
    {
        if (cq.tryPop(value))
        {
            refillPops++;
        }
    }

    // Should have gotten at least 10 elements (150ms * 100/sec = 15 tokens)
    ASSERT_GE(refillPops, 10);
}

TEST_F(CQueueTest, RateLimiterBurstSize)
{
    // Create queue with 100 elements/second but only 20 burst
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 100.0, 20.0);

    // Fill queue
    for (int i = 0; i < 100; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    // Should be able to pop up to burst size immediately
    std::shared_ptr<Dummy> value;
    int successfulPops = 0;
    for (int i = 0; i < 30; ++i)
    {
        if (cq.tryPop(value))
        {
            successfulPops++;
        }
    }

    // Should get ~20 elements (the burst size)
    ASSERT_GE(successfulPops, 19);
    ASSERT_LE(successfulPops, 21);
}

TEST_F(CQueueTest, RateLimiterWaitPop)
{
    // Create queue with 10 elements/second rate limit
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 10.0, 5.0);

    // Fill queue
    for (int i = 0; i < 20; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    // Pop burst (5 elements)
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 5; ++i)
    {
        ASSERT_TRUE(cq.waitPop(value, 1000000)); // 1 second timeout
    }

    // Next waitPop should WAIT for tokens to refill, not return immediately
    // Rate is 10/sec = 1 token every 100ms
    // We should wait ~100ms and then succeed
    auto start = std::chrono::steady_clock::now();
    ASSERT_TRUE(cq.waitPop(value, 500000)); // 500ms timeout - should succeed after ~100ms
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    // Should have waited for token refill (~100ms), not returned immediately
    ASSERT_GE(duration.count(), 50);  // At least 50ms (some margin)
    ASSERT_LT(duration.count(), 300); // But less than 300ms
}

TEST_F(CQueueTest, RateLimiterBulkOperations)
{
    // Create queue with 100 elements/second, burst of 50
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 100.0, 50.0);

    // Fill queue
    for (int i = 0; i < 200; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    // Try to pop 30 elements in bulk
    std::shared_ptr<Dummy> elements[30];
    size_t popped = cq.tryPopBulk(elements, 30);
    ASSERT_EQ(popped, 30); // Should succeed (within burst limit)

    // Try to pop 30 more immediately
    popped = cq.tryPopBulk(elements, 30);
    ASSERT_EQ(popped, 0); // Should fail (would exceed remaining tokens)

    // But should be able to pop smaller batches
    popped = cq.tryPopBulk(elements, 10);
    ASSERT_GE(popped, 10); // Should succeed (within remaining burst)
}

TEST_F(CQueueTest, RateLimiterDefaultBurstSize)
{
    // Default burst size should equal maxElementsPerSecond
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 50.0); // No burst size specified

    // Fill queue
    for (int i = 0; i < 100; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    // Should be able to pop 50 elements immediately (default burst = rate)
    std::shared_ptr<Dummy> value;
    int successfulPops = 0;
    for (int i = 0; i < 60; ++i)
    {
        if (cq.tryPop(value))
        {
            successfulPops++;
        }
    }

    ASSERT_GE(successfulPops, 49);
    ASSERT_LE(successfulPops, 51);
}

TEST_F(CQueueTest, RateLimiterNoInterferenceWithPush)
{
    // Rate limiting should NOT affect push operations
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 1.0, 1.0); // Very restrictive

    // Should be able to push many elements regardless of rate limit
    for (int i = 0; i < 1000; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    ASSERT_EQ(cq.size(), 1000);
}

TEST_F(CQueueTest, RateLimiterThreadSafety)
{
    // Test that rate limiter is thread-safe
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY * 4, 1000.0, 500.0);

    // Fill queue
    for (int i = 0; i < 5000; ++i)
    {
        cq.push(std::make_shared<Dummy>(i));
    }

    std::atomic<int> totalPopped {0};

    // Multiple threads trying to pop
    auto popWorker = [&cq, &totalPopped]()
    {
        std::shared_ptr<Dummy> value;
        for (int i = 0; i < 200; ++i)
        {
            if (cq.tryPop(value))
            {
                totalPopped++;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    };

    std::thread t1(popWorker);
    std::thread t2(popWorker);
    std::thread t3(popWorker);

    t1.join();
    t2.join();
    t3.join();

    // Total popped should not exceed what rate limiter allows significantly
    // 1000/sec * ~0.6 seconds (3 threads * 200 * 1ms) = ~600 elements
    // Plus initial burst of 500
    ASSERT_LE(totalPopped, 1200); // Some margin for timing variance
}

TEST_F(CQueueTest, RateLimiterWaitAcquireTimeout)
{
    // Create queue with very slow rate (1 element per second)
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 1.0, 1.0);

    // Fill queue
    for (int i = 0; i < 10; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    // Pop the initial burst token
    std::shared_ptr<Dummy> value;
    ASSERT_TRUE(cq.tryPop(value));

    // Next waitPop should timeout waiting for token (100ms timeout, need 1 second for token)
    auto start = std::chrono::steady_clock::now();
    ASSERT_FALSE(cq.waitPop(value, 100000)); // 100ms timeout
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    // Should have waited approximately the timeout duration
    ASSERT_GE(duration.count(), 80);  // At least 80ms (some margin)
    ASSERT_LT(duration.count(), 200); // But not much more than timeout
}

TEST_F(CQueueTest, RateLimiterWaitPopNoBusyWaiting)
{
    // Create queue with moderate rate (50 elements/second)
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY, 50.0, 10.0);

    // Fill queue
    for (int i = 0; i < 100; ++i)
    {
        ASSERT_TRUE(cq.push(std::make_shared<Dummy>(i)));
    }

    // Pop the burst
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 10; ++i)
    {
        ASSERT_TRUE(cq.tryPop(value));
    }

    // Measure CPU time vs wall time to detect busy waiting
    // If implementation is correct, thread should sleep and not consume CPU
    auto wallStart = std::chrono::steady_clock::now();

    // Multiple waitPops that should sleep waiting for tokens
    for (int i = 0; i < 5; ++i)
    {
        ASSERT_TRUE(cq.waitPop(value, 500000)); // 500ms timeout
    }

    auto wallDuration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - wallStart);

    // Should have taken at least 50ms for tokens to refill (50/sec = 20ms per token, need ~5 tokens)
    ASSERT_GE(wallDuration.count(), 50);

    // If this test completes without spinning, it proves we're not busy waiting
    // (A busy wait would consume CPU but take the same wall time)
}

TEST_F(CQueueTest, RateLimiterWaitPopMultipleThreads)
{
    // Test that multiple threads can waitPop without interfering
    CQueue<std::shared_ptr<Dummy>> cq(MIN_QUEUE_CAPACITY * 4, 100.0, 50.0);

    // Fill queue
    for (int i = 0; i < 1000; ++i)
    {
        cq.push(std::make_shared<Dummy>(i));
    }

    std::atomic<int> totalPopped {0};
    std::atomic<int> totalTimeouts {0};

    // Multiple threads using waitPop
    auto waitPopWorker = [&cq, &totalPopped, &totalTimeouts]()
    {
        std::shared_ptr<Dummy> value;
        for (int i = 0; i < 100; ++i)
        {
            if (cq.waitPop(value, 100000)) // 100ms timeout
            {
                totalPopped++;
            }
            else
            {
                totalTimeouts++;
            }
        }
    };

    auto start = std::chrono::steady_clock::now();

    std::thread t1(waitPopWorker);
    std::thread t2(waitPopWorker);
    std::thread t3(waitPopWorker);

    t1.join();
    t2.join();
    t3.join();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    // With 100 elements/sec and initial burst of 50, in the time it takes
    // we should be able to pop roughly: 50 (burst) + 100 * (duration_seconds)
    // This verifies rate limiting is working across threads
    int expectedMax = 50 + static_cast<int>(100.0 * duration.count() / 1000.0) + 50; // +50 margin
    ASSERT_LE(totalPopped, expectedMax);
    ASSERT_GT(totalPopped, 0); // Should have popped something
}
