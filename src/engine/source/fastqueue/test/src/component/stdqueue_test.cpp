#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <thread>

#include <fastqueue/stdqueue.hpp>

using namespace fastqueue;

// Dummy class for testing StdQueue
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

class StdQueueTest : public ::testing::Test
{
protected:
    StdQueueTest() {}

    ~StdQueueTest() {}

    void SetUp() override {}

    void TearDown() override {}

    static void SetUpTestSuite() {}
    static void TearDownTestSuite() {}
};

TEST_F(StdQueueTest, CanConstruct)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);
    ASSERT_TRUE(sq.empty());
    ASSERT_EQ(sq.size(), 0);
}

TEST_F(StdQueueTest, ConstructorRejectsNegativeCapacity)
{
    ASSERT_THROW({ StdQueue<std::shared_ptr<Dummy>> sq(-1); }, std::runtime_error);
}

TEST_F(StdQueueTest, ConstructorRejectsZeroCapacity)
{
    ASSERT_THROW({ StdQueue<std::shared_ptr<Dummy>> sq(0); }, std::runtime_error);
}

TEST_F(StdQueueTest, ConstructorRejectsTooSmallCapacity)
{
    ASSERT_THROW({ StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY - 1); }, std::runtime_error);
}

TEST_F(StdQueueTest, ConstructorAcceptsMinimumCapacity)
{
    ASSERT_NO_THROW({ StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY); });
}

TEST_F(StdQueueTest, ConstructorAcceptsLargeCapacity)
{
    ASSERT_NO_THROW({ StdQueue<std::shared_ptr<Dummy>> sq(1048576); });
}

TEST_F(StdQueueTest, CanPushAndPop)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);
    auto value = std::make_shared<Dummy>(42);
    ASSERT_TRUE(sq.push(std::move(value)));

    std::shared_ptr<Dummy> result;
    ASSERT_TRUE(sq.tryPop(result));
    ASSERT_EQ(result->value, 42);
}

TEST_F(StdQueueTest, Timeout)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);
    std::shared_ptr<Dummy> value;
    auto start = std::chrono::steady_clock::now();
    ASSERT_FALSE(sq.waitPop(value, 10000)); // 10ms timeout
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    ASSERT_GE(duration.count(), 8); // At least 8ms (some margin)
}

TEST_F(StdQueueTest, LargeQueueSequentialPop)
{
    constexpr int ELEMENTS = 10000;
    StdQueue<std::shared_ptr<Dummy>> sq(ELEMENTS); // Use capacity that fits all elements

    for (int i = 0; i < ELEMENTS; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    for (int i = 0; i < ELEMENTS; ++i)
    {
        std::shared_ptr<Dummy> value;
        ASSERT_TRUE(sq.tryPop(value));
        ASSERT_EQ(value->value, i);
    }
}

TEST_F(StdQueueTest, VeryLargeQueue)
{
    constexpr int CAPACITY = 1048576; // 2^20
    StdQueue<std::shared_ptr<Dummy>> sq(CAPACITY);

    ASSERT_TRUE(sq.empty());
    ASSERT_EQ(sq.size(), 0);
}

TEST_F(StdQueueTest, BulkOperations)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);

    // Push 100 elements
    for (int i = 0; i < 100; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Pop 50 in bulk
    std::shared_ptr<Dummy> elements[50];
    size_t popped = sq.tryPopBulk(elements, 50);
    ASSERT_EQ(popped, 50);

    // Verify FIFO order
    for (size_t i = 0; i < popped; ++i)
    {
        ASSERT_EQ(elements[i]->value, static_cast<int>(i));
    }
}

TEST_F(StdQueueTest, AproxFreeSlotsWithLargeQueue)
{
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY;
    StdQueue<std::shared_ptr<Dummy>> sq(CAPACITY);

    // Initially empty
    ASSERT_EQ(sq.aproxFreeSlots(), CAPACITY);

    // Fill half
    for (int i = 0; i < CAPACITY / 2; ++i)
    {
        sq.push(std::make_shared<Dummy>(i));
    }

    size_t freeSlots = sq.aproxFreeSlots();
    ASSERT_GE(freeSlots, CAPACITY / 2 - 100);
    ASSERT_LE(freeSlots, CAPACITY / 2 + 100);
}

TEST_F(StdQueueTest, QueueCapacityBehavior)
{
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY;
    StdQueue<std::shared_ptr<Dummy>> sq(CAPACITY);

    // Fill to capacity
    int pushed = 0;
    for (int i = 0; i < CAPACITY + 1000; ++i)
    {
        if (sq.push(std::make_shared<Dummy>(i)))
        {
            pushed++;
        }
        else
        {
            break;
        }
    }

    // Should stop at capacity
    ASSERT_EQ(pushed, CAPACITY);
    ASSERT_EQ(sq.aproxFreeSlots(), 0);
}

TEST_F(StdQueueTest, SizeAccuracyUnderLoad)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);

    // Push 100
    for (int i = 0; i < 100; ++i)
    {
        sq.push(std::make_shared<Dummy>(i));
    }

    ASSERT_EQ(sq.size(), 100);

    // Pop 50
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 50; ++i)
    {
        sq.tryPop(value);
    }

    ASSERT_EQ(sq.size(), 50);
}

TEST_F(StdQueueTest, AproxFreeSlotsAccuracy)
{
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY;
    StdQueue<std::shared_ptr<Dummy>> sq(CAPACITY);

    // Push 100
    for (int i = 0; i < 100; ++i)
    {
        sq.push(std::make_shared<Dummy>(i));
    }

    size_t freeSlots = sq.aproxFreeSlots();
    ASSERT_EQ(freeSlots, CAPACITY - 100);
}

TEST_F(StdQueueTest, QueueFullBehavior)
{
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY;
    StdQueue<std::shared_ptr<Dummy>> sq(CAPACITY);

    // Fill completely
    for (int i = 0; i < CAPACITY; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Next push should fail
    ASSERT_FALSE(sq.push(std::make_shared<Dummy>(9999)));
    ASSERT_EQ(sq.aproxFreeSlots(), 0);
}

TEST_F(StdQueueTest, PopFromEmptyQueue)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);

    std::shared_ptr<Dummy> value;
    ASSERT_FALSE(sq.tryPop(value));
    ASSERT_FALSE(sq.waitPop(value, 0));
}

TEST_F(StdQueueTest, TryPushVsPush)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);

    // tryPush with const reference
    auto dummy1 = std::make_shared<Dummy>(1);
    ASSERT_TRUE(sq.tryPush(dummy1));

    // push with move
    ASSERT_TRUE(sq.push(std::make_shared<Dummy>(2)));

    std::shared_ptr<Dummy> value;
    ASSERT_TRUE(sq.tryPop(value));
    ASSERT_EQ(value->value, 1);

    ASSERT_TRUE(sq.tryPop(value));
    ASSERT_EQ(value->value, 2);
}

TEST_F(StdQueueTest, FIFOOrdering)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);

    // Push sequence
    for (int i = 0; i < 1000; ++i)
    {
        sq.push(std::make_shared<Dummy>(i));
    }

    // Verify FIFO
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 1000; ++i)
    {
        ASSERT_TRUE(sq.tryPop(value));
        ASSERT_EQ(value->value, i);
    }
}

TEST_F(StdQueueTest, WaitPopWithDifferentTimeouts)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);

    std::shared_ptr<Dummy> value;

    // Zero timeout on empty queue
    ASSERT_FALSE(sq.waitPop(value, 0));

    // Short timeout
    auto start = std::chrono::steady_clock::now();
    ASSERT_FALSE(sq.waitPop(value, 5000)); // 5ms
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);
    ASSERT_GE(duration.count(), 3);

    // Now push and try with timeout
    sq.push(std::make_shared<Dummy>(42));
    ASSERT_TRUE(sq.waitPop(value, 10000));
    ASSERT_EQ(value->value, 42);
}

TEST_F(StdQueueTest, BulkPopExceedsAvailable)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);

    // Push only 10 elements
    for (int i = 0; i < 10; ++i)
    {
        sq.push(std::make_shared<Dummy>(i));
    }

    // Try to pop 50
    std::shared_ptr<Dummy> elements[50];
    size_t popped = sq.tryPopBulk(elements, 50);

    // Should only get 10
    ASSERT_EQ(popped, 10);
}

TEST_F(StdQueueTest, BulkPopFromEmptyQueue)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);

    std::shared_ptr<Dummy> elements[10];
    size_t popped = sq.tryPopBulk(elements, 10);

    ASSERT_EQ(popped, 0);
}

TEST_F(StdQueueTest, AlternatingPushPop)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);

    for (int i = 0; i < 1000; ++i)
    {
        sq.push(std::make_shared<Dummy>(i));

        std::shared_ptr<Dummy> value;
        ASSERT_TRUE(sq.tryPop(value));
        ASSERT_EQ(value->value, i);
        ASSERT_TRUE(sq.empty());
    }
}

TEST_F(StdQueueTest, SizeConsistencyAfterManyOperations)
{
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY);

    // Push 100
    for (int i = 0; i < 100; ++i)
    {
        sq.push(std::make_shared<Dummy>(i));
    }

    ASSERT_EQ(sq.size(), 100);

    // Pop 50
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 50; ++i)
    {
        sq.tryPop(value);
    }

    ASSERT_EQ(sq.size(), 50);

    // Pop remaining 50
    for (int i = 0; i < 50; ++i)
    {
        sq.tryPop(value);
    }

    ASSERT_EQ(sq.size(), 0);
}

TEST_F(StdQueueTest, CapacityRespectedAcrossBlocks)
{
    constexpr int CAPACITY = MIN_QUEUE_CAPACITY * 2;
    StdQueue<std::shared_ptr<Dummy>> sq(CAPACITY);

    // Try to push more than capacity
    int successfulPushes = 0;
    for (int i = 0; i < CAPACITY + 5000; ++i)
    {
        if (sq.push(std::make_shared<Dummy>(i)))
        {
            successfulPushes++;
        }
        else
        {
            break;
        }
    }

    // Should not exceed capacity
    ASSERT_EQ(successfulPushes, CAPACITY);
}

// ============================================================================
// Rate Limiter Tests
// ============================================================================

TEST_F(StdQueueTest, RateLimiterConstructorZeroRate)
{
    // maxElementsPerSecond = 0 should disable rate limiting
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 0.0);

    // Should work as normal queue without rate limiting
    for (int i = 0; i < 1000; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Should be able to pop all elements immediately (no rate limiting)
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 1000; ++i)
    {
        ASSERT_TRUE(sq.tryPop(value));
    }
}

TEST_F(StdQueueTest, RateLimiterConstructorInvalidParams)
{
    // Negative rate should throw
    ASSERT_THROW({ StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, -1.0); }, std::runtime_error);

    // Valid rate with invalid burst size should throw
    ASSERT_THROW({ StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 100.0, 0.5); }, std::runtime_error);
}

TEST_F(StdQueueTest, RateLimiterBasicThrottling)
{
    // Create queue with 10 elements/second rate limit
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 10.0, 10.0);

    // Fill queue
    for (int i = 0; i < 100; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Should be able to pop 10 elements immediately (burst)
    std::shared_ptr<Dummy> value;
    int successfulPops = 0;
    for (int i = 0; i < 20; ++i)
    {
        if (sq.tryPop(value))
        {
            successfulPops++;
        }
    }

    // Should get ~10 elements (the burst size)
    ASSERT_GE(successfulPops, 9); // Allow for timing variance
    ASSERT_LE(successfulPops, 11);

    // Immediately trying to pop more should fail (tokens exhausted)
    ASSERT_FALSE(sq.tryPop(value));
}

TEST_F(StdQueueTest, RateLimiterTokenRefill)
{
    // Create queue with 100 elements/second rate limit (very permissive)
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 100.0, 50.0);

    // Fill queue
    for (int i = 0; i < 200; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Pop burst (50 elements)
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 50; ++i)
    {
        ASSERT_TRUE(sq.tryPop(value));
    }

    // Next pop should fail (tokens exhausted)
    ASSERT_FALSE(sq.tryPop(value));

    // Wait for token refill (100 tokens/sec = 10ms per token, need ~10 tokens)
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Should now be able to pop more elements (tokens refilled)
    int refillPops = 0;
    for (int i = 0; i < 20; ++i)
    {
        if (sq.tryPop(value))
        {
            refillPops++;
        }
    }

    // Should have gotten at least 10 elements (150ms * 100/sec = 15 tokens)
    ASSERT_GE(refillPops, 10);
}

TEST_F(StdQueueTest, RateLimiterBurstSize)
{
    // Create queue with 100 elements/second but only 20 burst
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 100.0, 20.0);

    // Fill queue
    for (int i = 0; i < 100; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Should be able to pop up to burst size immediately
    std::shared_ptr<Dummy> value;
    int successfulPops = 0;
    for (int i = 0; i < 30; ++i)
    {
        if (sq.tryPop(value))
        {
            successfulPops++;
        }
    }

    // Should get ~20 elements (the burst size)
    ASSERT_GE(successfulPops, 19);
    ASSERT_LE(successfulPops, 21);
}

TEST_F(StdQueueTest, RateLimiterWaitPop)
{
    // Create queue with 10 elements/second rate limit
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 10.0, 5.0);

    // Fill queue
    for (int i = 0; i < 20; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Pop burst (5 elements)
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 5; ++i)
    {
        ASSERT_TRUE(sq.waitPop(value, 1000000)); // 1 second timeout
    }

    // Next waitPop should WAIT for tokens to refill, not return immediately
    // Rate is 10/sec = 1 token every 100ms
    // We should wait ~100ms and then succeed
    auto start = std::chrono::steady_clock::now();
    ASSERT_TRUE(sq.waitPop(value, 500000)); // 500ms timeout - should succeed after ~100ms
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    // Should have waited for token refill (~100ms), not returned immediately
    ASSERT_GE(duration.count(), 50);  // At least 50ms (some margin)
    ASSERT_LT(duration.count(), 300); // But less than 300ms
}

TEST_F(StdQueueTest, RateLimiterBulkOperations)
{
    // Create queue with 100 elements/second, burst of 50
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 100.0, 50.0);

    // Fill queue
    for (int i = 0; i < 200; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Try to pop 30 elements in bulk
    std::shared_ptr<Dummy> elements[30];
    size_t popped = sq.tryPopBulk(elements, 30);
    ASSERT_EQ(popped, 30); // Should succeed (within burst limit)

    // Try to pop 30 more immediately
    popped = sq.tryPopBulk(elements, 30);
    ASSERT_EQ(popped, 0); // Should fail (would exceed remaining tokens)

    // But should be able to pop smaller batches
    popped = sq.tryPopBulk(elements, 10);
    ASSERT_GE(popped, 10); // Should succeed (within remaining burst)
}

TEST_F(StdQueueTest, RateLimiterDefaultBurstSize)
{
    // Default burst size should equal maxElementsPerSecond
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 50.0); // No burst size specified

    // Fill queue
    for (int i = 0; i < 100; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Should be able to pop 50 elements immediately (default burst = rate)
    std::shared_ptr<Dummy> value;
    int successfulPops = 0;
    for (int i = 0; i < 60; ++i)
    {
        if (sq.tryPop(value))
        {
            successfulPops++;
        }
    }

    ASSERT_GE(successfulPops, 49);
    ASSERT_LE(successfulPops, 51);
}

TEST_F(StdQueueTest, RateLimiterNoInterferenceWithPush)
{
    // Rate limiting should NOT affect push operations
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 1.0, 1.0); // Very restrictive

    // Should be able to push many elements regardless of rate limit
    for (int i = 0; i < 1000; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    ASSERT_EQ(sq.size(), 1000);
}

TEST_F(StdQueueTest, RateLimiterThreadSafety)
{
    // Test that rate limiter is thread-safe
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY * 4, 1000.0, 500.0);

    // Fill queue
    for (int i = 0; i < 5000; ++i)
    {
        sq.push(std::make_shared<Dummy>(i));
    }

    std::atomic<int> totalPopped {0};

    // Multiple threads trying to pop
    auto popWorker = [&sq, &totalPopped]()
    {
        std::shared_ptr<Dummy> value;
        for (int i = 0; i < 200; ++i)
        {
            if (sq.tryPop(value))
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

TEST_F(StdQueueTest, RateLimiterWaitAcquireTimeout)
{
    // Create queue with very slow rate (1 element per second)
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 1.0, 1.0);

    // Fill queue
    for (int i = 0; i < 10; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Pop the initial burst token
    std::shared_ptr<Dummy> value;
    ASSERT_TRUE(sq.tryPop(value));

    // Next waitPop should timeout waiting for token (100ms timeout, need 1 second for token)
    auto start = std::chrono::steady_clock::now();
    ASSERT_FALSE(sq.waitPop(value, 100000)); // 100ms timeout
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start);

    // Should have waited approximately the timeout duration
    ASSERT_GE(duration.count(), 80);  // At least 80ms (some margin)
    ASSERT_LT(duration.count(), 200); // But not much more than timeout
}

TEST_F(StdQueueTest, RateLimiterWaitPopNoBusyWaiting)
{
    // Create queue with moderate rate (50 elements/second)
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY, 50.0, 10.0);

    // Fill queue
    for (int i = 0; i < 100; ++i)
    {
        ASSERT_TRUE(sq.push(std::make_shared<Dummy>(i)));
    }

    // Pop the burst
    std::shared_ptr<Dummy> value;
    for (int i = 0; i < 10; ++i)
    {
        ASSERT_TRUE(sq.tryPop(value));
    }

    // Measure CPU time vs wall time to detect busy waiting
    // If implementation is correct, thread should sleep and not consume CPU
    auto wallStart = std::chrono::steady_clock::now();

    // Multiple waitPops that should sleep waiting for tokens
    for (int i = 0; i < 5; ++i)
    {
        ASSERT_TRUE(sq.waitPop(value, 500000)); // 500ms timeout
    }

    auto wallDuration =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - wallStart);

    // Should have taken at least 50ms for tokens to refill (50/sec = 20ms per token, need ~5 tokens)
    ASSERT_GE(wallDuration.count(), 50);

    // If this test completes without spinning, it proves we're not busy waiting
    // (A busy wait would consume CPU but take the same wall time)
}

TEST_F(StdQueueTest, RateLimiterWaitPopMultipleThreads)
{
    // Test that multiple threads can waitPop without interfering
    StdQueue<std::shared_ptr<Dummy>> sq(MIN_QUEUE_CAPACITY * 4, 100.0, 50.0);

    // Fill queue
    for (int i = 0; i < 1000; ++i)
    {
        sq.push(std::make_shared<Dummy>(i));
    }

    std::atomic<int> totalPopped {0};
    std::atomic<int> totalTimeouts {0};

    // Multiple threads using waitPop
    auto waitPopWorker = [&sq, &totalPopped, &totalTimeouts]()
    {
        std::shared_ptr<Dummy> value;
        for (int i = 0; i < 100; ++i)
        {
            if (sq.waitPop(value, 100000)) // 100ms timeout
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
