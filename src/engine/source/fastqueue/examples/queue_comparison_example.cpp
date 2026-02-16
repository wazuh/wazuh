/**
 * @file queue_comparison_example.cpp
 * @brief Example comparing CQueue and StdQueue implementations
 *
 * This example demonstrates:
 * - Basic usage of both queue implementations
 * - Rate limiting features
 * - Performance characteristics
 * - When to use each implementation
 */

#include <chrono>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

#include <fastqueue/cqueue.hpp>
#include <fastqueue/stdqueue.hpp>

using namespace fastqueue;

// Simple message struct for demonstration
struct Message
{
    int id;
    std::string data;

    Message(int i, std::string d)
        : id(i)
        , data(std::move(d))
    {
    }
};

// ============================================================================
// Example 1: Basic Usage Without Rate Limiting
// ============================================================================

template<typename QueueType>
void basicUsageExample(const std::string& queueName)
{
    std::cout << "\n=== " << queueName << " - Basic Usage ===\n";

    // Create queue with minimum capacity
    QueueType queue(MIN_QUEUE_CAPACITY);

    // Producer: Push messages
    std::cout << "Pushing 100 messages...\n";
    for (int i = 0; i < 100; ++i)
    {
        auto msg = std::make_shared<Message>(i, "Data " + std::to_string(i));
        if (!queue.push(std::move(msg)))
        {
            std::cerr << "Failed to push message " << i << "\n";
        }
    }

    std::cout << "Queue size: " << queue.size() << "\n";
    std::cout << "Free slots: " << queue.aproxFreeSlots() << "\n";

    // Consumer: Pop messages
    std::cout << "Popping all messages...\n";
    std::shared_ptr<Message> msg;
    int count = 0;
    while (queue.tryPop(msg))
    {
        count++;
        // Process message
        if (count % 20 == 0)
        {
            std::cout << "  Processed " << count << " messages...\n";
        }
    }

    std::cout << "Total processed: " << count << "\n";
    std::cout << "Queue empty: " << (queue.empty() ? "yes" : "no") << "\n";
}

// ============================================================================
// Example 2: Rate Limiting
// ============================================================================

template<typename QueueType>
void rateLimitingExample(const std::string& queueName)
{
    std::cout << "\n=== " << queueName << " - Rate Limiting ===\n";

    // Create queue with rate limiting: 50 messages/second, burst of 20
    QueueType queue(MIN_QUEUE_CAPACITY, 50.0, 20.0);

    // Producer: Push 100 messages (unlimited)
    std::cout << "Pushing 100 messages (no rate limit on push)...\n";
    for (int i = 0; i < 100; ++i)
    {
        auto msg = std::make_shared<Message>(i, "Rate-limited data");
        queue.push(std::move(msg));
    }

    std::cout << "Queue size after push: " << queue.size() << "\n";

    // Consumer: Pop with rate limiting
    std::cout << "Popping with rate limit (50/sec, burst=20)...\n";

    auto startTime = std::chrono::steady_clock::now();
    std::shared_ptr<Message> msg;
    int successfulPops = 0;
    int failedPops = 0;

    // First burst: should get ~20 messages immediately
    std::cout << "  Trying initial burst...\n";
    for (int i = 0; i < 30; ++i)
    {
        if (queue.tryPop(msg))
        {
            successfulPops++;
        }
        else
        {
            failedPops++;
        }
    }

    std::cout << "  Initial burst: " << successfulPops << " successful, " << failedPops << " rate-limited\n";

    // Wait for tokens to refill
    std::cout << "  Waiting 500ms for token refill...\n";
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Try again - should get more messages
    int beforeRefill = successfulPops;
    for (int i = 0; i < 30; ++i)
    {
        if (queue.tryPop(msg))
        {
            successfulPops++;
        }
    }

    std::cout << "  After refill: " << (successfulPops - beforeRefill) << " additional messages\n";

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime);

    std::cout << "Total time: " << duration.count() << "ms\n";
    std::cout << "Total popped: " << successfulPops << "\n";
    std::cout << "Effective rate: " << (successfulPops * 1000.0 / duration.count()) << " msg/sec\n";
}

// ============================================================================
// Example 3: Bulk Operations
// ============================================================================

template<typename QueueType>
void bulkOperationsExample(const std::string& queueName)
{
    std::cout << "\n=== " << queueName << " - Bulk Operations ===\n";

    QueueType queue(MIN_QUEUE_CAPACITY);

    // Push 1000 messages
    std::cout << "Pushing 1000 messages...\n";
    for (int i = 0; i < 1000; ++i)
    {
        auto msg = std::make_shared<Message>(i, "Bulk data");
        queue.push(std::move(msg));
    }

    // Pop in bulk (batches of 100)
    std::cout << "Popping in batches of 100...\n";
    std::shared_ptr<Message> buffer[100];
    int totalPopped = 0;
    int batches = 0;

    while (true)
    {
        size_t count = queue.tryPopBulk(buffer, 100);
        if (count == 0)
            break;

        totalPopped += count;
        batches++;

        // Process batch
        for (size_t i = 0; i < count; ++i)
        {
            // Simulate processing
        }
    }

    std::cout << "Popped " << totalPopped << " messages in " << batches << " batches\n";
    std::cout << "Average batch size: " << (totalPopped / (double)batches) << "\n";
}

// ============================================================================
// Example 4: waitPop with Rate Limiting (No Busy Waiting)
// ============================================================================

template<typename QueueType>
void waitPopExample(const std::string& queueName)
{
    std::cout << "\n=== " << queueName << " - waitPop with Rate Limiting ===\n";

    // Very restrictive rate: 5 messages/second
    QueueType queue(MIN_QUEUE_CAPACITY, 5.0, 3.0);

    // Push some messages
    std::cout << "Pushing 10 messages...\n";
    for (int i = 0; i < 10; ++i)
    {
        auto msg = std::make_shared<Message>(i, "Wait data");
        queue.push(std::move(msg));
    }

    // Consumer using waitPop
    std::cout << "Consumer using waitPop (rate: 5/sec, burst: 3)...\n";

    auto startTime = std::chrono::steady_clock::now();
    std::shared_ptr<Message> msg;

    // Pop burst (3 messages)
    std::cout << "  Popping burst (3 messages)...\n";
    for (int i = 0; i < 3; ++i)
    {
        if (queue.waitPop(msg, 1000000)) // 1 second timeout
        {
            std::cout << "    Popped message " << msg->id << "\n";
        }
    }

    // Next waitPop will WAIT for token refill (not busy wait!)
    std::cout << "  Waiting for next message (will sleep for token refill)...\n";
    auto waitStart = std::chrono::steady_clock::now();

    if (queue.waitPop(msg, 500000)) // 500ms timeout
    {
        auto waitDuration =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - waitStart);
        std::cout << "    Popped message " << msg->id << " after " << waitDuration.count() << "ms (no busy waiting!)\n";
    }

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime);
    std::cout << "Total time: " << duration.count() << "ms\n";
}

// ============================================================================
// Example 5: Multi-threaded Producer-Consumer
// ============================================================================

template<typename QueueType>
void multiThreadedExample(const std::string& queueName)
{
    std::cout << "\n=== " << queueName << " - Multi-threaded ===\n";

    QueueType queue(MIN_QUEUE_CAPACITY * 2);

    std::atomic<int> totalProduced {0};
    std::atomic<int> totalConsumed {0};
    std::atomic<bool> done {false};

    // Start 2 producers
    auto producer = [&](int producerId)
    {
        for (int i = 0; i < 500; ++i)
        {
            auto msg = std::make_shared<Message>(i, "Producer " + std::to_string(producerId));
            if (queue.push(std::move(msg)))
            {
                totalProduced++;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    };

    // Start 2 consumers
    auto consumer = [&](int consumerId)
    {
        std::shared_ptr<Message> msg;
        while (!done || !queue.empty())
        {
            if (queue.waitPop(msg, 10000)) // 10ms timeout
            {
                totalConsumed++;
                // Simulate processing
                std::this_thread::sleep_for(std::chrono::microseconds(50));
            }
        }
    };

    std::cout << "Starting 2 producers and 2 consumers...\n";

    auto startTime = std::chrono::steady_clock::now();

    std::thread p1(producer, 1);
    std::thread p2(producer, 2);
    std::thread c1(consumer, 1);
    std::thread c2(consumer, 2);

    // Wait for producers to finish
    p1.join();
    p2.join();

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    done = true;

    // Wait for consumers to finish
    c1.join();
    c2.join();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startTime);

    std::cout << "Produced: " << totalProduced << "\n";
    std::cout << "Consumed: " << totalConsumed << "\n";
    std::cout << "Duration: " << duration.count() << "ms\n";
    std::cout << "Throughput: " << (totalConsumed * 1000.0 / duration.count()) << " msg/sec\n";
}

// ============================================================================
// Main
// ============================================================================

int main()
{
    std::cout << "FastQueue Implementation Comparison Examples\n";
    std::cout << "============================================\n";

    try
    {
        // Example 1: Basic usage
        basicUsageExample<CQueue<std::shared_ptr<Message>>>("CQueue");
        basicUsageExample<StdQueue<std::shared_ptr<Message>>>("StdQueue");

        // Example 2: Rate limiting
        rateLimitingExample<CQueue<std::shared_ptr<Message>>>("CQueue");
        rateLimitingExample<StdQueue<std::shared_ptr<Message>>>("StdQueue");

        // Example 3: Bulk operations
        bulkOperationsExample<CQueue<std::shared_ptr<Message>>>("CQueue");
        bulkOperationsExample<StdQueue<std::shared_ptr<Message>>>("StdQueue");

        // Example 4: waitPop with rate limiting
        waitPopExample<CQueue<std::shared_ptr<Message>>>("CQueue");
        waitPopExample<StdQueue<std::shared_ptr<Message>>>("StdQueue");

        // Example 5: Multi-threaded
        multiThreadedExample<CQueue<std::shared_ptr<Message>>>("CQueue");
        multiThreadedExample<StdQueue<std::shared_ptr<Message>>>("StdQueue");

        std::cout << "\nAll examples completed successfully!\n";
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
