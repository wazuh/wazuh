#include <benchmark/benchmark.h>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

#include <fastqueue/cqueue.hpp>
#include <fastqueue/stdqueue.hpp>

using namespace fastqueue;

// Helper struct for benchmarking
struct BenchData
{
    int value;
    char padding[60]; // Make it ~64 bytes to simulate real-world data

    explicit BenchData(int v = 0)
        : value(v)
    {
    }
};

// =============================================================================
// SPSC Comparison - CQueue vs StdQueue
// =============================================================================

static void BM_Compare_SPSC_CQueue(benchmark::State& state)
{
    const int items = state.range(0);
    CQueue<std::shared_ptr<BenchData>> queue(1 << 17);

    for (auto _ : state)
    {
        for (int i = 0; i < items; ++i)
        {
            queue.push(std::make_shared<BenchData>(i));
        }

        std::shared_ptr<BenchData> value;
        for (int i = 0; i < items; ++i)
        {
            queue.waitPop(value, WAIT_DEQUEUE_TIMEOUT_USEC);
            benchmark::DoNotOptimize(value);
        }
    }

    state.SetItemsProcessed(state.iterations() * items * 2);
}

static void BM_Compare_SPSC_StdQueue(benchmark::State& state)
{
    const int items = state.range(0);
    StdQueue<std::shared_ptr<BenchData>> queue(1 << 17);

    for (auto _ : state)
    {
        for (int i = 0; i < items; ++i)
        {
            queue.push(std::make_shared<BenchData>(i));
        }

        std::shared_ptr<BenchData> value;
        for (int i = 0; i < items; ++i)
        {
            queue.waitPop(value, WAIT_DEQUEUE_TIMEOUT_USEC);
            benchmark::DoNotOptimize(value);
        }
    }

    state.SetItemsProcessed(state.iterations() * items * 2);
}

BENCHMARK(BM_Compare_SPSC_CQueue)->Arg(1000)->Arg(10000)->Arg(50000)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Compare_SPSC_StdQueue)->Arg(1000)->Arg(10000)->Arg(50000)->Unit(benchmark::kMicrosecond);

// =============================================================================
// MPMC Comparison - 4 producers, 4 consumers
// =============================================================================

template<typename QueueType>
static void BM_Compare_MPMC_Template(benchmark::State& state, const std::string& queueName)
{
    const int numProducers = 4;
    const int numConsumers = 4;
    const int itemsPerProducer = 1000;
    const int totalItems = numProducers * itemsPerProducer;

    QueueType queue(1 << 17);

    for (auto _ : state)
    {
        std::atomic<int> startFlag {0};
        std::atomic<int> itemsConsumed {0};

        std::vector<std::thread> threads;
        threads.reserve(numProducers + numConsumers);

        // Producer threads
        for (int p = 0; p < numProducers; ++p)
        {
            threads.emplace_back(
                [&, p]()
                {
                    startFlag.fetch_add(1, std::memory_order_release);
                    while (startFlag.load(std::memory_order_acquire) < numProducers + numConsumers)
                    {
                        std::this_thread::yield();
                    }

                    for (int i = 0; i < itemsPerProducer; ++i)
                    {
                        while (!queue.push(std::make_shared<BenchData>(p * 10000 + i)))
                        {
                            std::this_thread::yield();
                        }
                    }
                });
        }

        // Consumer threads
        for (int c = 0; c < numConsumers; ++c)
        {
            threads.emplace_back(
                [&]()
                {
                    startFlag.fetch_add(1, std::memory_order_release);
                    while (startFlag.load(std::memory_order_acquire) < numProducers + numConsumers)
                    {
                        std::this_thread::yield();
                    }

                    std::shared_ptr<BenchData> value;
                    while (itemsConsumed.load(std::memory_order_acquire) < totalItems)
                    {
                        if (queue.tryPop(value))
                        {
                            benchmark::DoNotOptimize(value);
                            if (itemsConsumed.fetch_add(1, std::memory_order_release) + 1 >= totalItems)
                            {
                                break;
                            }
                        }
                    }
                });
        }

        for (auto& t : threads)
        {
            t.join();
        }
    }

    state.SetItemsProcessed(state.iterations() * totalItems);
}

static void BM_Compare_MPMC_CQueue(benchmark::State& state)
{
    BM_Compare_MPMC_Template<CQueue<std::shared_ptr<BenchData>>>(state, "CQueue");
}

static void BM_Compare_MPMC_StdQueue(benchmark::State& state)
{
    BM_Compare_MPMC_Template<StdQueue<std::shared_ptr<BenchData>>>(state, "StdQueue");
}

BENCHMARK(BM_Compare_MPMC_CQueue)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Compare_MPMC_StdQueue)->Unit(benchmark::kMicrosecond);

// =============================================================================
// MPSC Comparison - Multiple Producers, Single Consumer
// =============================================================================

template<typename QueueType>
static void BM_Compare_MPSC_Template(benchmark::State& state, int numProducers)
{
    const int itemsPerProducer = 1000;
    const int totalItems = numProducers * itemsPerProducer;

    QueueType queue(1 << 17);

    for (auto _ : state)
    {
        std::atomic<int> startFlag {0};
        std::atomic<int> itemsEnqueued {0};

        // Producer threads
        std::vector<std::thread> producers;
        producers.reserve(numProducers);

        for (int p = 0; p < numProducers; ++p)
        {
            producers.emplace_back(
                [&, p]()
                {
                    // Wait for all threads to be ready
                    startFlag.fetch_add(1, std::memory_order_release);
                    while (startFlag.load(std::memory_order_acquire) < numProducers + 1)
                    {
                        std::this_thread::yield();
                    }

                    // Push items
                    for (int i = 0; i < itemsPerProducer; ++i)
                    {
                        while (!queue.push(std::make_shared<BenchData>(p * 10000 + i)))
                        {
                            std::this_thread::yield();
                        }
                    }
                    itemsEnqueued.fetch_add(itemsPerProducer, std::memory_order_release);
                });
        }

        // Consumer thread (this thread)
        startFlag.fetch_add(1, std::memory_order_release); // Signal producers to start

        std::shared_ptr<BenchData> value;
        int consumed = 0;

        while (consumed < totalItems)
        {
            if (queue.tryPop(value))
            {
                benchmark::DoNotOptimize(value);
                consumed++;
            }
        }

        // Wait for producers
        for (auto& t : producers)
        {
            t.join();
        }
    }

    state.SetItemsProcessed(state.iterations() * totalItems);
}

static void BM_Compare_MPSC_CQueue(benchmark::State& state)
{
    BM_Compare_MPSC_Template<CQueue<std::shared_ptr<BenchData>>>(state, state.range(0));
}

static void BM_Compare_MPSC_StdQueue(benchmark::State& state)
{
    BM_Compare_MPSC_Template<StdQueue<std::shared_ptr<BenchData>>>(state, state.range(0));
}

BENCHMARK(BM_Compare_MPSC_CQueue)->Arg(2)->Arg(4)->Arg(8)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Compare_MPSC_StdQueue)->Arg(2)->Arg(4)->Arg(8)->Unit(benchmark::kMicrosecond);

// =============================================================================
// SPMC Comparison - Single Producer, Multiple Consumers
// =============================================================================

template<typename QueueType>
static void BM_Compare_SPMC_Template(benchmark::State& state, int numConsumers)
{
    const int totalItems = 10000;

    QueueType queue(1 << 17);

    for (auto _ : state)
    {
        std::atomic<int> startFlag {0};
        std::atomic<int> itemsConsumed {0};

        // Consumer threads
        std::vector<std::thread> consumers;
        consumers.reserve(numConsumers);

        for (int c = 0; c < numConsumers; ++c)
        {
            consumers.emplace_back(
                [&]()
                {
                    // Wait for all threads to be ready
                    startFlag.fetch_add(1, std::memory_order_release);
                    while (startFlag.load(std::memory_order_acquire) < numConsumers + 1)
                    {
                        std::this_thread::yield();
                    }

                    // Pop items
                    std::shared_ptr<BenchData> value;
                    while (itemsConsumed.load(std::memory_order_acquire) < totalItems)
                    {
                        if (queue.tryPop(value))
                        {
                            benchmark::DoNotOptimize(value);
                            itemsConsumed.fetch_add(1, std::memory_order_release);
                        }
                    }
                });
        }

        // Producer thread (this thread)
        startFlag.fetch_add(1, std::memory_order_release); // Signal consumers to start

        for (int i = 0; i < totalItems; ++i)
        {
            while (!queue.push(std::make_shared<BenchData>(i)))
            {
                std::this_thread::yield();
            }
        }

        // Wait for consumers
        for (auto& t : consumers)
        {
            t.join();
        }
    }

    state.SetItemsProcessed(state.iterations() * totalItems);
}

static void BM_Compare_SPMC_CQueue(benchmark::State& state)
{
    BM_Compare_SPMC_Template<CQueue<std::shared_ptr<BenchData>>>(state, state.range(0));
}

static void BM_Compare_SPMC_StdQueue(benchmark::State& state)
{
    BM_Compare_SPMC_Template<StdQueue<std::shared_ptr<BenchData>>>(state, state.range(0));
}

BENCHMARK(BM_Compare_SPMC_CQueue)->Arg(2)->Arg(4)->Arg(8)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Compare_SPMC_StdQueue)->Arg(2)->Arg(4)->Arg(8)->Unit(benchmark::kMicrosecond);

// =============================================================================
// Bulk Operations Comparison
// =============================================================================

static void BM_Compare_Bulk_CQueue(benchmark::State& state)
{
    const int bulkSize = state.range(0);
    const int totalItems = 10000;
    CQueue<std::shared_ptr<BenchData>> queue(1 << 17);

    for (auto _ : state)
    {
        // Fill queue
        for (int i = 0; i < totalItems; ++i)
        {
            queue.push(std::make_shared<BenchData>(i));
        }

        // Bulk pop
        std::vector<std::shared_ptr<BenchData>> buffer(bulkSize);
        int consumed = 0;

        while (consumed < totalItems)
        {
            size_t popped = queue.tryPopBulk(buffer.data(), bulkSize);
            consumed += popped;
            benchmark::DoNotOptimize(buffer);
        }
    }

    state.SetItemsProcessed(state.iterations() * totalItems);
}

static void BM_Compare_Bulk_StdQueue(benchmark::State& state)
{
    const int bulkSize = state.range(0);
    const int totalItems = 10000;
    StdQueue<std::shared_ptr<BenchData>> queue(1 << 17);

    for (auto _ : state)
    {
        // Fill queue
        for (int i = 0; i < totalItems; ++i)
        {
            queue.push(std::make_shared<BenchData>(i));
        }

        // Bulk pop
        std::vector<std::shared_ptr<BenchData>> buffer(bulkSize);
        int consumed = 0;

        while (consumed < totalItems)
        {
            size_t popped = queue.tryPopBulk(buffer.data(), bulkSize);
            consumed += popped;
            benchmark::DoNotOptimize(buffer);
        }
    }

    state.SetItemsProcessed(state.iterations() * totalItems);
}

BENCHMARK(BM_Compare_Bulk_CQueue)->Arg(1)->Arg(10)->Arg(100)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Compare_Bulk_StdQueue)->Arg(1)->Arg(10)->Arg(100)->Unit(benchmark::kMicrosecond);

// =============================================================================
// Rate Limiting Comparison
// =============================================================================

static void BM_Compare_RateLimit_CQueue(benchmark::State& state)
{
    const int ratePerSecond = state.range(0);
    const int totalItems = 100;

    // Create queue with rate limiting
    CQueue<std::shared_ptr<BenchData>> queue(MIN_QUEUE_CAPACITY, ratePerSecond, ratePerSecond);

    for (auto _ : state)
    {
        // Fill queue
        for (int i = 0; i < totalItems; ++i)
        {
            queue.push(std::make_shared<BenchData>(i));
        }

        // Pop with rate limiting
        std::shared_ptr<BenchData> value;
        for (int i = 0; i < totalItems; ++i)
        {
            while (!queue.tryPop(value))
            {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
            benchmark::DoNotOptimize(value);
        }
    }

    state.SetItemsProcessed(state.iterations() * totalItems);
}

static void BM_Compare_RateLimit_StdQueue(benchmark::State& state)
{
    const int ratePerSecond = state.range(0);
    const int totalItems = 100;

    // Create queue with rate limiting
    StdQueue<std::shared_ptr<BenchData>> queue(MIN_QUEUE_CAPACITY, ratePerSecond, ratePerSecond);

    for (auto _ : state)
    {
        // Fill queue
        for (int i = 0; i < totalItems; ++i)
        {
            queue.push(std::make_shared<BenchData>(i));
        }

        // Pop with rate limiting
        std::shared_ptr<BenchData> value;
        for (int i = 0; i < totalItems; ++i)
        {
            while (!queue.tryPop(value))
            {
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
            benchmark::DoNotOptimize(value);
        }
    }

    state.SetItemsProcessed(state.iterations() * totalItems);
}

BENCHMARK(BM_Compare_RateLimit_CQueue)->Arg(1000)->Arg(10000)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Compare_RateLimit_StdQueue)->Arg(1000)->Arg(10000)->Unit(benchmark::kMicrosecond);

// =============================================================================
// High Contention Comparison
// =============================================================================

template<typename QueueType>
static void BM_Compare_HighContention_Template(benchmark::State& state, int numThreads)
{
    const int opsPerThread = 5000;
    QueueType queue(1 << 20);

    for (auto _ : state)
    {
        std::atomic<int> ready {0};
        std::vector<std::thread> threads;
        threads.reserve(numThreads);

        for (int t = 0; t < numThreads; ++t)
        {
            threads.emplace_back(
                [&, t]()
                {
                    ready.fetch_add(1, std::memory_order_release);
                    while (ready.load(std::memory_order_acquire) < numThreads)
                    {
                        std::this_thread::yield();
                    }

                    std::shared_ptr<BenchData> value;
                    for (int i = 0; i < opsPerThread; ++i)
                    {
                        if (i % 2 == 0)
                        {
                            queue.push(std::make_shared<BenchData>(t * 10000 + i));
                        }
                        else
                        {
                            queue.tryPop(value);
                            benchmark::DoNotOptimize(value);
                        }
                    }
                });
        }

        for (auto& t : threads)
        {
            t.join();
        }
    }

    state.SetItemsProcessed(state.iterations() * numThreads * opsPerThread);
}

static void BM_Compare_HighContention_CQueue(benchmark::State& state)
{
    BM_Compare_HighContention_Template<CQueue<std::shared_ptr<BenchData>>>(state, state.range(0));
}

static void BM_Compare_HighContention_StdQueue(benchmark::State& state)
{
    BM_Compare_HighContention_Template<StdQueue<std::shared_ptr<BenchData>>>(state, state.range(0));
}

BENCHMARK(BM_Compare_HighContention_CQueue)->Arg(4)->Arg(8)->Arg(16)->Unit(benchmark::kMicrosecond);
BENCHMARK(BM_Compare_HighContention_StdQueue)->Arg(4)->Arg(8)->Arg(16)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();
