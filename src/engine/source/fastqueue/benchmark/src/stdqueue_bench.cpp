#include <benchmark/benchmark.h>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

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
// Single Producer, Single Consumer - Different Queue Sizes
// =============================================================================

template<size_t QueueSize>
static void BM_StdQueue_SPSC_PushPop(benchmark::State& state)
{
    StdQueue<std::shared_ptr<BenchData>> sq(QueueSize);

    for (auto _ : state)
    {
        // Push phase
        for (size_t i = 0; i < state.range(0); ++i)
        {
            sq.push(std::make_shared<BenchData>(i));
        }

        // Pop phase
        std::shared_ptr<BenchData> value;
        for (size_t i = 0; i < state.range(0); ++i)
        {
            sq.waitPop(value, WAIT_DEQUEUE_TIMEOUT_USEC);
            benchmark::DoNotOptimize(value);
        }
    }

    state.SetItemsProcessed(state.iterations() * state.range(0) * 2); // push + pop
}

// Note: Minimum queue capacity is MIN_QUEUE_CAPACITY (8192)
BENCHMARK_TEMPLATE(BM_StdQueue_SPSC_PushPop, 1 << 17)->Arg(1000)->Arg(10000)->Arg(50000)->Unit(benchmark::kMicrosecond);
BENCHMARK_TEMPLATE(BM_StdQueue_SPSC_PushPop, 1 << 20)
    ->Arg(10000)
    ->Arg(100000)
    ->Arg(500000)
    ->Unit(benchmark::kMicrosecond);

// =============================================================================
// Multiple Producers, Single Consumer
// =============================================================================

static void BM_StdQueue_MPSC_PushPop(benchmark::State& state)
{
    const int numProducers = state.range(0);
    const int queueSize = state.range(1);
    const int itemsPerProducer = 1000;

    StdQueue<std::shared_ptr<BenchData>> sq(queueSize);

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
                        while (!sq.push(std::make_shared<BenchData>(p * 10000 + i)))
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
        const int totalItems = numProducers * itemsPerProducer;

        while (consumed < totalItems)
        {
            if (sq.tryPop(value))
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

    state.SetItemsProcessed(state.iterations() * numProducers * itemsPerProducer);
}

BENCHMARK(BM_StdQueue_MPSC_PushPop)
    ->Args({2, 1 << 17})
    ->Args({4, 1 << 17})
    ->Args({8, 1 << 17})
    ->Args({2, 1 << 20})
    ->Args({4, 1 << 20})
    ->Args({8, 1 << 20})
    ->Unit(benchmark::kMicrosecond);

// =============================================================================
// Single Producer, Multiple Consumers
// =============================================================================

static void BM_StdQueue_SPMC_PushPop(benchmark::State& state)
{
    const int numConsumers = state.range(0);
    const int queueSize = state.range(1);
    const int totalItems = 10000;

    StdQueue<std::shared_ptr<BenchData>> sq(queueSize);

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
                        if (sq.tryPop(value))
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
            while (!sq.push(std::make_shared<BenchData>(i)))
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

BENCHMARK(BM_StdQueue_SPMC_PushPop)
    ->Args({2, 1 << 17})
    ->Args({4, 1 << 17})
    ->Args({8, 1 << 17})
    ->Args({2, 1 << 20})
    ->Args({4, 1 << 20})
    ->Args({8, 1 << 20})
    ->Unit(benchmark::kMicrosecond);

// =============================================================================
// Multiple Producers, Multiple Consumers
// =============================================================================

static void BM_StdQueue_MPMC_PushPop(benchmark::State& state)
{
    const int numProducers = state.range(0);
    const int numConsumers = state.range(1);
    const int queueSize = state.range(2);
    const int itemsPerProducer = 1000;
    const int totalItems = numProducers * itemsPerProducer;

    StdQueue<std::shared_ptr<BenchData>> sq(queueSize);

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
                        while (!sq.push(std::make_shared<BenchData>(p * 10000 + i)))
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
                        if (sq.tryPop(value))
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

        // Wait for all threads
        for (auto& t : threads)
        {
            t.join();
        }
    }

    state.SetItemsProcessed(state.iterations() * totalItems);
}

BENCHMARK(BM_StdQueue_MPMC_PushPop)
    ->Args({2, 2, 1 << 17})
    ->Args({4, 4, 1 << 17})
    ->Args({8, 8, 1 << 17})
    ->Args({2, 4, 1 << 20})
    ->Args({4, 8, 1 << 20})
    ->Args({8, 16, 1 << 20})
    ->Unit(benchmark::kMicrosecond);

// =============================================================================
// Bulk Operations
// =============================================================================

static void BM_StdQueue_BulkPop(benchmark::State& state)
{
    const int queueSize = state.range(0);
    const int bulkSize = state.range(1);
    const int totalItems = 10000;

    StdQueue<std::shared_ptr<BenchData>> sq(queueSize);

    for (auto _ : state)
    {
        // Fill queue
        for (int i = 0; i < totalItems; ++i)
        {
            sq.push(std::make_shared<BenchData>(i));
        }

        // Bulk pop
        std::vector<std::shared_ptr<BenchData>> buffer(bulkSize);
        int consumed = 0;

        while (consumed < totalItems)
        {
            size_t popped = sq.tryPopBulk(buffer.data(), bulkSize);
            consumed += popped;
            benchmark::DoNotOptimize(buffer);
        }
    }

    state.SetItemsProcessed(state.iterations() * totalItems);
}

BENCHMARK(BM_StdQueue_BulkPop)
    ->Args({1 << 17, 1})
    ->Args({1 << 17, 10})
    ->Args({1 << 17, 100})
    ->Args({1 << 20, 1})
    ->Args({1 << 20, 10})
    ->Args({1 << 20, 100})
    ->Args({1 << 20, 1000})
    ->Unit(benchmark::kMicrosecond);

// =============================================================================
// Contention Test - High throughput scenario
// =============================================================================

static void BM_StdQueue_HighContention(benchmark::State& state)
{
    const int numThreads = state.range(0);
    const int queueSize = 1 << 20; // Large queue
    const int opsPerThread = 10000;

    StdQueue<std::shared_ptr<BenchData>> sq(queueSize);

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

                    // Mix of push and pop operations
                    std::shared_ptr<BenchData> value;
                    for (int i = 0; i < opsPerThread; ++i)
                    {
                        if (i % 2 == 0)
                        {
                            sq.push(std::make_shared<BenchData>(t * 10000 + i));
                        }
                        else
                        {
                            sq.tryPop(value);
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

BENCHMARK(BM_StdQueue_HighContention)->Arg(2)->Arg(4)->Arg(8)->Arg(16)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN();
