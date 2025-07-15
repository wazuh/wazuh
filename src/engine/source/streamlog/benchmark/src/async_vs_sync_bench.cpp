#include <benchmark/benchmark.h>
#include <streamlog/logger.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

// Generate a 1KB string without line breaks
static std::string generateEvent()
{
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string event;
    event.reserve(1024);
    for (int i = 0; i < 1024; ++i)
    {
        event += chars[i % chars.size()];
    }
    return event;
}

// Thread-safe queue for asynchronous writing
class EventQueue
{
private:
    std::queue<std::string> m_queue;
    std::mutex m_mutex;
    std::condition_variable m_cv;
    std::atomic<bool> m_finished {false};

public:
    void push(const std::string& event)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_queue.push(event);
        m_cv.notify_one();
    }

    bool pop(std::string& event)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_cv.wait(lock, [this] { return !m_queue.empty() || m_finished.load(); });

        if (m_queue.empty())
        {
            return false;
        }

        event = std::move(m_queue.front());
        m_queue.pop();
        return true;
    }

    void finish()
    {
        m_finished.store(true);
        m_cv.notify_all();
    }

    bool isFinished() const { return m_finished.load(); }
};

// Benchmark: Multiple threads writing synchronously to the same file (with flush)
static void BM_SyncMultiThreadWithFlush(benchmark::State& state)
{
    const int numThreads = state.range(0);
    const int eventsPerThread = state.range(1);
    const std::string filename = "/tmp/sync_bench_flush.log";

    for (auto _ : state)
    {
        // Remove file if exists
        fs::remove(filename);

        std::mutex fileMutex;
        std::vector<std::thread> threads;
        const std::string event = generateEvent();

        std::atomic<bool> ready {false};
        std::atomic<int> ready_count {0};

        // Create threads but don't start timing yet
        for (int i = 0; i < numThreads; ++i)
        {
            threads.emplace_back(
                [&]()
                {
                    // Signal thread is ready
                    ready_count.fetch_add(1);

                    // Wait for all threads to be ready
                    while (!ready.load())
                    {
                        std::this_thread::yield();
                    }

                    for (int j = 0; j < eventsPerThread; ++j)
                    {
                        std::lock_guard<std::mutex> lock(fileMutex);
                        std::ofstream file(filename, std::ios::app);
                        file << event << '\n';
                        file.flush();
                    }
                });
        }

        // Wait for all threads to be ready
        while (ready_count.load() < numThreads)
        {
            std::this_thread::yield();
        }

        // Start timing after all threads are created and ready
        auto start = std::chrono::high_resolution_clock::now();

        // Signal all threads to start working
        ready.store(true);

        // Wait for all threads to complete
        for (auto& t : threads)
        {
            t.join();
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        state.SetIterationTime(duration.count() / 1000000.0);
    }

    state.SetItemsProcessed(state.iterations() * numThreads * eventsPerThread);
    fs::remove(filename);
}

// Benchmark: Multiple threads writing synchronously to the same file (without flush)
static void BM_SyncMultiThreadWithoutFlush(benchmark::State& state)
{
    const int numThreads = state.range(0);
    const int eventsPerThread = state.range(1);
    const std::string filename = "/tmp/sync_bench_no_flush.log";

    for (auto _ : state)
    {
        // Remove file if exists
        fs::remove(filename);

        std::mutex fileMutex;
        std::vector<std::thread> threads;
        const std::string event = generateEvent();

        std::atomic<bool> ready {false};
        std::atomic<int> ready_count {0};

        // Create threads but don't start timing yet
        for (int i = 0; i < numThreads; ++i)
        {
            threads.emplace_back(
                [&]()
                {
                    // Signal thread is ready
                    ready_count.fetch_add(1);

                    // Wait for all threads to be ready
                    while (!ready.load())
                    {
                        std::this_thread::yield();
                    }

                    for (int j = 0; j < eventsPerThread; ++j)
                    {
                        std::lock_guard<std::mutex> lock(fileMutex);
                        std::ofstream file(filename, std::ios::app);
                        file << event << '\n';
                        // No flush here
                    }
                });
        }

        // Wait for all threads to be ready
        while (ready_count.load() < numThreads)
        {
            std::this_thread::yield();
        }

        // Start timing after all threads are created and ready
        auto start = std::chrono::high_resolution_clock::now();

        // Signal all threads to start working
        ready.store(true);

        // Wait for all threads to complete
        for (auto& t : threads)
        {
            t.join();
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        state.SetIterationTime(duration.count() / 1000000.0);
    }

    state.SetItemsProcessed(state.iterations() * numThreads * eventsPerThread);
    fs::remove(filename);
}

// Benchmark: Asynchronous writing with dedicated writer thread (with flush)
static void BM_AsyncDedicatedWriterWithFlush(benchmark::State& state)
{
    const int numProducers = state.range(0);
    const int eventsPerProducer = state.range(1);
    const std::string filename = "/tmp/async_bench_flush.log";

    for (auto _ : state)
    {
        // Remove file if exists
        fs::remove(filename);

        EventQueue eventQueue;
        std::vector<std::thread> producers;
        const std::string event = generateEvent();

        std::atomic<bool> ready {false};
        std::atomic<int> ready_count {0};

        // Create writer thread but don't start timing yet
        std::thread writer(
            [&]()
            {
                // Signal writer thread is ready
                ready_count.fetch_add(1);

                // Wait for all threads to be ready
                while (!ready.load())
                {
                    std::this_thread::yield();
                }

                std::ofstream file(filename);
                std::string eventToWrite;
                while (eventQueue.pop(eventToWrite))
                {
                    file << eventToWrite << '\n';
                    file.flush();
                }
            });

        // Create producer threads but don't start timing yet
        for (int i = 0; i < numProducers; ++i)
        {
            producers.emplace_back(
                [&]()
                {
                    // Signal producer thread is ready
                    ready_count.fetch_add(1);

                    // Wait for all threads to be ready
                    while (!ready.load())
                    {
                        std::this_thread::yield();
                    }

                    for (int j = 0; j < eventsPerProducer; ++j)
                    {
                        eventQueue.push(event);
                    }
                });
        }

        // Wait for all threads to be ready (producers + 1 writer)
        while (ready_count.load() < (numProducers + 1))
        {
            std::this_thread::yield();
        }

        // Start timing after all threads are created and ready
        auto start = std::chrono::high_resolution_clock::now();

        // Signal all threads to start working
        ready.store(true);

        // Wait for all producers to finish
        for (auto& p : producers)
        {
            p.join();
        }

        // Signal writer to finish and wait
        eventQueue.finish();
        writer.join();

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        state.SetIterationTime(duration.count() / 1000000.0);
    }

    state.SetItemsProcessed(state.iterations() * numProducers * eventsPerProducer);
    fs::remove(filename);
}

// Benchmark: Asynchronous writing with dedicated writer thread (without flush)
static void BM_AsyncDedicatedWriterWithoutFlush(benchmark::State& state)
{
    const int numProducers = state.range(0);
    const int eventsPerProducer = state.range(1);
    const std::string filename = "/tmp/async_bench_no_flush.log";

    for (auto _ : state)
    {
        // Remove file if exists
        fs::remove(filename);

        EventQueue eventQueue;
        std::vector<std::thread> producers;
        const std::string event = generateEvent();

        std::atomic<bool> ready {false};
        std::atomic<int> ready_count {0};

        // Create writer thread but don't start timing yet
        std::thread writer(
            [&]()
            {
                // Signal writer thread is ready
                ready_count.fetch_add(1);

                // Wait for all threads to be ready
                while (!ready.load())
                {
                    std::this_thread::yield();
                }

                std::ofstream file(filename);
                std::string eventToWrite;
                while (eventQueue.pop(eventToWrite))
                {
                    file << eventToWrite << '\n';
                    // No flush here
                }
            });

        // Create producer threads but don't start timing yet
        for (int i = 0; i < numProducers; ++i)
        {
            producers.emplace_back(
                [&]()
                {
                    // Signal producer thread is ready
                    ready_count.fetch_add(1);

                    // Wait for all threads to be ready
                    while (!ready.load())
                    {
                        std::this_thread::yield();
                    }

                    for (int j = 0; j < eventsPerProducer; ++j)
                    {
                        eventQueue.push(event);
                    }
                });
        }

        // Wait for all threads to be ready (producers + 1 writer)
        while (ready_count.load() < (numProducers + 1))
        {
            std::this_thread::yield();
        }

        // Start timing after all threads are created and ready
        auto start = std::chrono::high_resolution_clock::now();

        // Signal all threads to start working
        ready.store(true);

        // Wait for all producers to finish
        for (auto& p : producers)
        {
            p.join();
        }

        // Signal writer to finish and wait
        eventQueue.finish();
        writer.join();

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        state.SetIterationTime(duration.count() / 1000000.0);
    }

    state.SetItemsProcessed(state.iterations() * numProducers * eventsPerProducer);
    fs::remove(filename);
}

// Register benchmarks with different thread counts and events per thread
BENCHMARK(BM_SyncMultiThreadWithFlush)
    ->Args({1, 100000})
    ->Args({2, 50000})
    ->Args({4, 25000})
    ->Args({8, 12500})
    ->Args({16, 6250})
    ->Args({32, 3125})
    ->UseManualTime();
BENCHMARK(BM_SyncMultiThreadWithoutFlush)
    ->Args({1, 100000})
    ->Args({2, 50000})
    ->Args({4, 25000})
    ->Args({8, 12500})
    ->Args({16, 6250})
    ->Args({32, 3125})
    ->UseManualTime();
BENCHMARK(BM_AsyncDedicatedWriterWithFlush)
    ->Args({1, 100000})
    ->Args({2, 50000})
    ->Args({4, 25000})
    ->Args({8, 12500})
    ->Args({16, 6250})
    ->Args({32, 3125})
    ->UseManualTime();
BENCHMARK(BM_AsyncDedicatedWriterWithoutFlush)
    ->Args({1, 100000})
    ->Args({2, 50000})
    ->Args({4, 25000})
    ->Args({8, 12500})
    ->Args({16, 6250})
    ->Args({32, 3125})
    ->UseManualTime();

BENCHMARK_MAIN();
