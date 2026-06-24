#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <new>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <fastqueue/cqueue.hpp>

using namespace fastqueue;

// =============================================================================
// Memory Tracking via global operator new/delete override
// =============================================================================

namespace memtrack
{
static constexpr size_t HEADER_SIZE = 16; // Aligned header to store allocation size

static std::atomic<size_t> g_totalAllocs {0};
static std::atomic<size_t> g_totalDeallocs {0};
static std::atomic<size_t> g_totalBytesAllocated {0};
static std::atomic<size_t> g_totalBytesFreed {0};
static std::atomic<size_t> g_currentLiveBytes {0};
static std::atomic<size_t> g_peakLiveBytes {0};

static std::atomic<bool> g_trackingEnabled {false};

void reset()
{
    g_totalAllocs.store(0, std::memory_order_relaxed);
    g_totalDeallocs.store(0, std::memory_order_relaxed);
    g_totalBytesAllocated.store(0, std::memory_order_relaxed);
    g_totalBytesFreed.store(0, std::memory_order_relaxed);
    g_currentLiveBytes.store(0, std::memory_order_relaxed);
    g_peakLiveBytes.store(0, std::memory_order_relaxed);
}

void enable() { g_trackingEnabled.store(true, std::memory_order_release); }
void disable() { g_trackingEnabled.store(false, std::memory_order_release); }

void updatePeak()
{
    size_t current = g_currentLiveBytes.load(std::memory_order_relaxed);
    size_t peak = g_peakLiveBytes.load(std::memory_order_relaxed);
    while (current > peak)
    {
        if (g_peakLiveBytes.compare_exchange_weak(peak, current, std::memory_order_relaxed))
            break;
    }
}

struct Snapshot
{
    size_t totalAllocs;
    size_t totalDeallocs;
    size_t totalBytesAllocated;
    size_t totalBytesFreed;
    size_t currentLiveBytes;
    size_t peakLiveBytes;
    size_t rssKB;
    size_t vmPeakKB;

    static Snapshot capture();
};

static size_t readProcFieldKB(const char* field)
{
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line))
    {
        if (line.find(field) == 0)
        {
            std::istringstream iss(line);
            std::string label;
            size_t value;
            iss >> label >> value;
            return value; // Already in kB
        }
    }
    return 0;
}

Snapshot Snapshot::capture()
{
    Snapshot s;
    s.totalAllocs = g_totalAllocs.load(std::memory_order_relaxed);
    s.totalDeallocs = g_totalDeallocs.load(std::memory_order_relaxed);
    s.totalBytesAllocated = g_totalBytesAllocated.load(std::memory_order_relaxed);
    s.totalBytesFreed = g_totalBytesFreed.load(std::memory_order_relaxed);
    s.currentLiveBytes = g_currentLiveBytes.load(std::memory_order_relaxed);
    s.peakLiveBytes = g_peakLiveBytes.load(std::memory_order_relaxed);
    s.rssKB = readProcFieldKB("VmRSS:");
    s.vmPeakKB = readProcFieldKB("VmPeak:");
    return s;
}

} // namespace memtrack

// Global operator new/delete overrides
void* operator new(std::size_t size)
{
    void* ptr = std::malloc(size + memtrack::HEADER_SIZE);
    if (!ptr)
        throw std::bad_alloc();

    // Store the size in the header
    *reinterpret_cast<std::size_t*>(ptr) = size;

    if (memtrack::g_trackingEnabled.load(std::memory_order_acquire))
    {
        memtrack::g_totalAllocs.fetch_add(1, std::memory_order_relaxed);
        memtrack::g_totalBytesAllocated.fetch_add(size, std::memory_order_relaxed);
        memtrack::g_currentLiveBytes.fetch_add(size, std::memory_order_relaxed);
        memtrack::updatePeak();
    }

    return static_cast<char*>(ptr) + memtrack::HEADER_SIZE;
}

void operator delete(void* ptr) noexcept
{
    if (!ptr)
        return;

    void* realPtr = static_cast<char*>(ptr) - memtrack::HEADER_SIZE;
    std::size_t size = *reinterpret_cast<std::size_t*>(realPtr);

    if (memtrack::g_trackingEnabled.load(std::memory_order_acquire))
    {
        memtrack::g_totalDeallocs.fetch_add(1, std::memory_order_relaxed);
        memtrack::g_totalBytesFreed.fetch_add(size, std::memory_order_relaxed);
        memtrack::g_currentLiveBytes.fetch_sub(size, std::memory_order_relaxed);
    }

    std::free(realPtr);
}

void operator delete(void* ptr, std::size_t) noexcept
{
    ::operator delete(ptr);
}

// =============================================================================
// Report formatting
// =============================================================================

static void printReport(const std::string& scenario,
                        int numProducers,
                        int numConsumers,
                        int numEvents,
                        int eventSizeBytes,
                        const memtrack::Snapshot& before,
                        const memtrack::Snapshot& after)
{
    const size_t deltaAllocs = after.totalAllocs - before.totalAllocs;
    const size_t deltaBytes = after.totalBytesAllocated - before.totalBytesAllocated;
    const size_t deltaRssKB = (after.rssKB > before.rssKB) ? (after.rssKB - before.rssKB) : 0;
    const double avgBytesPerEvent = (numEvents > 0) ? static_cast<double>(deltaBytes) / numEvents : 0.0;
    const double allocsPerEvent = (numEvents > 0) ? static_cast<double>(deltaAllocs) / numEvents : 0.0;
    const double overheadPerEvent = avgBytesPerEvent - eventSizeBytes;

    std::cout << "\n";
    std::cout << "=== " << scenario << " ===\n";
    std::cout << "    Config:             " << numProducers << "P / " << numConsumers << "C, " << numEvents
              << " events x " << eventSizeBytes << " bytes\n";
    std::cout << "    RSS delta:          " << std::fixed << std::setprecision(2)
              << static_cast<double>(deltaRssKB) / 1024.0 << " MB\n";
    std::cout << "    Peak live memory:   " << std::fixed << std::setprecision(2)
              << static_cast<double>(after.peakLiveBytes) / (1024.0 * 1024.0) << " MB\n";
    std::cout << "    Total allocations:  " << deltaAllocs << "\n";
    std::cout << "    Total bytes alloc:  " << std::fixed << std::setprecision(2)
              << static_cast<double>(deltaBytes) / (1024.0 * 1024.0) << " MB\n";
    std::cout << "    Avg bytes/event:    " << std::fixed << std::setprecision(1) << avgBytesPerEvent << " bytes\n";
    std::cout << "    Overhead/event:     " << std::fixed << std::setprecision(1) << overheadPerEvent
              << " bytes (vs " << eventSizeBytes << " payload)\n";
    std::cout << "    Allocs/event:       " << std::fixed << std::setprecision(2) << allocsPerEvent << "\n";
    std::cout << "    Live bytes at end:  " << after.currentLiveBytes << " bytes\n";
}

// =============================================================================
// MPMC Memory Profiling Scenario
// =============================================================================

static void runScenario(int numProducers, int numConsumers, int numEvents, int eventSizeBytes)
{
    const int queueCapacity = MIN_QUEUE_CAPACITY; // 8192
    const int eventsPerProducer = numEvents / numProducers;
    const int totalEvents = eventsPerProducer * numProducers; // Adjusted for even distribution

    // Create the payload template
    const std::string payload(eventSizeBytes, 'X');

    // Create queue BEFORE enabling tracking (we measure push/pop overhead, not queue construction)
    CQueue<std::string> queue(queueCapacity);

    // Reset and enable tracking
    memtrack::reset();
    memtrack::enable();

    auto before = memtrack::Snapshot::capture();

    // Synchronization
    std::atomic<int> readyCount {0};
    const int totalThreads = numProducers + numConsumers;
    std::atomic<int> itemsConsumed {0};

    std::vector<std::thread> threads;
    threads.reserve(totalThreads);

    // Producer threads
    for (int p = 0; p < numProducers; ++p)
    {
        threads.emplace_back(
            [&, p]()
            {
                readyCount.fetch_add(1, std::memory_order_release);
                while (readyCount.load(std::memory_order_acquire) < totalThreads)
                {
                    std::this_thread::yield();
                }

                for (int i = 0; i < eventsPerProducer; ++i)
                {
                    std::string event = payload; // Copy the payload
                    while (!queue.push(std::move(event)))
                    {
                        std::this_thread::yield();
                    }
                }
            });
    }

    // Consumer threads (throttled to keep queue saturated)
    // Each consumer simulates processing time so producers outpace consumers
    for (int c = 0; c < numConsumers; ++c)
    {
        threads.emplace_back(
            [&]()
            {
                readyCount.fetch_add(1, std::memory_order_release);
                while (readyCount.load(std::memory_order_acquire) < totalThreads)
                {
                    std::this_thread::yield();
                }

                std::string value;
                while (itemsConsumed.load(std::memory_order_acquire) < totalEvents)
                {
                    if (queue.tryPop(value))
                    {
                        itemsConsumed.fetch_add(1, std::memory_order_release);
                        // Simulate processing delay: ~50µs per event
                        // This ensures producers flood the queue faster than consumers drain it
                        std::this_thread::sleep_for(std::chrono::microseconds(50));
                    }
                    else
                    {
                        std::this_thread::yield();
                    }
                }
            });
    }

    // Wait for all threads to complete
    for (auto& t : threads)
    {
        t.join();
    }

    auto after = memtrack::Snapshot::capture();
    memtrack::disable();

    // Build scenario name
    std::ostringstream name;
    name << "MPMC " << numProducers << "P/" << numConsumers << "C";

    printReport(name.str(), numProducers, numConsumers, totalEvents, eventSizeBytes, before, after);
}

// =============================================================================
// Queue construction memory cost measurement
// =============================================================================

static void measureQueueConstruction()
{
    memtrack::reset();
    memtrack::enable();

    auto before = memtrack::Snapshot::capture();

    { CQueue<std::string> queue(MIN_QUEUE_CAPACITY); }

    auto after = memtrack::Snapshot::capture();
    memtrack::disable();

    const size_t deltaAllocs = after.totalAllocs - before.totalAllocs;
    const size_t deltaBytes = after.totalBytesAllocated - before.totalBytesAllocated;

    std::cout << "\n";
    std::cout << "=== Queue Construction Cost (capacity=" << MIN_QUEUE_CAPACITY << ") ===\n";
    std::cout << "    Allocations:        " << deltaAllocs << "\n";
    std::cout << "    Bytes allocated:    " << deltaBytes << " bytes (" << std::fixed << std::setprecision(2)
              << static_cast<double>(deltaBytes) / 1024.0 << " KB)\n";
    std::cout << "    Live at end:        " << after.currentLiveBytes << " bytes (freed by destructor)\n";
}

// =============================================================================
// Main
// =============================================================================

int main()
{
    std::cout << "FastQueue CQueue Memory Profiling\n";
    std::cout << "==================================\n";
    const int numEvents = 131072; // 128K events
    const int eventSize = 4096;   // 4KB payload per event
    const int numProducers = 8;
    const int numConsumers = 4;

    std::cout << "Queue type:     CQueue<std::string> (lock-free, moodycamel)\n";
    std::cout << "Queue capacity: " << MIN_QUEUE_CAPACITY << " (MIN_QUEUE_CAPACITY)\n";
    std::cout << "Block size:     512 (WQueueTraits)\n";
    std::cout << "Event payload:  " << eventSize << " bytes (std::string)\n";
    std::cout << "Events/test:    " << numEvents << " (128K)\n";
    std::cout << "Producers:      " << numProducers << "\n";
    std::cout << "Consumers:      " << numConsumers << "\n";
    std::cout << std::endl;

    // Measure queue construction cost first
    measureQueueConstruction();

    // Run the scenario: 8P/4C, 128K events of 4KB
    runScenario(numProducers, numConsumers, numEvents, eventSize);

    std::cout << "\n==================================\n";
    std::cout << "Profiling complete.\n";
    std::cout << "\nTip: For detailed heap timeline, run under:\n";
    std::cout << "  valgrind --tool=massif ./fastqueue_memory_profile\n";
    std::cout << "  ms_print massif.out.<pid>\n";
    std::cout << std::endl;

    return 0;
}
