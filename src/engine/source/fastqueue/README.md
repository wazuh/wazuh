# FastQueue — Concurrent Queue Library

## Overview

`fastqueue` provides thread-safe, bounded queue implementations for high-throughput inter-thread communication in the Wazuh Engine. It offers two implementations behind a common `IQueue<T>` interface:

- **`CQueue`** — Lock-free queue backed by `moodycamel::BlockingConcurrentQueue` with optimized block/index traits. Best for high-contention scenarios.
- **`StdQueue`** — Mutex-based queue backed by `std::queue` with condition variable. Simpler, with exact (not approximate) size reporting.

Both implementations support optional **token-bucket rate limiting** on dequeue operations, an optional
**byte budget** on enqueue (`setByteLimit()`, backed by `ByteLimiter<T>`), and **bulk pop** for batch
processing.

## Architecture

```
                         IQueue<T>
                        (interface)
                       ┌─────┴─────┐
                       │           │
                  CQueue<T>    StdQueue<T>
                  (lock-free)  (mutex-based)
                       │           │
                       └─────┬─────┘
                             │
               ┌─────────────┴─────────────┐
        ┌──────┴──────┐            ┌───────┴────────┐
        │ RateLimiter │            │ ByteLimiter<T> │
        │ (dequeue,   │            │ (enqueue,      │
        │  optional)  │            │  optional)     │
        └─────────────┘            └────────────────┘

    Producer ──push()/tryPush()──► Queue ──waitPop()/tryPop()──► Consumer
                                    │
                                    ├── tryPopBulk() ──► Batch consumer
                                    │
                                    ├── aproxFreeSlots() ──► Backpressure
                                    │
                                    └── bytesUsed()/maxBytes() ──► Byte usage
```

### Comparison

| Feature | CQueue | StdQueue |
|---------|--------|----------|
| Synchronization | Lock-free (atomics) | Mutex + condition variable |
| Underlying storage | `moodycamel::BlockingConcurrentQueue` | `std::queue` |
| Size reporting | Approximate | Exact |
| Bulk dequeue | Native (`try_dequeue_bulk`) | Loop-based |
| Best for | High contention, MPMC | Low contention, simple use cases |

## Key Concepts

### Bounded Capacity

Both constructors throw `std::runtime_error` for a capacity ≤ 0 or below **8,192 elements**
(`MIN_QUEUE_CAPACITY` in `iqueue.hpp`). `StdQueue` enforces the capacity exactly (`push()` fails at
`m_capacity`); `CQueue` passes it to moodycamel as an initial size, so its bound is approximate and
`aproxFreeSlots()` is `capacity - size_approx()`, floored at 0. `WQueueTraits` is tuned for 2^17–2^20
elements.

### Token-Bucket Rate Limiting

An optional `RateLimiter` can throttle dequeue rate (elements per second). It uses a lock-free token bucket algorithm:

- Tokens refill at a constant rate based on elapsed time
- The bucket starts full (`burstSize` tokens; `burstSize` 0 means `maxElementsPerSecond`)
- `tryAcquire(n)` — non-blocking, returns `false` if insufficient tokens
- `waitAcquire(n, timeout)` — sleeps when the refill wait exceeds 1 ms, otherwise yields, until tokens are available or the timeout expires; a timeout ≤ 0 is a single `tryAcquire()`
- Applied transparently on `waitPop()`, `tryPop()`, and `tryPopBulk()`. Tokens are taken **before** the
  dequeue and are not returned when the queue turns out to be empty; `tryPopBulk(elements, max)` takes
  `max` tokens up front and returns 0 when fewer are available

Constructed via `CQueue(capacity, maxElementsPerSecond, burstSize = 0.0)` (same for `StdQueue`). A
`maxElementsPerSecond` of 0 creates no limiter; a negative one, or an effective burst below 1, throws
`std::runtime_error`. In the engine, `main.cpp` builds the router's event queue as
`CQueue<router::IngestEvent>(analysisd.event_queue_size, analysisd.event_queue_eps)` (operator
settings: [Event queue](../../../../docs/ref/modules/engine/configuration.md#event-queue)).

### Byte Budget (`ByteLimiter<T>`)

`setByteLimit(maxBytes, sizeOf)` configures a lock-free byte budget after construction (it also resets
the byte count to 0, so call it before the queue is used):

- `push()` / `tryPush()` measure the element with `sizeOf` and reserve its bytes before enqueuing; an
  element that would push the total over `maxBytes`, or is itself larger than `maxBytes`, is rejected
  (`false`). The reservation is rolled back if the underlying enqueue fails.
- Every successful pop (`waitPop()`, `tryPop()`, `tryPopBulk()`) releases the popped elements' bytes.
- `maxBytes` 0 means unlimited (bytes are still counted). Without `setByteLimit()` the limiter is
  disabled and `bytesUsed()` / `maxBytes()` return 0.

`main.cpp` sets it on the router's event queue to `analysisd.event_queue_max_bytes`, measuring each
`IngestEvent` by the size of its raw string (`e.second.size()`).

### CQueue Traits

`CQueue` uses custom `WQueueTraits` optimized for large queues:

- `BLOCK_SIZE = 512` — fewer allocations, better cache locality
- `IMPLICIT_INITIAL_INDEX_SIZE = 512` — covers up to ~2M elements without index reallocation

## Directory Structure

```
fastqueue/
├── CMakeLists.txt
├── interface/fastqueue/
│   └── iqueue.hpp                    # IQueue<T> — common interface
├── include/fastqueue/
│   ├── cqueue.hpp                    # CQueue<T> — lock-free implementation
│   ├── stdqueue.hpp                  # StdQueue<T> — mutex-based implementation
│   ├── ratelimiter.hpp               # RateLimiter — token bucket algorithm
│   └── bytelimiter.hpp               # ByteLimiter<T> — lock-free byte budget
├── src/
│   └── cqueue.cpp                    # CQueue template instantiation (empty body)
├── test/
│   ├── mocks/queue/
│   │   └── mockQueue.hpp             # GMock of IQueue<T>
│   └── src/component/
│       ├── cqueue_test.cpp           # CQueue component tests
│       ├── stdqueue_test.cpp         # StdQueue component tests
│       └── ratelimiter_test.cpp      # RateLimiter multi-consumer accuracy tests
└── benchmark/
    ├── README.md                     # Benchmark documentation
    └── src/
        ├── cqueue_bench.cpp          # CQueue benchmarks
        ├── stdqueue_bench.cpp        # StdQueue benchmarks
        ├── comparison_bench.cpp      # Head-to-head comparison
        └── memory_profile_bench.cpp  # Standalone memory profiler (no Google Benchmark)
```

## Public Interface

### `IQueue<T>` (iqueue.hpp)

```cpp
namespace fastqueue {
constexpr int64_t WAIT_DEQUEUE_TIMEOUT_USEC = 1 * 100000;    // 100 ms; the router workers' waitPop() timeout
constexpr size_t MIN_QUEUE_CAPACITY = 8192;

template<typename T>
class IQueue {
    virtual bool push(T&& element) = 0;                          // Move-push, false if full
    virtual bool tryPush(const T& element) = 0;                  // Copy-push, false if full
    virtual bool waitPop(T& element, int64_t timeout) = 0;       // Blocking pop (timeout in µs)
    virtual bool tryPop(T& element) = 0;                         // Non-blocking pop
    virtual bool empty() const noexcept = 0;
    virtual std::size_t size() const noexcept = 0;
    virtual std::size_t aproxFreeSlots() const noexcept = 0;     // Backpressure signal
    virtual std::size_t tryPopBulk(T* elements, std::size_t max) = 0;  // Batch pop
    virtual std::size_t bytesUsed() const noexcept { return 0; }     // Byte budget in use
    virtual std::size_t maxBytes() const noexcept { return 0; }      // Byte budget (0 = none)
    virtual void setByteLimit(std::size_t maxBytes,
                              std::function<std::size_t(const T&)> sizeOf) = 0;
};
}
```

### `CQueue<T>` (cqueue.hpp)

```cpp
explicit CQueue(int capacity);                                              // Basic
CQueue(int capacity, double maxElementsPerSecond, double burstSize = 0.0);  // With rate limiting
```

### `StdQueue<T>` (stdqueue.hpp)

```cpp
explicit StdQueue(int capacity);                                              // Basic
StdQueue(int capacity, double maxElementsPerSecond, double burstSize = 0.0);  // With rate limiting
```

### `RateLimiter` (ratelimiter.hpp)

```cpp
RateLimiter(size_t maxElementsPerSecond, size_t burstSize = 0);
bool tryAcquire(size_t count = 1);                    // Non-blocking
bool waitAcquire(size_t count, int64_t timeoutMicros); // Blocking with timeout
```

## Implementation Details

### CQueue

- Wraps `moodycamel::BlockingConcurrentQueue<T, WQueueTraits>`.
- `push()` / `tryPush()` → `try_enqueue()` (never allocates beyond the blocks preallocated for the initial capacity).
- `waitPop()` → `wait_dequeue_timed()` with microsecond timeout.
- `tryPopBulk()` → `try_dequeue_bulk()` (native batch operation).
- Size reporting is approximate (`size_approx()`).

### StdQueue

- Wraps `std::queue<T>` with `std::mutex` + `std::condition_variable`.
- `push()` acquires lock, checks capacity, pushes, notifies condition variable.
- `waitPop()` uses `condition_variable::wait_for()` for timed blocking; a timeout of 0 (or negative) does not wait.
- `tryPopBulk()` implemented as a loop under a single lock acquisition.
- Size reporting is exact.

### Rate Limiter Integration

When a `RateLimiter` is configured, dequeue operations follow a two-phase approach:

1. **Acquire tokens** from the rate limiter (may wait or fail)
2. **Dequeue** from the underlying queue with remaining timeout

The rate limiter uses `std::atomic<double>` for tokens and `std::atomic<int64_t>` for the last refill timestamp, achieving lock-free operation. Token refill is computed lazily on each access based on elapsed microseconds.

## CMake Targets

| Target | Type | Alias | Description |
|--------|------|-------|-------------|
| `fastqueue_ifastqueue` | INTERFACE | `fastqueue::ifastqueue` | `IQueue<T>` interface |
| `fastqueue_fasqueue` (sic) | STATIC | `fastqueue::fastqueue` | Both implementations (links `unofficial-concurrentqueue::concurrentqueue`) |
| `fastqueue_mocks` | INTERFACE | `fastqueue::mocks` | GMock `fastqueue::mocks::MockQueue<T>` (`ENGINE_BUILD_TEST`) |
| `fastqueue_ctest` | Executable | — | Component tests (`ENGINE_BUILD_TEST`) |
| `fastqueue_bench` | INTERFACE | `fastqueue::bench` | Links `fastqueue::fastqueue` + `benchmark::benchmark` (`ENGINE_BUILD_BENCHMARK`) |
| `fastqueue_benchmark` | Executable | — | CQueue benchmarks (`ENGINE_BUILD_BENCHMARK`) |
| `fastqueue_stdqueue_benchmark` | Executable | — | StdQueue benchmarks (`ENGINE_BUILD_BENCHMARK`) |
| `fastqueue_comparison_benchmark` | Executable | — | Head-to-head comparison (`ENGINE_BUILD_BENCHMARK`) |
| `fastqueue_memory_profile` | Executable | — | Memory profiler, links only `fastqueue::fastqueue` (`ENGINE_BUILD_BENCHMARK`) |

`MockQueue<T>` mocks the pure virtual methods only; `bytesUsed()` / `maxBytes()` keep the interface's
defaults (0).

## Testing

- **Component tests** (`fastqueue_ctest`): `cqueue_test.cpp` and `stdqueue_test.cpp` cover construction
  limits, push/pop, timeouts (including negative), FIFO order, bulk pop, capacity and free-slot
  accounting, and rate-limiter throttling, refill, burst and thread safety; `cqueue_test.cpp` also covers
  the byte budget (`ByteLimit_*`). `ratelimiter_test.cpp` checks that several consumers sharing one
  limited queue do not exceed the configured rate.
- **Benchmarks** (`ENGINE_BUILD_BENCHMARK`): SPSC, MPSC, SPMC, MPMC, bulk and high-contention scenarios for each implementation, a head-to-head comparison that adds rate limiting, and a standalone `CQueue` memory profiler. See [benchmark/README.md](benchmark/README.md).

## Consumers

| Consumer | Dependency | Usage |
|----------|------------|-------|
| **router** | `fastqueue::ifastqueue` (`fastqueue::mocks` in tests) | Worker threads pop from `IQueue<IngestEvent>` (production) and `IQueue<test::EventTest>` (tester); its `router.queue.*` pull metrics read `size()`, `aproxFreeSlots()`, `bytesUsed()` and `maxBytes()` |
| **streamlog** | `fastqueue::fastqueue` | Each channel buffers log lines in a `StdQueue<std::string>` for its worker thread (`streamlog/src/channel.hpp`) |
| **main.cpp** | `fastqueue::fastqueue` | Creates the production `CQueue<router::IngestEvent>` (size, EPS and byte limit from `analysisd.event_queue_*`) and the tester `StdQueue<router::test::EventTest>` (same size, no limits) |
