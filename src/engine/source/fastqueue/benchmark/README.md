# FastQueue Benchmarks

Performance benchmarks comparing `CQueue` (lock-free) and `StdQueue` (mutex-based) implementations,
plus a standalone memory profiler for `CQueue`. Library documentation: [../README.md](../README.md).

## Building

The four executables are defined in `../CMakeLists.txt` under `ENGINE_BUILD_BENCHMARK`, which
`src/engine/CMakeLists.txt` forces on when the build passes `WAZUH_ENGINE_TEST` — that is,
`make -C src -j TARGET=manager ENGINE_TEST=y` (with `TEST` unset). They land in
`src/build/engine/source/fastqueue/`. CMake warns when benchmarks are built in a build type other than
`Release` or `RelWithDebInfo`, because the timings are skewed.

## Available Benchmarks

| Executable | Source | Framework |
|---|---|---|
| `fastqueue_benchmark` | `src/cqueue_bench.cpp` | Google Benchmark — `CQueue` only |
| `fastqueue_stdqueue_benchmark` | `src/stdqueue_bench.cpp` | Google Benchmark — the same scenarios on `StdQueue` (`BM_StdQueue_*`) |
| `fastqueue_comparison_benchmark` | `src/comparison_bench.cpp` | Google Benchmark — paired `BM_Compare_*_CQueue` / `BM_Compare_*_StdQueue` cases |
| `fastqueue_memory_profile` | `src/memory_profile_bench.cpp` | Standalone (`main()`, no Google Benchmark) |

Every queued element is a `std::shared_ptr<BenchData>` in the Google Benchmark executables and a
`std::string` in the memory profiler.

## Important Notes

**Minimum Queue Capacity**: Both implementations require **8,192 elements** (`MIN_QUEUE_CAPACITY`);
a smaller capacity throws `std::runtime_error`. `CQueue` uses `WQueueTraits` with `BLOCK_SIZE = 512` and
`IMPLICIT_INITIAL_INDEX_SIZE = 512` (`include/fastqueue/cqueue.hpp`). The benchmarks use 2^17 (131,072)
and 2^20 (1,048,576) element queues.

**Reading `items_per_second`**: none of the cases calls `UseRealTime()`, so Google Benchmark derives
`items_per_second` from the CPU time of the benchmark thread. In the MPMC, high-contention and
rate-limit cases that thread mostly waits (in `join()`, or sleeping), so its CPU time is far below the
wall time (`Time` column) and the rate is inflated — compare the `Time` column across implementations
for those cases. In MPSC and SPMC the benchmark thread is itself the consumer or the producer.

## Benchmark Scenarios

### `fastqueue_benchmark` and `fastqueue_stdqueue_benchmark`

Both files register the same cases with the same arguments:

| Case | Arguments | Work per iteration |
|---|---|---|
| SPSC (`BM_SPSC_PushPop<N>`) | queue 2^17: 1K, 10K, 50K items; queue 2^20: 10K, 100K, 500K items | push all, then `waitPop()` all, one thread |
| MPSC (`BM_MPSC_PushPop`) | 2, 4, 8 producers × queue 2^17, 2^20 | 1,000 items per producer, one consumer |
| SPMC (`BM_SPMC_PushPop`) | 2, 4, 8 consumers × queue 2^17, 2^20 | 10,000 items, one producer |
| MPMC (`BM_MPMC_PushPop`) | 2×2, 4×4, 8×8 on 2^17; 2×4, 4×8, 8×16 on 2^20 | 1,000 items per producer |
| Bulk (`BM_BulkPop`) | bulk 1, 10, 100 on 2^17; bulk 1, 10, 100, 1000 on 2^20 | fill 10,000 items, drain with `tryPopBulk()` |
| High contention (`BM_HighContention`) | 2, 4, 8, 16 threads, queue 2^20 | 10,000 ops per thread, alternating `push()` / `tryPop()` |

### `fastqueue_comparison_benchmark`

| Case | Arguments | Work per iteration |
|---|---|---|
| SPSC | 1K, 10K, 50K items, queue 2^17 | push all, then `waitPop()` all |
| MPMC | fixed 4 producers × 4 consumers, queue 2^17 | 1,000 items per producer |
| MPSC | 2, 4, 8 producers, queue 2^17 | 1,000 items per producer |
| SPMC | 2, 4, 8 consumers, queue 2^17 | 10,000 items |
| Bulk | bulk 1, 10, 100, queue 2^17 | fill 10,000 items, drain with `tryPopBulk()` |
| Rate limit | 1,000 and 10,000 elements/s (burst = rate), queue `MIN_QUEUE_CAPACITY` | push 100 items, pop each with `tryPop()`, sleeping 100 µs whenever the limiter refuses |
| High contention | 4, 8, 16 threads, queue 2^20 | 5,000 ops per thread, alternating `push()` / `tryPop()` |

Rate limiting exists only in the comparison executable. Both implementations run the identical
`tryPop()` + sleep loop there, so the case measures the shared `RateLimiter`, not the queue's blocking
path (`waitPop()` / the condition variable are not exercised).

## Running Benchmarks

```bash
cd src/build/engine/source/fastqueue
./fastqueue_comparison_benchmark
./fastqueue_benchmark --benchmark_filter='BM_MPSC_PushPop'
./fastqueue_stdqueue_benchmark --benchmark_filter='BM_StdQueue_Bulk'
```

The executables use `BENCHMARK_MAIN()`, so every standard Google Benchmark flag
(`--benchmark_filter`, `--benchmark_repetitions`, `--benchmark_format=json`, …) applies.

## Memory Profiling

### `fastqueue_memory_profile` (Standalone)

Measures heap allocation behaviour of `CQueue<std::string>` in one MPMC scenario: **8 producers, 4
consumers, 131,072 events of 4,096 bytes**, queue capacity `MIN_QUEUE_CAPACITY` (8,192). Before the
scenario it reports the construction cost of an empty `CQueue<std::string>` of that capacity.

### What it measures
- **RSS delta**: change in `VmRSS` from `/proc/self/status` (`VmPeak` is captured too)
- **Peak live memory**: maximum heap bytes in flight at any point
- **Total allocations** and **total bytes allocated** during push/pop
- **Avg bytes/event**, **overhead/event** (versus the payload size) and **allocs/event**
- **Live bytes at end**
- **Queue construction cost**: allocations and bytes to create an empty queue

### Running

```bash
cd src/build/engine/source/fastqueue

# Direct execution (text report to stdout)
./fastqueue_memory_profile

# With Valgrind Massif (heap timeline snapshots)
valgrind --tool=massif ./fastqueue_memory_profile
ms_print massif.out.<pid>

# With heaptrack (if available)
heaptrack ./fastqueue_memory_profile
heaptrack_print heaptrack.fastqueue_memory_profile.<pid>.gz
```

### How it works
- Overrides global `operator new` / `operator delete` with atomic counters
- Stores allocation size in a 16-byte header before each returned pointer
- Thread-safe via `std::atomic` (no mutex overhead in hot path)
- Reads `/proc/self/status` for `VmRSS` / `VmPeak`
- The scenario's queue is constructed before tracking begins (isolates push/pop cost from construction cost)

## Recorded Run

One recorded run of `fastqueue_comparison_benchmark` on a 32-core host. Its header warns that CPU
scaling was enabled and that the (Google Benchmark) library was built as **DEBUG**, so the absolute
numbers are indicative only; rerun on a `Release`/`RelWithDebInfo` build before drawing conclusions.

```
$ src/build/engine/source/fastqueue/fastqueue_comparison_benchmark
2026-02-16T21:30:07+00:00
Running /workspaces/wazuh-5.x/wazuh/src/build/engine/source/fastqueue/fastqueue_comparison_benchmark
Run on (32 X 5600 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 2048 KiB (x16)
  L3 Unified 36864 KiB (x1)
Load Average: 2.25, 1.90, 2.90
***WARNING*** CPU scaling is enabled, the benchmark real time measurements may be noisy and will incur extra overhead.
***WARNING*** Library was built as DEBUG. Timings may be affected.
------------------------------------------------------------------------------------------------
Benchmark                                      Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------------
BM_Compare_SPSC_CQueue/1000                 51.6 us         51.4 us        12929 items_per_second=38.8809M/s
BM_Compare_SPSC_CQueue/10000                 512 us          510 us         1371 items_per_second=39.1879M/s
BM_Compare_SPSC_CQueue/50000                2559 us         2551 us          272 items_per_second=39.2049M/s
BM_Compare_SPSC_StdQueue/1000               44.1 us         43.9 us        15940 items_per_second=45.5183M/s
BM_Compare_SPSC_StdQueue/10000               443 us          442 us         1606 items_per_second=45.2999M/s
BM_Compare_SPSC_StdQueue/50000              2276 us         2269 us          311 items_per_second=44.0725M/s
BM_Compare_MPMC_CQueue                      1059 us          167 us         3991 items_per_second=23.8888M/s
BM_Compare_MPMC_StdQueue                    2761 us          181 us         1000 items_per_second=22.0425M/s
BM_Compare_MPSC_CQueue/2                     314 us          311 us         2226 items_per_second=6.43011M/s
BM_Compare_MPSC_CQueue/4                     464 us          463 us         1499 items_per_second=8.63377M/s
BM_Compare_MPSC_CQueue/8                     862 us          857 us          841 items_per_second=9.33645M/s
BM_Compare_MPSC_StdQueue/2                   842 us          708 us          964 items_per_second=2.82319M/s
BM_Compare_MPSC_StdQueue/4                  1499 us         1236 us          561 items_per_second=3.23707M/s
BM_Compare_MPSC_StdQueue/8                  2741 us         2410 us          288 items_per_second=3.31911M/s
BM_Compare_SPMC_CQueue/2                    3260 us         3138 us          224 items_per_second=3.18679M/s
BM_Compare_SPMC_CQueue/4                    3350 us         3265 us          213 items_per_second=3.06301M/s
BM_Compare_SPMC_CQueue/8                    3540 us         3497 us          203 items_per_second=2.8595M/s
BM_Compare_SPMC_StdQueue/2                  4721 us         3726 us          187 items_per_second=2.68414M/s
BM_Compare_SPMC_StdQueue/4                  9911 us         8231 us           86 items_per_second=1.21494M/s
BM_Compare_SPMC_StdQueue/8                 16969 us        15364 us           45 items_per_second=650.855k/s
BM_Compare_Bulk_CQueue/1                     663 us          660 us         1059 items_per_second=15.1425M/s
BM_Compare_Bulk_CQueue/10                    386 us          385 us         1816 items_per_second=25.956M/s
BM_Compare_Bulk_CQueue/100                   409 us          408 us         1718 items_per_second=24.5227M/s
BM_Compare_Bulk_StdQueue/1                   587 us          586 us         1191 items_per_second=17.0578M/s
BM_Compare_Bulk_StdQueue/10                  466 us          465 us         1505 items_per_second=21.4906M/s
BM_Compare_Bulk_StdQueue/100                 450 us          449 us         1553 items_per_second=22.2909M/s
BM_Compare_RateLimit_CQueue/1000           90000 us         1662 us          100 items_per_second=60.1722k/s
BM_Compare_RateLimit_CQueue/10000           9000 us          115 us         1000 items_per_second=866.421k/s
BM_Compare_RateLimit_StdQueue/1000         90001 us          943 us          100 items_per_second=105.998k/s
BM_Compare_RateLimit_StdQueue/10000         9000 us          105 us         1000 items_per_second=952.396k/s
BM_Compare_HighContention_CQueue/4          2001 us         76.7 us         9592 items_per_second=260.706M/s
BM_Compare_HighContention_CQueue/8          3826 us          205 us         1000 items_per_second=194.772M/s
BM_Compare_HighContention_CQueue/16         6730 us          402 us         1000 items_per_second=198.798M/s
BM_Compare_HighContention_StdQueue/4        3561 us         79.8 us         1000 items_per_second=250.588M/s
BM_Compare_HighContention_StdQueue/8       10086 us          236 us         1000 items_per_second=169.72M/s
BM_Compare_HighContention_StdQueue/16      21036 us          458 us         1000 items_per_second=174.831M/s
```


What this run shows (wall time, `Time` column, lower is better):

| Case | CQueue | StdQueue |
|---|---|---|
| SPSC, 10K items | 512 µs | 443 µs |
| MPSC, 8 producers | 862 µs | 2,741 µs |
| SPMC, 8 consumers | 3,540 µs | 16,969 µs |
| MPMC, 4×4 | 1,059 µs | 2,761 µs |
| Bulk, size 10 | 386 µs | 466 µs |
| Rate limit, 10K/s | 9,000 µs | 9,000 µs |
| High contention, 16 threads | 6,730 µs | 21,036 µs |

In this run `StdQueue` is faster only in single-threaded cases (SPSC, and bulk pop of size 1: 587 µs
against 663 µs); `CQueue` is faster with several
producers or consumers and under contention; the rate-limited case is bound by the token refill (100
items at the configured rate) and takes the same wall time on both.
