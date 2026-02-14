# FastQueue Benchmarks

Comprehensive performance benchmarks for CQueue with different thread configurations and queue sizes.

## Important Notes

⚠️ **Minimum Queue Capacity**: CQueue requires a minimum capacity of **8,192 elements** (`MIN_QUEUE_CAPACITY`).
- This is 2x `BLOCK_SIZE` (4096) for optimal performance
- Attempting to create smaller queues will throw `std::runtime_error`
- Recommended sizes: 2^17 (131K), 2^20 (1M)

## Benchmark Categories

### 1. Single Producer, Single Consumer (SPSC)
- **BM_SPSC_PushPop**: Tests basic push/pop performance with different queue sizes
- Queue sizes tested: 2^17, 2^20 (minimum 8,192 enforced)
- Items tested: 1K-500K depending on queue size
- **Use case**: Sequential processing pipeline

### 2. Multiple Producers, Single Consumer (MPSC)
- **BM_MPSC_PushPop**: Multiple threads pushing, one consuming
- Producers: 2, 4, 8 threads
- Queue sizes: 2^17, 2^20
- **Use case**: Log aggregation, event collection

### 3. Single Producer, Multiple Consumers (SPMC)
- **BM_SPMC_PushPop**: One thread pushing, multiple consuming
- Consumers: 2, 4, 8 threads
- Queue sizes: 2^17, 2^20
- **Use case**: Work distribution, fan-out patterns

### 4. Multiple Producers, Multiple Consumers (MPMC)
- **BM_MPMC_PushPop**: Concurrent producers and consumers
- Configurations: 2x2, 4x4, 8x8, 2x4, 4x8, 8x16
- Queue sizes: 2^17, 2^20
- **Use case**: High-throughput message passing

### 5. Bulk Operations
- **BM_BulkPop**: Tests bulk dequeue performance
- Bulk sizes: 1, 10, 100, 1000
- Queue sizes: 2^17, 2^20
- **Use case**: Batch processing

### 6. High Contention
- **BM_HighContention**: Mixed push/pop operations under high contention
- Threads: 2, 4, 8, 16
- **Use case**: Stress testing, worst-case scenarios

## Running Benchmarks

### Build with benchmarks enabled:
```bash
cd /workspaces/wazuh-5.x/wazuh/src
make TARGET=server ENGINE_TEST=y ENGINE_BENCHMARK=y DEBUG=yes
```

### Run all benchmarks:
```bash
./build/bin/fastqueue_benchmark
```

### Run specific benchmark patterns:
```bash
# Only SPSC benchmarks
./build/bin/fastqueue_benchmark --benchmark_filter=BM_SPSC

# Only queue size 2^20
./build/bin/fastqueue_benchmark --benchmark_filter=".*1048576.*"

# Run with specific repetitions
./build/bin/fastqueue_benchmark --benchmark_repetitions=5

# Generate JSON output
./build/bin/fastqueue_benchmark --benchmark_format=json --benchmark_out=results.json
```

## Understanding Results

### Metrics
- **Time**: Time per iteration (microseconds)
- **Items/sec**: Throughput (operations per second)
- Lower time and higher items/sec = better performance

### Expected Performance Characteristics

#### Queue Size Impact
- **Minimum**: 8,192 elements (MIN_QUEUE_CAPACITY) - enforced by constructor
- **2^17 (131K)**: Balanced for typical workloads, optimal memory/performance ratio
- **2^20 (1M)**: Best throughput for high-volume scenarios, same performance as 131K

#### Thread Count Impact
- Linear scaling expected up to physical cores
- Performance plateaus beyond CPU core count
- Contention increases with thread count

#### Bulk Operations
- **Bulk size 1**: Baseline (same as tryPop)
- **Bulk size 10-100**: 2-5x faster than individual pops
- **Bulk size 1000**: Maximum throughput, watch for latency spikes

## Performance Goals

Based on WQueueTraits (BLOCK_SIZE=4096, IMPLICIT_INITIAL_INDEX_SIZE=512):

| Scenario | Target Throughput | Notes |
|----------|------------------|-------|
| SPSC | 10M+ ops/sec | Minimal contention |
| MPSC (4 producers) | 5M+ ops/sec | Good scaling |
| SPMC (4 consumers) | 5M+ ops/sec | Consumer-bound |
| MPMC (4x4) | 3M+ ops/sec | High contention |
| Bulk (size 100) | 20M+ ops/sec | Batch efficiency |

## Tuning Recommendations

If benchmarks show poor performance:

1. **High latency in SPSC**: Check BLOCK_SIZE (currently 4096)
2. **Poor MPMC scaling**: Increase IMPLICIT_INITIAL_INDEX_SIZE (currently 512)
3. **Bulk operations slow**: Verify WQueueTraits configuration
4. **Contention issues**: Consider queue size increase or workload distribution

## Example Output

```
$ENGINE_BUILD/source/fastqueue/fastqueue_benchmark
2026-02-14T04:33:52+00:00
Running /workspaces/wazuh-5.x/wazuh/src/build/engine/source/fastqueue/fastqueue_benchmark
Run on (32 X 5600 MHz CPU s)
CPU Caches:
  L1 Data 48 KiB (x16)
  L1 Instruction 32 KiB (x16)
  L2 Unified 2048 KiB (x16)
  L3 Unified 36864 KiB (x1)
Load Average: 17.04, 15.95, 8.56
***WARNING*** CPU scaling is enabled, the benchmark real time measurements may be noisy and will incur extra overhead.
***WARNING*** Library was built as DEBUG. Timings may be affected.
------------------------------------------------------------------------------------------
Benchmark                                Time             CPU   Iterations UserCounters...
------------------------------------------------------------------------------------------
BM_SPSC_PushPop<1 << 10>/100          9619 us         9.23 us         1000 items_per_second=21.6791M/s
BM_SPSC_PushPop<1 << 10>/500       4045280 us         1264 us           10 items_per_second=791.357k/s
BM_SPSC_PushPop<1 << 10>/1000     18103519 us         5872 us           10 items_per_second=340.594k/s
BM_SPSC_PushPop<1 << 17>/1000         48.2 us         48.1 us        13976 items_per_second=41.621M/s
BM_SPSC_PushPop<1 << 17>/10000         488 us          487 us         1452 items_per_second=41.0907M/s
BM_SPSC_PushPop<1 << 17>/50000        2478 us         2471 us          285 items_per_second=40.476M/s
BM_SPSC_PushPop<1 << 20>/10000         484 us          483 us         1450 items_per_second=41.4095M/s
BM_SPSC_PushPop<1 << 20>/100000       5096 us         5071 us          100 items_per_second=39.4417M/s
BM_SPSC_PushPop<1 << 20>/500000      25973 us        25893 us           26 items_per_second=38.6202M/s
BM_MPSC_PushPop/2/131072               306 us          302 us         2220 items_per_second=6.61412M/s
BM_MPSC_PushPop/4/131072               460 us          458 us         1541 items_per_second=8.72483M/s
BM_MPSC_PushPop/8/131072               876 us          871 us          809 items_per_second=9.18399M/s
BM_MPSC_PushPop/2/1048576              300 us          297 us         2300 items_per_second=6.74182M/s
BM_MPSC_PushPop/4/1048576              461 us          460 us         1488 items_per_second=8.69909M/s
BM_MPSC_PushPop/8/1048576              896 us          892 us          806 items_per_second=8.97251M/s
BM_SPMC_PushPop/2/131072              3817 us         3662 us          197 items_per_second=2.73069M/s
BM_SPMC_PushPop/4/131072              4370 us         4237 us          165 items_per_second=2.36016M/s
BM_SPMC_PushPop/8/131072              4650 us         4598 us          152 items_per_second=2.17492M/s
BM_SPMC_PushPop/2/1048576             3748 us         3634 us          193 items_per_second=2.75179M/s
BM_SPMC_PushPop/4/1048576             4322 us         4221 us          166 items_per_second=2.36938M/s
BM_SPMC_PushPop/8/1048576             4833 us         4771 us          146 items_per_second=2.09581M/s
BM_MPMC_PushPop/2/2/131072             716 us         63.3 us        13527 items_per_second=31.6013M/s
BM_MPMC_PushPop/4/4/131072            1122 us          170 us         3885 items_per_second=23.5047M/s
BM_MPMC_PushPop/8/8/131072            1778 us          398 us         1865 items_per_second=20.0981M/s
BM_MPMC_PushPop/2/4/1048576            645 us          107 us         6105 items_per_second=18.7768M/s
BM_MPMC_PushPop/4/8/1048576           1119 us          242 us         3189 items_per_second=16.5527M/s
BM_MPMC_PushPop/8/16/1048576          2137 us          466 us         1594 items_per_second=17.169M/s
BM_BulkPop/131072/1                    662 us          655 us         1068 items_per_second=15.266M/s
BM_BulkPop/131072/10                   392 us          389 us         1809 items_per_second=25.6766M/s
BM_BulkPop/131072/100                  431 us          428 us         1633 items_per_second=23.3405M/s
BM_BulkPop/1048576/1                   661 us          657 us         1061 items_per_second=15.229M/s
BM_BulkPop/1048576/10                  388 us          386 us         1815 items_per_second=25.9185M/s
BM_BulkPop/1048576/100                 438 us          432 us         1611 items_per_second=23.1659M/s
BM_BulkPop/1048576/1000                434 us          430 us         1615 items_per_second=23.2454M/s
BM_HighContention/2                   2135 us         71.5 us        10432 items_per_second=279.869M/s
BM_HighContention/4                   4142 us         82.1 us         1000 items_per_second=486.928M/s
BM_HighContention/8                   6678 us          289 us         1000 items_per_second=276.955M/s
BM_HighContention/16                 11236 us          546 us         1366 items_per_second=292.878M/s
```
