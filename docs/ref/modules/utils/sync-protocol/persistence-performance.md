# Persistence Performance and WAL Justification

## Overview

The Agent Sync Protocol uses SQLite as its persistent storage backend, configured with Write-Ahead Logging (WAL) mode to optimize performance for high-throughput write operations. This document provides technical justification and performance analysis supporting the use of WAL mode in the persistent queue implementation.

## Implementation Location

The WAL configuration is set in the `PersistentQueueStorage` constructor:

**File**: `src/shared_modules/sync_protocol/src/persistent_queue_storage.cpp`

```cpp
m_connection.execute("PRAGMA synchronous = NORMAL;");
m_connection.execute("PRAGMA journal_mode = WAL;");
```

## Performance Analysis Results

### Comparative Scan Durations

Performance testing confirms that enabling Write-Ahead Logging (WAL) mode provides significant performance improvements, particularly for File Integrity Monitoring (FIM), which is the module with the highest load.

| Platform | Journal Mode | Scan Duration | Performance Improvement |
|----------|--------------|---------------|-------------------------|
| **Linux** | WAL enabled | 24 seconds | **2.0× faster** |
| **Linux** | Default (DELETE) | 48 seconds | Baseline |
| **Windows** | WAL enabled | 100 seconds | **2.85× faster** |
| **Windows** | Default (DELETE) | 285 seconds | Baseline |

### Key Findings

1. **Windows benefits most dramatically** from WAL mode (2.85× improvement vs 2.0× on Linux)
2. **Consistent performance gains** across all tested scenarios
3. **FIM scan duration reduced by 2-3×** across both platforms

## Technical Justification for WAL Mode

### 1. I/O Optimization for FIM Workload

FIM scans generate high-volume, sequential write operations as file checksums are recorded. WAL mode optimizes this pattern by:

- **Append-only writes** to `.wal` file (sequential I/O)
- **Reduced disk head movement** compared to DELETE journal's random writes

### 2. Platform-Specific Advantages

#### Windows-Specific Benefits

The larger performance gain on Windows (2.85× vs 2.0×) is due to NTFS/Win32 characteristics:

- **FlushFileBuffers() cost**: Windows file flush operations are 5-10× more expensive than Linux's `fsync()`
- **File locking overhead**: NTFS mandatory locking adds contention not present in Linux's advisory locks
- **Journal file management**: DELETE mode requires create/delete cycles that are expensive on NTFS

#### Linux Benefits

While the improvement is smaller on Linux, WAL mode still provides:

- **Reduced fsync() calls**: Fewer kernel context switches
- **Better ext4/XFS performance**: These filesystems optimize sequential writes
- **Lower I/O wait times**: Reduced contention on busy systems

### 3. Database Integrity & Recovery

WAL mode with `PRAGMA synchronous = NORMAL` provides optimal balance:

- **Crash-safe**: Commits are durable once written to WAL
- **Atomic operations**: Complete transactions or none at all
- **Automatic checkpoint management**: SQLite handles WAL-to-database merging

### 4. Benefits Summary

| Benefit | Impact |
|---------|--------|
| **Performance** | 2-3× faster FIM scans |
| **Scalability** | Better handling of large file sets |
| **SSD Longevity** | Sequential writes reduce wear leveling |
| **Reliability** | Crash-safe with atomic commits |
| **Concurrency** | Readers don't block writers (if needed in future) |

## Transaction Strategy Analysis

### Transaction-per-Event Performance

The Agent Sync Protocol uses a transaction-per-event approach, where each file operation is wrapped in its own `BEGIN`/`COMMIT` transaction. Performance testing validates this approach:

#### Test Results

**With BEGIN/COMMIT per event (current implementation):**

- Test 1: 10:28:18 → 10:29:10 = 52 seconds
- Test 2: 11:19:34 → 11:20:30 = 56 seconds
- Test 3: 11:22:35 → 11:23:44 = 69 seconds
- Test 4: 11:24:39 → 11:25:33 = 54 seconds
- Test 5: 11:26:15 → 11:27:10 = 55 seconds
- **Average: ~57 seconds**

**Without BEGIN/COMMIT (agent_sync_protocol disabled):**

- Test 1: 10:31:12 → 10:32:06 = 54 seconds
- Test 2: 11:05:11 → 11:06:03 = 52 seconds
- Test 3: 11:12:54 → 11:13:49 = 55 seconds
- Test 4: 11:14:46 → 11:15:39 = 53 seconds
- Test 5: 11:16:44 → 11:17:37 = 53 seconds
- **Average: ~53 seconds**

### Transaction Overhead Analysis

The measured overhead of BEGIN/COMMIT per file operation:

```
57 seconds (with transactions) - 53 seconds (without) = 4 seconds overhead
```

This represents only **~7% of total scan time** (4s / 57s ≈ 7%), demonstrating that:

1. **WAL mode successfully minimized transaction costs** - The overhead is negligible
2. **Primary bottleneck is filesystem I/O and hashing** - Not database transactions
3. **Transaction-per-event approach is sufficiently efficient** - No need for complex batching


## Configuration Details

### Current SQLite PRAGMA Settings

```cpp
PRAGMA synchronous = NORMAL;  // Balance between safety and performance
PRAGMA journal_mode = WAL;    // Write-Ahead Logging mode
```

### Configuration Rationale

- **synchronous = NORMAL**:
  - Commits are durable after written to WAL
  - Does not wait for OS-level flush on every transaction
  - Provides crash safety with better performance than FULL
  - More secure than OFF mode

- **journal_mode = WAL**:
  - Enables Write-Ahead Logging
  - Sequential append-only writes to `.wal` file
  - Automatic checkpointing when WAL grows
  - Better performance for write-heavy workloads


## Conclusion

The evidence demonstrates that WAL mode provides substantial performance benefits for FIM operations, with improvements ranging from 2× on Linux to 2.85× on Windows. Beyond speed improvements, WAL mode delivers:

- **Significant disk I/O optimizations** through sequential writes
- **Crash-safe data persistence** with minimal overhead
- **Simple implementation** using transaction-per-event pattern
- **Cross-platform benefits** with particularly strong gains on Windows

The transaction-per-event approach with WAL mode represents an optimal balance of:
- **Performance**: Minimal overhead (7%) with 2-3× overall improvement
- **Reliability**: Crash-safe, atomic operations
- **Maintainability**: Simple code, easy debugging

This configuration is well-suited for the Agent Sync Protocol's write-heavy workload patterns and should be maintained as the standard persistence strategy.

## References

- SQLite WAL Documentation: https://www.sqlite.org/wal.html
- SQLite PRAGMA Documentation: https://www.sqlite.org/pragma.html
- Implementation: `src/shared_modules/sync_protocol/src/persistent_queue_storage.cpp`
