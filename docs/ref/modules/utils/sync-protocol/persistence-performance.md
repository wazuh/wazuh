# Persistence Performance and WAL Justification

## Overview

The Agent Sync Protocol uses SQLite as its persistent storage backend, configured with Write-Ahead Logging (WAL) mode to optimize performance for high-throughput write operations. This document provides technical justification and performance analysis supporting the use of WAL mode in the persistent queue implementation.

## Implementation Location

The WAL configuration is set in the `PersistentQueueStorage` constructor:

**File**: `src/shared_modules/sync_protocol/src/persistent_queue_storage.cpp`

```cpp
m_connection.execute("PRAGMA synchronous = OFF;");
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

WAL mode runs with `PRAGMA synchronous = OFF` (PR #37180), so SQLite never calls `fsync()`, not even at WAL checkpoints (with `NORMAL`, WAL mode already skipped it at commit but still synced at checkpoints):

- **Agent crash or kill**: committed batches survive; SQLite replays the WAL on the next open
- **Operating system crash or power loss**: the most recent commits can be lost, and the database file can be corrupted
- **Atomic operations**: Complete transactions or none at all
- **Automatic checkpoint management**: SQLite handles WAL-to-database merging

The weaker guarantee is accepted because the queue is transient: items are removed once the manager accepts them, and FIM, SCA and syscollector's regular instance resend lost items after their next integrity check (every 24 hours by default) finds a checksum mismatch. Nothing repairs a database file corrupted by a power loss.

### 4. Benefits Summary

| Benefit | Impact |
|---------|--------|
| **Performance** | 2-3× faster FIM scans |
| **Scalability** | Better handling of large file sets |
| **SSD Longevity** | Sequential writes reduce wear leveling |
| **Reliability** | Atomic commits; survives an agent crash, not a power loss |
| **Concurrency** | Readers don't block writers (if needed in future) |

## Transaction Strategy Analysis

### Batched Writes

`persistDifference()` does not write to SQLite directly. `PersistentQueue` buffers items in memory and a flush thread writes them to storage in one `BEGIN IMMEDIATE` transaction when 100 items are buffered or 500 ms have passed, whichever comes first; a sync also flushes the buffer before it reads the queue. The flush uses two buffers, so modules keep submitting while a batch is being written. The destructor flushes whatever is still buffered on a clean shutdown; an agent crash loses the unflushed buffer and any batch whose transaction had not committed.

### Transaction-per-Event Performance (earlier design)

Until PR #37180, during 5.0.0 development, each file operation was wrapped in its own `BEGIN`/`COMMIT` transaction. These measurements date from that design:

#### Test Results

**With BEGIN/COMMIT per event:**

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


## Configuration Details

### Current SQLite PRAGMA Settings

```cpp
PRAGMA synchronous = OFF;  // Never fsync(), not even at checkpoints
PRAGMA journal_mode = WAL; // Write-Ahead Logging mode
```

### Configuration Rationale

- **synchronous = OFF**:
  - Never waits for data to reach the disk, at commit or at WAL checkpoints
  - Survives an agent crash; an operating system crash or power loss can lose recent commits or corrupt the file
  - Acceptable because the queue is transient and the modules' integrity check resends lost items

- **journal_mode = WAL**:
  - Enables Write-Ahead Logging
  - Sequential append-only writes to `.wal` file
  - Automatic checkpointing when WAL grows
  - Better performance for write-heavy workloads


## Conclusion

The evidence demonstrates that WAL mode provides substantial performance benefits for FIM operations, with improvements ranging from 2× on Linux to 2.85× on Windows. Beyond speed improvements, WAL mode delivers:

- **Significant disk I/O optimizations** through sequential writes
- **Atomic commits** that survive an agent crash
- **Cross-platform benefits** with particularly strong gains on Windows

Batched writes with WAL mode and `synchronous = OFF` trade durability against a power loss, which a transient queue does not need, for lower write latency.

This configuration is well-suited for the Agent Sync Protocol's write-heavy workload patterns and should be maintained as the standard persistence strategy.

## References

- SQLite WAL Documentation: https://www.sqlite.org/wal.html
- SQLite PRAGMA Documentation: https://www.sqlite.org/pragma.html
- Implementation: `src/shared_modules/sync_protocol/src/persistent_queue_storage.cpp`
