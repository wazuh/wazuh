# Scheduler Module

## Overview

The **scheduler** module provides a multi-threaded, priority-aware task scheduling system for the Wazuh engine. It manages the execution of periodic and one-time background tasks using a configurable thread pool and a sorted, thread-safe priority queue.

Tasks are identified by unique names and configured with an execution interval, an optional immediate-execution flag, CPU priority (nice value), and a callable function. The scheduler handles task lifecycle—including automatic removal of one-time tasks and rescheduling of recurring ones—while guaranteeing thread safety across all operations.

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                     Consumers                          │
│  (main.cpp, streamlog, api/ioccrud)                    │
│                                                        │
│   scheduleTask("name", {interval, runImmediately, …})  │
│   scheduleTaskFirst("name", {interval, …})             │
└──────────────────────┬─────────────────────────────────┘
                       │
              ┌────────▼────────┐
              │   IScheduler     │  (interface)
              │  scheduleTask()  │
              │  scheduleTask-   │
              │    First()       │
              │  removeTask()    │
              │  getActiveCount  │
              │  getThreadCount  │
              └────────┬─────────┘
                       │
              ┌────────▼────────────────────────────────┐
              │            Scheduler                     │
              │                                          │
              │  m_tasks (map)  ←→  m_taskQueue (sorted) │
              │                                          │
              │  ┌──────────┐ ┌──────────┐ ┌──────────┐ │
              │  │ worker 0 │ │ worker 1 │ │ worker N │ │
              │  └──────────┘ └──────────┘ └──────────┘ │
              │       ↕             ↕             ↕      │
              │         pop() → execute → reschedule     │
              └──────────────────────────────────────────┘
```

## Key Concepts

### Task Configuration (`TaskConfig`)

Defined in `ischeduler.hpp`:

| Field | Type | Description |
|-------|------|-------------|
| `interval` | `std::size_t` | Execution interval in seconds. `0` = one-time task |
| `runImmediately` | `bool` | If `true` and `interval > 0`, first execution happens immediately; then recurs at `interval`. No effect when `interval == 0` |
| `CPUPriority` | `int` | Linux nice value (`-20` highest to `19` lowest). `0` = default |
| `taskFunction` | `std::function<void()>` | The callable to execute |

Fields must be specified in the order listed above when using C++20 designated initializers.

### One-Time vs Recurring Tasks

- **One-time** (`interval = 0`): Scheduled for immediate execution (`nextRun = now()`). Automatically removed from the task map after completion. `runImmediately` has no additional effect.
- **Recurring** (`interval > 0`, `runImmediately = false`): First execution occurs after `interval` seconds (`nextRun = now() + interval`). After each execution, rescheduled with `nextRun = now() + interval`.
- **Recurring with immediate first run** (`interval > 0`, `runImmediately = true`): First execution is immediate (`nextRun = now()`). Subsequent executions recur at `interval` seconds.

### Task Queue (`TaskQueue`)

An internal thread-safe sorted list that orders tasks by their `nextRun` time (earliest first). Features:

- **Blocking `pop()`**: Worker threads block on a condition variable until a task is available or shutdown is signaled.
- **Sorted insertion**: New tasks are inserted at the correct position via `std::lower_bound` to maintain chronological order.
- **Deep copy semantics**: Items returned by `pop()` are copied to prevent data races between the queue and the worker that processes the item.
- **Graceful shutdown**: `shutdown()` sets a flag and notifies all waiting threads.

### Thread Pool

The scheduler creates a fixed number of worker threads (configurable, minimum 1). Each worker runs a loop:

1. `pop()` a task from the queue (blocks if empty)
2. If `nextRun > now`, push the task back and sleep 100 ms
3. Verify the task still exists in the task map (it may have been removed)
4. Set thread CPU priority via `setpriority(2)`
5. Execute the task function (catching exceptions)
6. Restore default priority
7. Reschedule (recurring) or remove (one-time) the task

### Deferred Start

The scheduler is designed to be **created before tasks are registered** and **started only after all tasks have been scheduled**. This ensures workers begin processing a fully populated queue rather than spinning on an empty one during engine initialization.

- Tasks can be enqueued via `scheduleTask()` or `scheduleTaskFirst()` at any time before or after `start()`.
- Worker threads are launched only when `start()` is explicitly called.
- In `main.cpp`, `start()` is called immediately after the last `scheduleTaskFirst("initial-sync", …)` call in each execution branch.

### CPU Priority

The scheduler sets per-thread Linux nice values around task execution using `setpriority(PRIO_PROCESS, 0, niceValue)`. Values are clamped to `[-20, 19]`. Priority is restored to `0` after each task completes.

## Directory Structure

```
scheduler/
├── CMakeLists.txt
├── interface/scheduler/
│   └── ischeduler.hpp          # IScheduler interface + TaskConfig
├── include/scheduler/
│   └── scheduler.hpp           # Scheduler, TaskQueue, ScheduledTask
├── src/
│   └── scheduler.cpp           # Scheduler implementation
└── test/
    ├── mocks/scheduler/
    │   └── mockScheduler.hpp   # GMock for IScheduler
    └── src/component/
        └── scheduler_test.cpp  # Component tests
```

## Public Interface

### `IScheduler` (interface/scheduler/ischeduler.hpp)

| Method | Signature | Description |
|--------|-----------|-------------|
| `scheduleTask` | `(string_view name, TaskConfig&& config) → void` | Schedule a new task; throws if name is duplicate or function is null |
| `scheduleTaskFirst` | `(string_view name, TaskConfig&& config) → void` | Schedule a task forcing it to the front of the queue (executes before all other pending tasks); same validation as `scheduleTask` |
| `removeTask` | `(string_view name) → void` | Remove a task by name; no-op if not found |
| `getActiveTasksCount` | `() → size_t` | Number of tasks currently registered |
| `getThreadCount` | `() → size_t` | Number of worker threads (constant after construction) |

### `Scheduler` (include/scheduler/scheduler.hpp)

Extends `IScheduler` with lifecycle control:

| Method | Description |
|--------|-------------|
| `Scheduler(int threads = 1)` | Create a stopped scheduler with the given thread count (min 1) |
| `start()` | Launch worker threads; idempotent |
| `stop()` | Gracefully shut down: signal queue, join all workers, clear tasks; idempotent |
| `isRunning()` | Check if the scheduler is active |

## Implementation Details

### Thread Safety

The implementation uses two separate synchronization mechanisms:

| Resource | Protection | Purpose |
|----------|-----------|---------|
| `m_tasks` (task map) | `std::mutex m_tasksMutex` | Guards the name → `ScheduledTask` lookup map |
| `m_taskQueue` | Internal mutex + condition variable | Guards the sorted execution queue |
| `m_running` | `std::atomic<bool>` | Lock-free scheduler state flag |

### Task Lifecycle

```
scheduleTask()
    ├── Validate: taskFunction != null, name is unique
    ├── Create ScheduledTask (compute nextRun based on interval / runImmediately)
    ├── Insert into m_tasks map
    └── Push TaskItem into m_taskQueue (sorted by nextRun)

scheduleTaskFirst()
    ├── Validate: taskFunction != null, name is unique
    ├── Create ScheduledTask
    ├── Insert into m_tasks map
    └── Push TaskItem with nextRun = time_point{} (epoch)
            → lower_bound returns begin() → inserted at position 0
            → always executes before any other queued task

workerThread()
    ├── pop() from m_taskQueue (blocks)
    ├── nextRun > now? → push back + sleep 100ms
    ├── task removed? → skip
    ├── executeTask() (with priority)
    └── recurring? → update nextRun, push back
        one-time? → erase from m_tasks
```

#### `scheduleTaskFirst` ordering guarantee

Multiple calls before `start()` are ordered such that the **last call executes first**. Each new task with `nextRun = epoch` is inserted at position 0 (before any existing epoch-time task), so the most-recently registered task is always at the head of the queue when workers start.

### Error Handling

- Task functions are executed inside a `try/catch` block; exceptions are logged as warnings but do not crash the scheduler or affect other tasks.
- `scheduleTask` and `scheduleTaskFirst` throw `std::invalid_argument` for null functions and `std::runtime_error` for duplicate names.
- Worker thread names are set to `"sched-worker"` via `base::process::setThreadName`.

## CMake Targets

| Target | Alias | Type | Description |
|--------|-------|------|-------------|
| `scheduler_ischeduler` | `scheduler::ischeduler` | INTERFACE | Public interface (`IScheduler`, `TaskConfig`) |
| `scheduler_scheduler` | `scheduler::scheduler` | STATIC | Full implementation |
| `scheduler_mocks` | `scheduler::mocks` | INTERFACE | GMock for `IScheduler` |
| `scheduler_ctest` | — | EXECUTABLE | Component tests |

**Dependency graph:**

```
scheduler::ischeduler  ←── base
        ↑
        ├──── scheduler::scheduler  ←── base
        └──── scheduler::mocks  ←── GTest::gmock
```

## Testing

### Component Tests (scheduler_test.cpp)

Use a real 2-thread scheduler with atomic counters and short sleeps to verify behavior:

| Test | Validates |
|------|-----------|
| `SchedulerInitialization` | Default state: stopped, 0 tasks, correct thread count |
| `StartStopScheduler` | Lifecycle transitions |
| `ScheduleOneTimeTask` | Executes once, auto-removed from task map |
| `ScheduleRecurringTask` | Executes at least once within interval window |
| `RunImmediately_ExecutesOnFirstCycle` | `runImmediately=true` fires before one full interval elapses |
| `RunImmediately_ThenRecurresAtInterval` | Immediate first fire, then normal recurring cadence, task not removed |
| `RunImmediately_NoEffectOnOneTimeTask` | `runImmediately=true` on one-time task: runs once, removed, no double execution |
| `ScheduleTaskFirst_ExecutesBeforeOtherPendingTasks` | Task registered via `scheduleTaskFirst` runs before a previously registered one-time task |
| `ScheduleTaskFirst_LastCallIsFirst` | Second `scheduleTaskFirst` call executes before first call |
| `RemoveTask` | Task removed before execution does not fire |
| `MultipleTasks` | Mix of one-time + recurring tasks coexist |
| `TaskPriority` | Tasks with different CPU priorities all execute |
| `TaskExecutionOrder` | FIFO ordering for same-time one-time tasks |
| `TaskQueueOrdering` | Shorter-interval recurring tasks execute before longer ones |

## Consumers

The scheduler is instantiated once in `main.cpp` as `std::make_shared<scheduler::Scheduler>()`. Tasks are registered during engine initialization; `start()` is called only after the last task has been scheduled.

| Task Name | Interval | Method | Consumer | Purpose |
|-----------|----------|--------|----------|---------|
| `cm-sync-task` | `CM_SYNC_INTERVAL` | `scheduleTask` | Content Manager | Synchronizes content manager data |
| `ioc-sync-task` | `IOC_SYNC_INTERVAL` | `scheduleTask` | IOC Sync | Indicator of Compromise synchronization |
| `geo-sync-task` | `GEO_SYNC_INTERVAL` | `scheduleTask` | Geo Manager | Updates GeoIP databases (GeoLite2-City, GeoLite2-ASN) |
| `remote-conf-sync` | `REMOTE_CONF_SYNC_INTERVAL` | `scheduleTask` | Remote Config | Remote configuration synchronization |
| `MetricsLogger` | `METRICS_LOG_INTERVAL` | `scheduleTask` | Metrics | Writes all metrics to the stream logger |
| `initial-sync` | one-time | `scheduleTaskFirst` | main.cpp | Triggers cm/ioc/geo/remote-conf synchronization at startup; guaranteed to run before all other pending tasks |
| *(dynamic)* | one-time | `scheduleTask` | streamlog | Gzip compression of rotated log files |
| *(dynamic)* | one-time | `scheduleTask` | api/ioccrud | On-demand IOC sync triggered via API |

### Injection Patterns

- **streamlog**: Stores `std::weak_ptr<scheduler::IScheduler>` and dynamically schedules one-time compression tasks when log files rotate.
- **api/ioccrud**: Receives the scheduler as a parameter in API route handlers for managing IOC sync operations.
- **main.cpp**: Calls `scheduleTask()` for all periodic tasks during initialization, then `scheduleTaskFirst()` for the one-time `initial-sync` startup task. `start()` is deferred until after all tasks are registered.
