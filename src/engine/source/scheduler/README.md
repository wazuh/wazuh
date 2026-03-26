# Scheduler Module

## Overview

The **scheduler** module provides a multi-threaded, priority-aware task scheduling system for the Wazuh engine. It manages the execution of periodic and one-time background tasks using a configurable thread pool and a sorted, thread-safe priority queue.

Tasks are identified by unique names and configured with an execution interval, CPU priority (nice value), and a callable function. The scheduler handles task lifecycle—including automatic removal of one-time tasks and rescheduling of recurring ones—while guaranteeing thread safety across all operations.

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                     Consumers                          │
│  (main.cpp, streamlog, api/ioccrud)                    │
│                                                        │
│   scheduleTask("task-name", {interval, prio, fn})      │
└──────────────────────┬─────────────────────────────────┘
                       │
              ┌────────▼────────┐
              │   IScheduler     │  (interface)
              │  scheduleTask()  │
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
| `CPUPriority` | `int` | Linux nice value (`-20` highest to `19` lowest). `0` = default |
| `timeout` | `int` | Reserved for future use (currently unused) |
| `taskFunction` | `std::function<void()>` | The callable to execute |

### One-Time vs Recurring Tasks

- **One-time** (`interval = 0`): Scheduled for immediate execution. Automatically removed from the task map after completion.
- **Recurring** (`interval > 0`): First execution occurs after `interval` seconds. After each execution, the task is rescheduled with a new `nextRun` time = `now + interval`.

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
    ├── Create ScheduledTask (compute nextRun)
    ├── Insert into m_tasks map
    └── Push TaskItem into m_taskQueue

workerThread()
    ├── pop() from m_taskQueue (blocks)
    ├── nextRun > now? → push back + sleep 100ms
    ├── task removed? → skip
    ├── executeTask() (with priority)
    └── recurring? → update nextRun, push back
        one-time? → erase from m_tasks
```

### Error Handling

- Task functions are executed inside a `try/catch` block; exceptions are logged as warnings but do not crash the scheduler or affect other tasks.
- `scheduleTask` throws `std::invalid_argument` for null functions and `std::runtime_error` for duplicate names.
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
| `RemoveTask` | Task removed before execution does not fire |
| `MultipleTasks` | Mix of one-time + recurring tasks coexist |
| `TaskPriority` | Tasks with different CPU priorities all execute |
| `TaskExecutionOrder` | FIFO ordering for same-time one-time tasks |
| `TaskQueueOrdering` | Shorter-interval recurring tasks execute before longer ones |

## Consumers

The scheduler is instantiated once in `main.cpp` as `std::make_shared<scheduler::Scheduler>()`, started, and injected into consumers:

| Task Name | Interval | Consumer | Purpose |
|-----------|----------|----------|---------|
| `cm-sync-task` | `CM_SYNC_INTERVAL` | Content Manager | Synchronizes content manager data |
| `ioc-sync-task` | `IOC_SYNC_INTERVAL` | IOC Sync | Indicator of Compromise synchronization |
| `geo-sync-task` | `GEO_SYNC_INTERVAL` | Geo Manager | Updates GeoIP databases (GeoLite2-City, GeoLite2-ASN) |
| `remote-conf-sync` | `REMOTE_CONF_SYNC_INTERVAL` | Remote Config | Remote configuration synchronization |
| *(dynamic)* | One-time | streamlog | Gzip compression of rotated log files |

### Injection Patterns

- **streamlog**: Stores `std::weak_ptr<scheduler::IScheduler>` and dynamically schedules one-time compression tasks when log files rotate.
- **api/ioccrud**: Receives the scheduler as a parameter in API route handlers for managing IOC sync operations.
- **main.cpp**: Directly calls `scheduler->scheduleTask()` for all core periodic sync tasks.
