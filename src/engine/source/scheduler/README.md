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
│   scheduleTaskFirst("name")                            │
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
              │  │ worker 1 │ │ worker 2 │ │ worker N │ │
              │  └──────────┘ └──────────┘ └──────────┘ │
              │       ↕             ↕             ↕      │
              │        pop() → execute → reschedule      │
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
| `nextInterval` | `std::function<std::size_t()>` | Optional. Recurring tasks only: called after each run; a non-zero result replaces `interval` for the next run only (e.g. a shorter retry while a task's work is incomplete). If it throws, a warning is logged and `interval` applies |

Fields must be specified in the order listed above when using C++20 designated initializers.

### One-Time vs Recurring Tasks

- **One-time** (`interval = 0`): Scheduled for immediate execution (`nextRun = now()`). Automatically removed from the task map after completion. `runImmediately` has no additional effect.
- **Recurring** (`interval > 0`, `runImmediately = false`): First execution occurs after `interval` seconds (`nextRun = now() + interval`). After each execution, rescheduled with `nextRun = now() + interval`, or `now() + nextInterval()` when `nextInterval` is set and returns a non-zero value.
- **Recurring with immediate first run** (`interval > 0`, `runImmediately = true`): First execution is immediate (`nextRun = now()`). Subsequent executions recur at `interval` seconds.

### Run-now tasks (`TriggerableTask`)

`interface/scheduler/triggerableTask.hpp` (header-only) wraps a recurring task that can also be run
on request. `start()` registers it with its interval, first run one interval away (a no-op with
interval 0); `start(true)` makes that first recurring run immediate and moves it to the front of the
queue (with interval 0 it triggers a run); `trigger()` never blocks and never throws. An optional
`nextInterval` goes to the recurring task only: request runs are one-time and do not move its cadence.

A request that arrives while the work is running sets a rerun flag, and the work runs once more as
soon as it finishes. Any other request schedules a one-time run of its own, `<name>/request-<n>`,
and moves it to the front of the queue; requests made before that run starts share it. A request
never depends on the recurring task being in the queue — it is not, between a run returning and the
scheduler re-queuing it — so none is lost. Runs never overlap: an execution that finds another one
running leaves the work to it, as a rerun. Every request is answered by a run that started after it. `cm-sync-task` and `ioc-sync-task` are
`TriggerableTask`s, triggered by `POST /content/ruleset/update` and `POST /content/ioc/sync`.

### Task Queue (`TaskQueue`)

An internal thread-safe sorted list that orders tasks by their `nextRun` time (earliest first). Features:

- **Blocking `pop()`**: Worker threads block on a condition variable until the front task is due (`wait_until` its `nextRun`), a push or reprioritization wakes them, or shutdown is signaled. A task is returned only once it is due.
- **Sorted insertion**: New tasks are inserted at the correct position via `std::lower_bound` to maintain chronological order.
- **Deep copy semantics**: Items returned by `pop()` are copied to prevent data races between the queue and the worker that processes the item.
- **Reprioritization**: `reprioritizeToFront(name)` moves a queued task to the head with `nextRun = time_point{}` (epoch), so it is due immediately.
- **Graceful shutdown**: `shutdown()` sets a flag and notifies all waiting threads; later pushes are ignored.

### Thread Pool

The scheduler creates a fixed number of worker threads (configurable, minimum 2). Each worker runs a loop:

1. `pop()` a due task from the queue (blocks until one is due)
2. Verify the task still exists in the task map (it may have been removed)
3. If `CPUPriority != 0`, set the thread's nice value via `setpriority(2)`
4. Execute the task function (catching exceptions)
5. If it was changed, restore the nice value to `0`
6. Reschedule (recurring, only if still registered) or remove (one-time) the task

### Deferred Start

The scheduler is designed to be **created before tasks are registered** and **started only after all tasks have been scheduled**. This ensures workers begin processing a fully populated queue rather than spinning on an empty one during engine initialization.

- Tasks can be enqueued via `scheduleTask()` (and moved to the front via `scheduleTaskFirst()`) at any time before or after `start()`.
- Worker threads are launched only when `start()` is explicitly called.
- In `main.cpp`, with event processing enabled, `start()` is called right after `cm-sync-task` is started with `start(true)`, which moves its first run to the front of the queue; with it disabled, `start()` is called without any reprioritization.

### CPU Priority

The scheduler sets per-thread Linux nice values around task execution using `setpriority(PRIO_PROCESS, 0, niceValue)` when `CPUPriority != 0`. Values are clamped to `[-20, 19]`; a failure is logged as a warning. Priority is then restored to `0` after the task completes. Every task registered today uses `0`.

## Directory Structure

```
scheduler/
├── CMakeLists.txt
├── interface/scheduler/
│   ├── ischeduler.hpp          # IScheduler interface + TaskConfig
│   └── triggerableTask.hpp     # TriggerableTask (run on interval and on request)
├── include/scheduler/
│   └── scheduler.hpp           # Scheduler, TaskQueue, ScheduledTask (TaskQueue is header-only)
├── src/
│   └── scheduler.cpp           # Scheduler implementation
└── test/
    ├── mocks/scheduler/
    │   └── mockScheduler.hpp   # GMock for IScheduler
    └── src/
        ├── component/scheduler_test.cpp     # Component tests
        └── unit/triggerableTask_test.cpp    # TriggerableTask over a mocked IScheduler
```

## Public Interface

### `IScheduler` (interface/scheduler/ischeduler.hpp)

| Method | Signature | Description |
|--------|-----------|-------------|
| `scheduleTask` | `(string_view name, TaskConfig&& config) → void` | Schedule a new task; throws if name is duplicate or function is null |
| `scheduleTaskFirst` | `(string_view name) → void` | Move an already registered task to the front of the queue with an immediate `nextRun`, so it runs before all other pending tasks; throws `std::invalid_argument` if the name is not registered; logs a warning and does nothing if the task is executing (not in the queue) |
| `removeTask` | `(string_view name) → void` | Remove a task by name from the task map (its queue item is skipped when popped; a running recurring task is not rescheduled); no-op if not found |
| `getActiveTasksCount` | `() → size_t` | Number of tasks currently registered |
| `getThreadCount` | `() → size_t` | Number of worker threads (constant after construction) |

### `Scheduler` (include/scheduler/scheduler.hpp)

Extends `IScheduler` with lifecycle control:

| Method | Description |
|--------|-------------|
| `Scheduler(int threads = 2)` | Create a stopped scheduler with `max(2, threads)` worker threads |
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

scheduleTaskFirst(name)
    ├── Validate: name is registered in m_tasks (else std::invalid_argument)
    └── m_taskQueue.reprioritizeToFront(name)
            → item removed from its position, nextRun = time_point{} (epoch)
            → pushed to the front and a worker is notified
            → not in queue (executing)? → warning, no-op

workerThread()
    ├── pop() from m_taskQueue (blocks until the front task is due)
    ├── task removed? → skip
    ├── executeTask() (with priority)
    └── recurring and still registered? → nextRun = now + (nextInterval() || interval), push back
        one-time? → erase from m_tasks
```

#### `scheduleTaskFirst` ordering guarantee

Multiple calls before `start()` are ordered such that the **last call executes first**: each call moves its task to position 0, ahead of any task reprioritized earlier. Called while running, the reprioritized task is due immediately and wakes a worker.

### Error Handling

- Task functions are executed inside a `try/catch` block; exceptions are logged as warnings but do not crash the scheduler or affect other tasks.
- `scheduleTask` throws `std::invalid_argument` for a null function and `std::runtime_error` for a duplicate name; `scheduleTaskFirst` throws `std::invalid_argument` for an unregistered name.
- A throwing `nextInterval` is logged as a warning and the regular `interval` applies.
- `stop()` (also run by the destructor) shuts the queue down, joins the workers, and clears both the queue and the task map.
- Worker thread names are set to `"sched-worker"` via `base::process::setThreadName`.

## CMake Targets

| Target | Alias | Type | Description |
|--------|-------|------|-------------|
| `scheduler_ischeduler` | `scheduler::ischeduler` | INTERFACE | Public interface (`IScheduler`, `TaskConfig`) |
| `scheduler_scheduler` | `scheduler::scheduler` | STATIC | Full implementation |
| `scheduler_mocks` | `scheduler::mocks` | INTERFACE | GMock for `IScheduler` (test builds only) |
| `scheduler_ctest` | — | EXECUTABLE | Component tests (test builds only) |
| `scheduler_utest` | — | EXECUTABLE | `TriggerableTask` unit tests (test builds only) |

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
| `NextInterval_OverridesIntervalForNextRun` | A non-zero `nextInterval` result reschedules sooner than `interval`; `0` falls back to `interval` |
| `NextInterval_ThrowFallsBackToInterval` | A throwing `nextInterval` falls back to `interval` and the task keeps running |
| `RunImmediately_NoEffectOnOneTimeTask` | `runImmediately=true` on one-time task: runs once, removed, no double execution |
| `ScheduleTaskFirst_ExecutesBeforeOtherPendingTasks` | Task registered via `scheduleTaskFirst` runs before a previously registered one-time task |
| `ScheduleTaskFirst_LastCallIsFirst` | Second `scheduleTaskFirst` call executes before first call |
| `RemoveTask` | Task removed before execution does not fire |
| `MultipleTasks` | Mix of one-time + recurring tasks coexist |
| `TaskPriority` | Tasks with different CPU priorities all execute |
| `TaskExecutionOrder` | FIFO ordering for same-time one-time tasks |
| `TaskQueueOrdering` | Shorter-interval recurring tasks execute before longer ones |
| `StartWhenAlreadyRunning`, `StartStop_Idempotent`, `StopWithoutStart`, `DestructorStopsScheduler`, `TasksClearedAfterStop` | Lifecycle idempotence and cleanup |
| `ConstructorWithZeroThreads`, `ConstructorWithNegativeThreads` | Thread count floor of 2 |
| `ScheduleTaskWithNullFunction`, `ScheduleTaskDuplicateName`, `ScheduleTask_ThrowsOnNullFunction`, `ScheduleTask_ThrowsOnDuplicateName`, `ScheduleTaskFirst_ThrowsOnUnregisteredTask` | Validation errors |
| `TaskRemovedBeforeExecution`, `RemoveTask_NoopForNonExistentTask`, `RemoveRecurringTask_WhileExecuting_DoesNotReschedule` | Removal semantics |
| `TaskThrowsStdException`, `TaskThrowsUnknownException` | Task exceptions do not stop the scheduler |
| `ScheduleTaskFirst_WhileRunning_ReprioritizesImmediately` | Reprioritization of a pending task while running |
| `ConcurrentScheduleRemove_IsThreadSafe` | Concurrent schedule/remove |

## Consumers

The scheduler is instantiated once in `main.cpp` as `std::make_shared<scheduler::Scheduler>()` (2 worker threads). Tasks are registered during engine initialization; `start()` is called only after the last task has been scheduled. Intervals come from the `analysisd.*` options in `conf.cpp` (`conf::key::*`).

| Task Name | Interval | Method | Consumer | Purpose |
|-----------|----------|--------|----------|---------|
| `cm-sync-task` | `CM_SYNC_INTERVAL`, run immediately (`CM_SYNC_RETRY_INTERVAL` via `nextInterval` while a space has no route) | `TriggerableTask` (`start(true)`) | cmsync | Expands the router worker pool, synchronizes content, reports route status; its first run is moved to the front so it runs first at startup; also triggered by the contentsync API |
| `ioc-sync-task` | `IOC_SYNC_INTERVAL` (0 = on request only); a first run is triggered at startup | `TriggerableTask` | IOC Sync | Indicator of Compromise synchronization; also triggered by the contentsync API |
| `<task>/request-<n>` | one-time | `TriggerableTask::trigger()` | contentsync API, main.cpp | A requested run of `cm-sync-task` or `ioc-sync-task`, moved to the front of the queue |
| `geo-sync-task` | `GEO_SYNC_INTERVAL`, run immediately; not registered when `0` | `scheduleTask` | Geo Manager | Updates GeoIP databases (GeoLite2-City, GeoLite2-ASN) |
| `remote-conf-sync` | `REMOTE_CONF_SYNC_INTERVAL`, run immediately | `scheduleTask` | confremote | Remote configuration synchronization |
| `clean-agent-cache` | `AGENT_METADATA_CACHE_CLEAN_INTERVAL` | `scheduleTask` | Agent metadata cache | Evicts stale cache entries |
| `CompressLog-<channel>-<file>` | one-time | `scheduleTask` | streamlog | Gzip compression of a rotated log file |
| `ioc-sync-<8 hex>` | one-time | `scheduleTask` | api/ioccrud | On-demand IOC sync triggered via API |

All but `geo-sync-task` and the dynamic tasks are registered only when event processing is enabled (`analysisd.server_enable_event_processing`).

### Injection Patterns

- **streamlog**: Stores `std::weak_ptr<scheduler::IScheduler>` and dynamically schedules one-time compression tasks when log files rotate (or, at startup, for a previous file left uncompressed).
- **api/ioccrud**: Receives the scheduler as a parameter in API route handlers for managing IOC sync operations.
- **main.cpp**: Calls `scheduleTask()` for the periodic tasks and starts the two `TriggerableTask`s during initialization: `ioc-sync-task` is triggered for a first run now, and `cm-sync-task` starts with `start(true)` last, so its first recurring run is the first to run and its `nextInterval` (the early retry) follows it. `start()` is deferred until after all tasks are registered.
