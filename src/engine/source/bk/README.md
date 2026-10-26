# `bk` Module — Expression Execution Backend

## Overview

The `bk` (**b**ac**k**end) module is the execution engine of the Wazuh engine. Its responsibility is to take a **logical expression tree** (`base::Expression`) —which describes an event-processing pipeline— and turn it into a **concrete execution graph** that processes events (`base::Event`) efficiently.

In simple terms: other modules (such as the `builder`) construct a tree that *describes* what operations to perform and in what order. The `bk` module takes that description and materializes it into an executable pipeline, receives JSON events, runs them through the pipeline, and returns the result.

## Key Concepts

### Expression

Defined in `base/expression.hpp`. It is a tree of nodes (`base::Expression = std::shared_ptr<Formula>`) that describes logical operations without implementing execution. Each node is one of the following types:

| Type | Class | Execution Semantics |
|------|-------|---------------------|
| **Term** | `base::Term<EngineOp>` | Leaf node. Contains an `EngineOp` function (`Event → Result<Event>`) that performs a concrete operation on the event (evaluate a condition, transform a field, etc.). |
| **And** | `base::And` | Executes its operands sequentially. If any operand fails (returns `false`), execution stops and returns `false` (short-circuit). |
| **Or** | `base::Or` | Executes its operands sequentially while they fail. If any operand succeeds (returns `true`), execution stops and returns `true` (short-circuit). |
| **Chain** | `base::Chain` | Executes all its operands sequentially **regardless of each one's result**. Always returns `true`. |
| **Implication** | `base::Implication` | Has exactly 2 operands: `condition` and `consequence`. If the condition is `true`, the consequence is executed and `true` is returned whatever the consequence's result. If the condition is `false`, the consequence is not executed and `false` is returned. |
| **Broadcast** | `base::Broadcast` | Executes all its operands on the same event regardless of each one's result. Always returns `true`. `bk::rx` runs them in operand order, exactly like Chain; `bk::taskf` forks them as independent branches of the DAG, so their order is not guaranteed (its executor has a single worker, so they never run concurrently). |

### Event

```cpp
using Event = std::shared_ptr<json::Json>;
```

An event is an in-memory JSON document. It is the data unit that flows through the pipeline. Terms read and/or modify it.

### EngineOp

```cpp
using EngineOp = std::function<result::Result<Event>(Event)>;
```

The atomic processing function. It receives an event, processes it, and returns a `Result<Event>` that encapsulates:
- The event (possibly modified)
- A trace message (`trace`)
- A success/failure status (`bool`)

### Controller

The central piece of the `bk` module. A `Controller`:
1. Receives an `Expression`, a set of traceable node names and an optional end callback in its constructor
2. Internally converts it into an execution graph (observable pipeline or task DAG)
3. Exposes the `ingest(Event)` / `ingestGet(Event)` methods to process events; both block until the event has gone through the whole graph and neither is thread-safe (`interface/bk/icontroller.hpp`)
4. Invokes the end callback, when one was given, once per processed event
5. Supports tracing: allows subscribing to specific tree nodes to observe their results

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│          Consumer (router::EnvironmentBuilder)              │
│  Builds the Expression with the Builder and passes it to bk │
└────────────────────────┬────────────────────────────────────┘
                         │ Expression + traceables
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              bk::IControllerMaker (Factory)                 │
│  Creates a concrete IController from an Expression          │
└────────────────────────┬────────────────────────────────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
┌──────────────────────┐ ┌──────────────────────┐
│   bk::rx::Controller │ │ bk::taskf::Controller│
│   (RxCpp impl.)      │ │ (Taskflow impl.)     │
│                      │ │                      │
│  ExprBuilder → Obs.  │ │ ExprBuilder → DAG    │
│  RxCpp pipeline      │ │ Taskflow tasks       │
│                      │ │                      │
│  Tracer (pub/sub)    │ │ Tracer (pub/sub)     │
└──────────────────────┘ └──────────────────────┘
```

The module provides **two interchangeable implementations** of the same contract (`IController`):

1. **`bk::rx::Controller`** — Based on [RxCpp](https://github.com/ReactiveX/RxCpp): builds a reactive observable pipeline.
2. **`bk::taskf::Controller`** — Based on [Taskflow](https://github.com/taskflow/taskflow): builds a task DAG executed via a `tf::Executor`.

Both implementations:
- Accept the same `Expression`
- Produce the same result for a given event
- Support the same tracing system
- Fulfill the `IController` interface

Only `bk::rx` is used by the engine: `main.cpp` hands the orchestrator a `bk::rx::ControllerMaker`, and the
`wazuh-engine` target links `bk::rx` while its `bk::taskf` line is commented out
(`src/engine/CMakeLists.txt`). Only the component tests (`bk_ctest`) link `bk::taskf`.

## Directory Structure

```
bk/
├── CMakeLists.txt                          # Build: defines targets bk::ibk, bk::rx, bk::taskf
├── interface/
│   └── bk/
│       └── icontroller.hpp                 # Public interface: IController, IControllerMaker
├── include/
│   └── bk/
│       ├── rx/
│       │   └── controller.hpp              # Public header for the RxCpp implementation
│       └── taskf/
│           └── controller.hpp              # Public header for the Taskflow implementation
├── src/
│   ├── rx/                                 # RxCpp implementation (internal detail)
│   │   ├── controller.cpp                  # rx Controller construction
│   │   ├── exprBuilder.hpp                 # Converts Expression → observable pipeline
│   │   └── tracer.hpp                      # Tracing system (pub/sub) for rx
│   └── taskf/                              # Taskflow implementation (internal detail)
│       ├── controller.cpp                  # taskf Controller construction
│       ├── exprBuilder.hpp                 # Converts Expression → task DAG
│       └── tracer.hpp                      # Tracing system (pub/sub) for taskf
└── test/
    ├── mocks/
    │   └── bk/
    │       └── mockController.hpp          # IController mock for external module tests
    └── src/
        └── component/
            ├── bk_test.hpp                 # Test utilities: expression generation and validation
            └── bk_test.cpp                 # Parameterized component tests (both backends)
```

## Public Interface

### `IController`

Main backend contract. Defined in `interface/bk/icontroller.hpp`.

```cpp
class IController {
    // Process an event, discarding the result (blocking, not thread-safe)
    virtual void ingest(base::Event&& event) = 0;

    // Process an event and return the result (blocking, not thread-safe)
    virtual base::Event ingestGet(base::Event&& event) = 0;

    // Check whether the backend is available
    virtual bool isAvailable() const = 0;

    // Start / stop the backend
    virtual void start() = 0;
    virtual void stop() = 0;

    // Get the execution graph in DOT format (Graphviz)
    virtual std::string printGraph() const = 0;

    // --- Tracing System ---
    // Get the names of traceable nodes
    virtual const std::unordered_set<std::string>& getTraceables() const = 0;

    // Subscribe to a traceable node (receive its trace and result)
    virtual base::RespOrError<Subscription> subscribe(const std::string& traceable,
                                                       const Subscriber& subscriber) = 0;

    // Unsubscribe
    virtual void unsubscribe(const std::string& traceable, Subscription subscription) = 0;
    virtual void unsubscribeAll() = 0;
};
```

How the two implementations fill the contract:

| Method | `bk::rx::Controller` | `bk::taskf::Controller` |
|---|---|---|
| `ingest` / `ingestGet` | Pushes the event into the RxCpp subject; once `stop()` has completed the subject, `ingest` drops the event and `ingestGet` returns it unprocessed | Stores the event in `m_event` and runs the Taskflow graph, waiting for it |
| `isAvailable` | Always `true` | Always `true` |
| `start` | No-op | No-op |
| `stop` | Completes the subject (also called by the destructor); the controller processes nothing afterwards | No-op |
| `printGraph` | Returns the placeholder string `"TODO"` | `tf::Taskflow::dump()` (DOT) |
| `subscribe` | `base::Error{"Traceable not found"}` for a name with no tracer | Same |
| `unsubscribe` | Unknown traceable or subscription is ignored | Same |

### `IControllerMaker`

Factory that creates `IController` instances; `bk::rx::ControllerMaker` and `bk::taskf::ControllerMaker` construct
the matching `Controller`:

```cpp
class IControllerMaker {
    virtual std::shared_ptr<IController> create(
        const base::Expression& expression,
        const std::unordered_set<std::string>& traceables,
        const std::function<void()>& endCallback) = 0;

    // Non-virtual convenience overload: create(expression, traceables, nullptr)
    std::shared_ptr<IController> create(const base::Expression& expression,
                                        const std::unordered_set<std::string>& traceables);
};
```

### Auxiliary Types

```cpp
using Subscriber = std::function<void(const std::string&, bool)>;  // Tracing callback (message, success)
using Subscription = std::size_t;                                   // Subscription ID
```

## Execution Flow

### 1. Construction

```
Expression (logical tree)
    │
    ▼
Controller::Controller(expression, traceables, endCallback)
    │
    ├── ExprBuilder.build(expression, ...)
    │       │
    │       ├── Recursively traverses the Expression tree
    │       ├── For each Term node: extracts the EngineOp and wraps it in a task/observable
    │       ├── For each Operation node: connects tasks/observables according to semantics
    │       │   (And → sequential with short-circuit, Or → sequential with inverse short-circuit, etc.)
    │       └── For traceable nodes: creates a Tracer and connects the publisher
    │
    └── Result: execution graph ready to process events
```

A null node throws `std::runtime_error("Expression is null")`, and an unknown node type
`"Unsupported operation type"` / `"Unsupported expression type"`, from the constructor.

### 2. Event Processing

```
JSON event (base::Event)
    │
    ▼
controller.ingestGet(event)
    │
    ├── [rx]    → pushes the event into the RxCpp subject → the observable pipeline processes it
    ├── [taskf] → assigns the event to the shared m_event → runs the DAG with executor.run()
    │
    ▼
processed event (modified by the Terms that were executed)
```

### 3. Tracing

The tracing system allows observing the execution of specific tree nodes:

```
1. When constructing the Controller, a set of "traceables" (node names) is provided
2. The ExprBuilder creates a Tracer for each node whose name is in that set
3. An external consumer calls controller.subscribe("node_name", callback)
4. Only Term nodes publish: every Term built beneath a traceable node invokes that node's subscribers
   with (trace_message, success/failure) after it runs
5. The router passes the policy's asset names as traceables; the tester uses them to report
   per-asset traces
```

The publisher is carried in the builders' shared `BuildParams`: a traceable node replaces it for its own subtree,
and the previous one is restored when the builder leaves that node, so the sibling nodes built after a traceable
subtree keep publishing to their own ancestor's tracer (`src/rx/exprBuilder.hpp`, `src/taskf/exprBuilder.hpp`).

## Implementation: RxCpp (`bk::rx`)

The RxCpp implementation builds a pipeline of chained **observables**:

- **Term**: `input.map(fn)` — transforms the event with the `EngineOp`. An exception thrown by the operation is
  caught: it logs a warning (`[BK::pipeline] Unexpected error processing term: …`) and turns the result into a
  failure with the trace `[<name>] -> Failure: operation throw exception.`
- **And**: `input.publish().ref_count()` → chains operands with `.filter(success)` between them
- **Or**: `input.publish().ref_count()` → chains operands with `.filter(failure)` between them
- **Chain/Broadcast**: `input.publish().ref_count()` → chains all operands in order, then maps the result status to `true`
- **Implication**: `input.publish().ref_count()` → condition `.filter(success)` → consequence; the result status is set to the condition's

The event circulates wrapped in `RxEvent = shared_ptr<Result<Event>>` to maintain a shared reference across pipeline
branches. The rx controller does not keep the source `Expression` alive once built (pinned by
`RxControllerTest.DoesNotRetainSourceExpression`).

## Implementation: Taskflow (`bk::taskf`)

The Taskflow implementation builds a **DAG (Directed Acyclic Graph)** of tasks:

Each node type is modeled with an `ITask` class that exposes:
- `input()`: the entry `tf::Task`
- `on(success, failure)`: connects the output to success/failure tasks

| Type | Class | Strategy |
|------|-------|----------|
| Term | `TaskTerm` | A single task that executes the `EngineOp`. Branches to `success` or `failure` based on result. |
| And | `TaskAnd` | Chains steps: each success goes to the next, each failure jumps to global `failure`. |
| Or | `TaskOr` | Chains steps: each success jumps to global `success`, each failure goes to the next. |
| Chain | `TaskChain` | Chains steps: each step goes to the next regardless of result. |
| Broadcast | `TaskBroadcast` | Forks input to all steps, converges at output. |
| Implication | `TaskImplication` | Condition → [success] → consequence; [failure] → direct output. |

The event is a `base::Event` stored as a `Controller` member (`m_event`), shared across all tasks via a `void*`
pointer. The graph runs on a `tf::Executor` with a single worker, and ends in an `output` task that runs the end
callback when one was given. As in `bk::rx`, an exception thrown by a Term's operation is caught, logged as a
warning and turned into a failure with the trace `[<name>] -> Failure: operation throw exception.`

## Usage from the Router

The `router` module is the primary consumer of `bk`. The typical flow is:

```cpp
// 1. The router's EnvironmentBuilder holds an IControllerMaker
//    (main.cpp passes a bk::rx::ControllerMaker through router::Orchestrator::Options)

// 2. The Builder constructs an Expression from a policy
auto policy = builder->buildPolicy(namespaceId, isTestMode);

// 3. The Controller is created with the Expression and asset names as traceables
auto controller = m_controllerMaker->create(policy->expression(), assetNames);

// 4. The Controller is injected into an Environment
auto env = std::make_unique<Environment>(std::move(controller), std::move(hash));

// 5a. Production: Router::ingest feeds each enabled environment, discarding the result
env->ingest(std::move(event));

// 5b. Test sessions (router/src/tester.cpp): the processed event is returned
result->event() = entry.controller()->ingestGet(std::move(event));
```

Source: `router/src/environmentBuilder.hpp` (`makeController`), `router/src/router.cpp`, `router/src/tester.cpp`.

## CMake Targets

| Target | Alias | Type | Description |
|--------|-------|------|-------------|
| `bk_ibk` | `bk::ibk` | INTERFACE | Interface only (`IController`, `IControllerMaker`). Depends on `base`. |
| `bk_taskf` | `bk::taskf` | STATIC | Taskflow implementation. Depends on `Taskflow::Taskflow` and `bk::ibk`. |
| `bk_rx` | `bk::rx` | STATIC | RxCpp implementation. Depends on `RxCpp::RxCpp` and `bk::ibk`. |
| `bk_mocks` | `bk::mocks` | INTERFACE | GMock mocks for external testing. Depends on `GTest::gmock` and `bk::ibk`. |
| `bk_ctest` | — | EXECUTABLE | Component tests (links both backends). |

`bk_mocks` and `bk_ctest` exist only when `ENGINE_BUILD_TEST` is on.

## Operation Semantics (Truth Tables)

### And
```
[T, T, T, T] → executes all → true
[T, T, F, T] → executes up to F, stops → false  (t3 and t4 are NOT executed)
[F, ...]     → stops immediately → false
```

### Or
```
[F, F, F, F] → executes all → false
[F, F, T, F] → executes up to T, stops → true  (t3 and t4 are NOT executed)
[T, ...]     → stops immediately → true
```

### Chain
```
[T, F, T, F] → executes all → true  (individual results do not matter)
[F, F, F, F] → executes all → true
```

### Broadcast
```
[T, F, T, F] → executes all (rx: in order; taskf: order not guaranteed) → true
```

### Implication
```
cond=T, imp=T → executes both → true  (result = condition result)
cond=T, imp=F → executes both → true  (result = condition result, not the consequence's)
cond=F, imp=* → executes condition only → false  (consequence is NOT executed)
```

## Testing

Tests are located in `test/src/component/bk_test.cpp`:

- `BK/PipelineTest` — parameterized tests that **verify both implementations** (rx and taskf) with the same
  expressions and expected results (`TfProcessEvent`, `RxProcessEvent`). Its `TfProcessTraces` and
  `RxProcessTraces` cases are `GTEST_SKIP()` placeholders.
- `BKTraceTest` — subscribe, unknown traceable, multiple subscribers and unsubscribe, on both backends; plus two
  rx-only cases pinning that Chain forces success and runs the operand after a failed one.
- `RxControllerTest.DoesNotRetainSourceExpression`.

### Test Structure

1. An `Expression` is built using helpers (`build::term`, `And::create`, etc.)
2. The `getTestExpression()` function (`bk_test.hpp`) replaces every Term's `EngineOp` with a test function: a Term named `<NAME>:SUCCESS|FAILURE` writes that boolean into the event at a path built from its ancestors' names and returns success or failure accordingly
3. A `Controller` is created with the expression
4. An empty event is ingested
5. The resulting event is verified to contain exactly the expected fields, in the correct order

### Running Tests

Built only with engine tests enabled (`make -C src TARGET=manager ENGINE_TEST=y`):

```bash
src/build/engine/source/bk/bk_ctest
ctest --test-dir src/build/engine -R 'PipelineTest|BKTraceTest|RxControllerTest'
```

Test coverage includes:
- Basic individual operations (Term, And, Or, Chain, Implication, Broadcast)
- Operation compositions (Broadcast of And, Chain of Implication, Implication of Or, etc.)
- Correct short-circuit behavior (And stops on failure, Or stops on success)
- Implication does not execute the consequence if the condition fails

## Relevant Design Decisions

1. **Dual implementation**: Allows comparing and choosing between a reactive model (RxCpp) and a task-graph-based model (Taskflow). Tests validate that both produce identical results. The engine currently ships the RxCpp backend only (see [Architecture](#architecture)).

2. **Expression as description, not execution**: The `Expression` is an immutable tree that describes *what* to do. The `bk` module decides *how* to execute it. This decouples rule definition logic from the execution strategy.

3. **Tracing as pub/sub**: The tracing system uses a thread-safe publisher/subscriber pattern with `shared_mutex`, allowing external observers to subscribe/unsubscribe without affecting execution.

4. **Shared event by reference**: In the Taskflow implementation, the event is a Controller member shared across all tasks via pointer. In RxCpp, the event is wrapped in a `shared_ptr<Result<Event>>` to share it across pipeline branches.

5. **Factory pattern for decoupling**: `IControllerMaker` allows the `Router` to create controllers without knowing the concrete implementation, facilitating testing with mocks and eventual backend swapping.
