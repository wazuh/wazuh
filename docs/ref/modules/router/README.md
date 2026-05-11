# Router

The **Router** module implements the Publish-Subscribe messaging pattern for inter-module communication within Wazuh. It separates message producers (publishers) and message consumers (subscribers) by allowing them to communicate indirectly through a central `RouterFacade` singleton that acts as the message broker.

## Key Features

- **Decoupled communication**: Publishers and subscribers have no direct references to each other
- **Topic-based routing**: Messages are grouped by logical channels (topics) managed in the facade
- **Asynchronous dispatch**: Messages are processed through a thread pool (`FilterMsgDispatcher`) for non-blocking delivery
- **IPC support**: Socket-based communication for cross-process providers and subscribers (`queue/router/` endpoints)
- **Lazy provider creation**: Publishers are instantiated on-demand when the first subscriber or message arrives for a topic
- **Observer pattern**: Subscribers implement the `Observer` interface; publishers extend `Subject` to notify all attached observers

## Overview

The module is built around a `RouterFacade` singleton that manages the full lifecycle of publishers and subscribers. Publishers send messages to named topics, and subscribers register interest in those topics with a callback. The facade looks up the target publisher by topic name and dispatches messages through an async `FilterMsgDispatcher` (thread pool), which then notifies all observers attached to that publisher.

### Key Concepts

- **RouterFacade**: Singleton that acts as the message broker. Manages a map of topic → `Publisher` instances, handles registration of local and remote providers/subscribers, and routes messages by topic.
- **Publisher**: Manages a per-topic socket endpoint and a `FilterMsgDispatcher` for async message processing. Inherits from `Provider<T>` → `Subject<T>` to notify observers.
- **Subscriber**: Implements the `Observer<T>` interface with a user-provided callback invoked on each message. Registered with a publisher via the facade.
- **FilterMsgDispatcher**: Async message dispatcher (from shared utils) backed by a configurable thread pool. Supports an optional filter callback at the dispatcher level.
- **IPC Endpoints**: Remote providers and subscribers communicate via Unix domain sockets under `queue/router/`. A central subscription socket (`queue/router/subscription.sock`) handles provider registration messages.
