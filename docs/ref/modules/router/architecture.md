# Router Architecture

## Overview

The Router module is built around a central `RouterFacade` singleton that manages publishers, subscribers, and IPC socket servers. The facade coordinates the full lifecycle: initialization, message dispatch, and teardown. Providers are created lazily — a `Publisher` instance is only instantiated when the first subscriber or message arrives for a given topic.

## Component Architecture

```mermaid
graph TD
    subgraph Facade ["RouterFacade (Singleton)"]
        lookup["m_providers map\n(topic → Publisher)"]
    end

    subgraph Pub ["Publisher (one per topic)"]
        socket["SocketServer\n(queue/router/topic)"]
        dispatcher["FilterMsgDispatcher\n(thread pool)"]
        subject["Subject\n(Observer pattern)"]
    end

    lookup -->|"get by topic"| Pub
    socket -->|"receive data"| dispatcher
    dispatcher -->|"async dispatch"| subject

    subject -->|"notify"| sub1["Subscriber 1\n(callback)"]
    subject -->|"notify"| sub2["Subscriber 2\n(callback)"]

    rp["RemoteProvider"] <-->|"IPC socket"| socket
    rs["RemoteSubscriber"] <-->|"IPC socket"| socket
```

## Sequence Diagrams

### Initialization

The initialization sequence shows how the router is set up from the `wazuh-modulesd` daemon perspective. The `RouterFacade` creates a subscription socket server for cross-process provider registration.

```mermaid
sequenceDiagram
    actor User
    participant RouterFacade
    participant SocketServer

    User->>RouterFacade: 1. Initialize (from modulesd)
    RouterFacade->>SocketServer: 2. Create subscription server (queue/router/subscription.sock)
    SocketServer->>SocketServer: 3. Listen for InitProvider JSON messages

    User->>RouterFacade: 4. Destroy service
    RouterFacade->>SocketServer: 5. Cleanup socket server
```

### Publisher Flow

The publisher flow shows how a provider is registered on-demand and how messages are dispatched asynchronously through the `FilterMsgDispatcher` thread pool to all observers.

```mermaid
sequenceDiagram
    actor User
    participant RouterFacade
    participant Publisher
    participant FilterMsgDispatcher
    participant Subject
    participant Subscriber

    User->>RouterFacade: 1. initProviderLocal(name)
    RouterFacade->>Publisher: 2. Create publisher (lazy, on first use)
    Publisher->>Publisher: 3. Create per-topic socket endpoint (queue/router/name)
    Publisher->>FilterMsgDispatcher: 4. Initialize thread pool for async dispatch
    RouterFacade->>RouterFacade: 5. Store publisher in m_providers[name]

    User->>RouterFacade: 6. push(name, data)
    RouterFacade->>RouterFacade: 7. Look up publisher by topic name
    RouterFacade->>Publisher: 8. Forward message
    Publisher->>FilterMsgDispatcher: 9. push(data) into async queue
    FilterMsgDispatcher->>FilterMsgDispatcher: 10. Dispatch in worker thread (apply optional filter)
    FilterMsgDispatcher->>Subject: 11. Invoke callback → setData(data)
    Subject->>Subscriber: 12. notifyObservers() → update(data) on each subscriber

    User->>RouterFacade: 13. removeProviderLocal(name)
    RouterFacade->>RouterFacade: 14. Remove publisher from m_providers map
```

### Subscriber Flow

The subscriber flow shows how a subscriber registers with a topic, and receives messages through the observer pattern.

```mermaid
sequenceDiagram
    actor User
    participant RouterFacade
    participant Publisher
    participant Subscriber
    participant FilterMsgDispatcher
    participant Subject

    User->>RouterFacade: 1. addSubscriber(name, subscriberId, callback)
    RouterFacade->>Publisher: 2. Get or create publisher for topic
    RouterFacade->>Subscriber: 3. Create subscriber with callback
    Publisher->>Subject: 4. attach(subscriber) to observer list

    User->>RouterFacade: 5. push(name, data) (from a publisher)
    RouterFacade->>Publisher: 6. Forward message to topic publisher
    Publisher->>FilterMsgDispatcher: 7. push(data) into async queue
    FilterMsgDispatcher->>FilterMsgDispatcher: 8. Dispatch in worker thread
    FilterMsgDispatcher->>Subject: 9. Invoke callback → setData(data)
    Subject->>Subscriber: 10. notifyObservers() → update(data)
    Subscriber->>Subscriber: 11. Execute user callback with message data

    User->>RouterFacade: 12. removeSubscriberLocal(name, subscriberId)
    Publisher->>Subject: 13. detach(subscriberId) from observer list
```
