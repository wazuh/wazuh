<!---
Copyright (C) 2015, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
-->

# Wazuh module: Router PubSub architecture
## Index
- [Wazuh module: Router PubSub architecture](#wazuh-module-router-pubsub-architecture)
  - [Index](#index)
  - [Purpose](#purpose)
    - [Definition](#definition)
    - [Key Concepts](#key-concepts)
      - [Publisher](#publisher)
      - [Subscriber](#subscriber)
      - [Channel/Topic](#channeltopic)
      - [Message Broker/Event Bus](#message-brokerevent-bus)
      - [Message](#message)
      - [Filtering](#filtering)
  - [Sequence diagrams](#sequence-diagrams)


## Purpose

### Definition
The Publish-Subscribe (Pub/Sub) pattern is a messaging pattern that separates the concerns of message producers (publishers) and message consumers (subscribers) by allowing them to communicate indirectly through a shared middleware component, called a message broker or event bus.

### Key Concepts

#### Publisher
A publisher is an entity that sends messages to one or more channels (also called topics). Publishers are unaware of subscribers and do not have any direct reference to them.

#### Subscriber
A subscriber is an entity that expresses interest in receiving messages from specific channels or based on certain criteria. Subscribers receive messages that meet their specified interests.

#### Channel/Topic
A channel (or topic) is a logical grouping of messages. Publishers send messages to channels, and subscribers receive messages from channels they are interested in.

#### Message Broker/Event Bus
A message broker (or event bus) is a middleware component that facilitates communication between publishers and subscribers. It is responsible for managing channels and routing messages to the appropriate subscribers.

#### Message
A message is a piece of information sent by a publisher to a channel. It usually contains data and metadata (such as headers or attributes) to provide context or aid in filtering.

#### Filtering
Filtering is the process of selectively delivering messages to subscribers based on their interests. Common filtering techniques include topic-based, content-based, context-based, and collaborative filtering.


## Sequence diagrams
The different sequence diagrams ilustrate the flow of the different modules interacting on the router general use.
- 001-sequence-initialize: It explains the wazuh module router initialization, construction, use, destruction and stop from the wazuh modules daemon perspective.
- 002-sequence-publisher: It explains the pubsub mechanism from the perspective of the publisher.
- 003-sequence-subscriber:It explains the pubsub mechanism from the perspective of the subscriber.

