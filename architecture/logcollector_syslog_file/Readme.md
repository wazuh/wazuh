# **Logcollector syslog architecture**
## **Index**
- [**Logcollector syslog architecture**](#logcollector-syslog-architecture)
  - [**Index**](#index)
  - [**Purpose**](#purpose)
  - [**Activity diagram 001**](#activity-diagram-001)
  - [**Sequence diagram 002**](#sequence-diagram-002)
  - [**Memory consumption**](#memory-consumption)
    - [**Summary**](#summary)



## **Purpose**
Logcollector monitors configured files new log messages.

Syslog is multi-threaded, achieving an improvement in overall performance. Each of the threads will read the first log that is not already handled by other threads and when it finishes reading, it will try to read the next available log so that all the threads are always occupied.

## **Activity diagram 001**

## **Sequence diagram 002**

## **Memory consumption**

**Thread quantity**

- 4 input threads(default) and configurable with "logcollector.input
_threads".
- 1 ouput thread to fordward readed events to agentd/memory-queue what will they send to the manager.

**Linux**
For each thread the stack size limit the reserved area is 8192 * 1024 * 5 (wazuh.thread_stack_size * constant * thread quantity) = 40mbs.

**Windows**
For each thread the stack size limit the reserved area is the default value 1mb * 5 (constant * thread quantity) = 5mbs.

------

In turn, this memory is not totally consumed when the thread is created, it is only reserved and taken when entering a function call that have locals variables, and this work in a LIFO way.

The release is automatic, in the same way as the "alloca" system function.


**File descriptors**

For windows, a temporary 4kb buffer is generated when doing a read operation, only when the file is opened as text mode.

Example: 200 Concurrents files scanning.

4 * 200 (FD buffer * Files to read) = 800kb

**Logcollector Event queue**

As a thread is processing log lines a maximum limit of 64kb is established for each line, these 64kb are from the stack segment, but after the processing this elements are incorporated into a queue that is allocated in the heap segment.
The limit for this queue is 1024 elements with the default configuration, and could be changed with "logcollector.queue_size" configuration.


**Agentd Event queue**

This queue works in a similar way to that logcollector queue, but it has mucha larger has a much larger capacity by default and in turn the processing is much slower, since it calls blocking functions in sockets (from here the message come to the manager for example).

**Memory deallocation**

Processing queues are kept in memory, allocated in the heap segment and  as they are moved between queues, until memory is deallocated when the message is sent or when the queue are saturated (here the behavior is to discard the events)

### **Summary**

Stressed condition with default configuration, reading 200 files with lines of 64kb, with 1024 events in the logcollector queue (full queue), and 5000 events in the agent event queue (full queue).

| Category | Memory usage |
| ------ | -----|
| Threads | ~960kb |
| FD buffer| 800kb |
| Logcollector Event queue | 64mb |
| Agent Event queue | 312.5mb |
| ------ | -----|
| Total | 378.2 MB |


The saturation could be achieve by lowering the EPS of the agent or congesting the system buffer so that the call to the send function becomes blocking.