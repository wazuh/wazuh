#ifndef _FASTMETRICS_ENGINEMETRICS_HPP
#define _FASTMETRICS_ENGINEMETRICS_HPP

/**
 * @file engineMetrics.hpp
 * @brief Pre-defined singleton metrics for the Wazuh Engine
 *
 * Each metric is a unique type that can be registered as a singleton.
 * Access is ultra-fast with zero overhead (direct atomic operations).
 *
 * Usage:
 *   // At startup (once):
 *   fastmetrics::initEngineMetrics();
 *
 *   // Anywhere in code:
 *   fastmetrics::EventsReceived::get().increment();
 *   fastmetrics::BytesReceived::get().add(1024);
 *   fastmetrics::QueueSize::get().set(42);
 *   fastmetrics::ProcessingLatencyUs::get().record(150);
 *
 * Performance: ~3ns overhead (single atomic operation)
 */

#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>

#include "atomicCounter.hpp"
#include "atomicGauge.hpp"
#include "atomicHistogram.hpp"

namespace fastmetrics
{

// ============================================================================
// Unique metric types (each is a separate singleton)
// ============================================================================

class EventsReceivedCounter : public AtomicCounter
{
public:
    EventsReceivedCounter()
        : AtomicCounter("events.received")
    {
    }
};

class EventsProcessedCounter : public AtomicCounter
{
public:
    EventsProcessedCounter()
        : AtomicCounter("events.processed")
    {
    }
};

class EventsDroppedCounter : public AtomicCounter
{
public:
    EventsDroppedCounter()
        : AtomicCounter("events.dropped")
    {
    }
};

class BytesReceivedCounter : public AtomicCounter
{
public:
    BytesReceivedCounter()
        : AtomicCounter("bytes.received")
    {
    }
};

class QueueSizeGauge : public AtomicGaugeInt
{
public:
    QueueSizeGauge()
        : AtomicGaugeInt("queue.size")
    {
    }
};

class QueueUsagePctGauge : public AtomicGaugeDouble
{
public:
    QueueUsagePctGauge()
        : AtomicGaugeDouble("queue.usage_pct")
    {
    }
};

class ProcessingLatencyUsHistogram : public AtomicHistogram<>
{
public:
    ProcessingLatencyUsHistogram()
        : AtomicHistogram<>("processing.latency_us")
    {
    }
};

// ============================================================================
// Static accessor classes (simple interface)
// ============================================================================

class EventsReceived
{
public:
    static EventsReceivedCounter& get() { return SingletonLocator::instance<EventsReceivedCounter>(); }
    static void init()
    {
        SingletonLocator::registerManager<EventsReceivedCounter,
                                          base::PtrSingleton<EventsReceivedCounter, EventsReceivedCounter>>();
    }
    static void cleanup() { SingletonLocator::unregisterManager<EventsReceivedCounter>(); }
};

class EventsProcessed
{
public:
    static EventsProcessedCounter& get() { return SingletonLocator::instance<EventsProcessedCounter>(); }
    static void init()
    {
        SingletonLocator::registerManager<EventsProcessedCounter,
                                          base::PtrSingleton<EventsProcessedCounter, EventsProcessedCounter>>();
    }
    static void cleanup() { SingletonLocator::unregisterManager<EventsProcessedCounter>(); }
};

class EventsDropped
{
public:
    static EventsDroppedCounter& get() { return SingletonLocator::instance<EventsDroppedCounter>(); }
    static void init()
    {
        SingletonLocator::registerManager<EventsDroppedCounter,
                                          base::PtrSingleton<EventsDroppedCounter, EventsDroppedCounter>>();
    }
    static void cleanup() { SingletonLocator::unregisterManager<EventsDroppedCounter>(); }
};

class BytesReceived
{
public:
    static BytesReceivedCounter& get() { return SingletonLocator::instance<BytesReceivedCounter>(); }
    static void init()
    {
        SingletonLocator::registerManager<BytesReceivedCounter,
                                          base::PtrSingleton<BytesReceivedCounter, BytesReceivedCounter>>();
    }
    static void cleanup() { SingletonLocator::unregisterManager<BytesReceivedCounter>(); }
};

class QueueSize
{
public:
    static QueueSizeGauge& get() { return SingletonLocator::instance<QueueSizeGauge>(); }
    static void init()
    {
        SingletonLocator::registerManager<QueueSizeGauge, base::PtrSingleton<QueueSizeGauge, QueueSizeGauge>>();
    }
    static void cleanup() { SingletonLocator::unregisterManager<QueueSizeGauge>(); }
};

class QueueUsagePct
{
public:
    static QueueUsagePctGauge& get() { return SingletonLocator::instance<QueueUsagePctGauge>(); }
    static void init()
    {
        SingletonLocator::registerManager<QueueUsagePctGauge,
                                          base::PtrSingleton<QueueUsagePctGauge, QueueUsagePctGauge>>();
    }
    static void cleanup() { SingletonLocator::unregisterManager<QueueUsagePctGauge>(); }
};

class ProcessingLatencyUs
{
public:
    static ProcessingLatencyUsHistogram& get() { return SingletonLocator::instance<ProcessingLatencyUsHistogram>(); }
    static void init()
    {
        SingletonLocator::registerManager<ProcessingLatencyUsHistogram,
                                          base::PtrSingleton<ProcessingLatencyUsHistogram, ProcessingLatencyUsHistogram>>();
    }
    static void cleanup() { SingletonLocator::unregisterManager<ProcessingLatencyUsHistogram>(); }
};

// ============================================================================
// Initialization
// ============================================================================

/**
 * @brief Initialize all engine metrics as singletons
 * Call once at engine startup
 */
inline void initEngineMetrics()
{
    EventsReceived::init();
    EventsProcessed::init();
    EventsDropped::init();
    BytesReceived::init();
    QueueSize::init();
    QueueUsagePct::init();
    ProcessingLatencyUs::init();
}

/**
 * @brief Cleanup all engine metrics (for testing)
 */
inline void cleanupEngineMetrics()
{
    EventsReceived::cleanup();
    EventsProcessed::cleanup();
    EventsDropped::cleanup();
    BytesReceived::cleanup();
    QueueSize::cleanup();
    QueueUsagePct::cleanup();
    ProcessingLatencyUs::cleanup();
}

} // namespace fastmetrics

#endif // _FASTMETRICS_ENGINEMETRICS_HPP
