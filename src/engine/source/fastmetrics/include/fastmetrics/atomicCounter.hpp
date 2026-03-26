#ifndef _FASTMETRICS_ATOMIC_COUNTER_HPP
#define _FASTMETRICS_ATOMIC_COUNTER_HPP

#include <atomic>
#include <string>

#include <fastmetrics/iMetric.hpp>

namespace fastmetrics
{

/**
 * @brief Lock-free atomic counter implementation
 *
 * Uses std::atomic with memory_order_relaxed for maximum performance.
 * Monotonically increasing counter that never decreases.
 *
 * Design: Each counter is registered as a singleton for ultra-fast access.
 */
class AtomicCounter : public ICounter
{
private:
    std::string m_name;
    std::atomic<uint64_t> m_value;
    std::atomic_bool m_enabled;

public:
    explicit AtomicCounter(std::string name)
        : m_name(std::move(name))
        , m_value(0)
        , m_enabled(true)
    {
    }

    // Constructor for singleton registration
    AtomicCounter()
        : AtomicCounter("")
    {
    }

    ~AtomicCounter() override = default;

    // Non-copyable, non-movable
    AtomicCounter(const AtomicCounter&) = delete;
    AtomicCounter& operator=(const AtomicCounter&) = delete;
    AtomicCounter(AtomicCounter&&) = delete;
    AtomicCounter& operator=(AtomicCounter&&) = delete;

    // IMetric interface
    const std::string& name() const override { return m_name; }

    MetricType type() const override { return MetricType::COUNTER; }

    bool isEnabled() const override { return m_enabled.load(std::memory_order_relaxed); }

    void enable() override { m_enabled.store(true, std::memory_order_relaxed); }

    void disable() override { m_enabled.store(false, std::memory_order_relaxed); }

    void reset() override { m_value.store(0, std::memory_order_relaxed); }

    double value() const override { return static_cast<double>(get()); }

    // ICounter interface
    void add(uint64_t delta = 1) override
    {
        if (!m_enabled.load(std::memory_order_relaxed)) [[unlikely]]
        {
            return;
        }

        m_value.fetch_add(delta, std::memory_order_relaxed);
    }

    uint64_t get() const override { return m_value.load(std::memory_order_relaxed); }

    /**
     * @brief Convenience method: increment by 1
     */
    inline void increment() { add(1); }
};

} // namespace fastmetrics

#endif // _FASTMETRICS_ATOMIC_COUNTER_HPP
