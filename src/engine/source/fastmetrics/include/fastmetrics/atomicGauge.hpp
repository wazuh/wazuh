#ifndef _FASTMETRICS_ATOMIC_GAUGE_HPP
#define _FASTMETRICS_ATOMIC_GAUGE_HPP

#include <atomic>
#include <string>
#include <type_traits>

#include <fastmetrics/iMetric.hpp>

namespace fastmetrics
{

/**
 * @brief Lock-free atomic int64 gauge implementation
 */
class AtomicGaugeInt : public IGaugeInt
{
private:
    std::string m_name;
    std::atomic<int64_t> m_value;
    std::atomic_bool m_enabled;

public:
    explicit AtomicGaugeInt(std::string name)
        : m_name(std::move(name))
        , m_value(0)
        , m_enabled(true)
    {
    }

    ~AtomicGaugeInt() override = default;

    AtomicGaugeInt(const AtomicGaugeInt&) = delete;
    AtomicGaugeInt& operator=(const AtomicGaugeInt&) = delete;
    AtomicGaugeInt(AtomicGaugeInt&&) = delete;
    AtomicGaugeInt& operator=(AtomicGaugeInt&&) = delete;

    // IMetric interface
    const std::string& name() const override { return m_name; }

    MetricType type() const override { return MetricType::GAUGE_INT; }

    bool isEnabled() const override { return m_enabled.load(std::memory_order_relaxed); }

    void enable() override { m_enabled.store(true, std::memory_order_relaxed); }

    void disable() override { m_enabled.store(false, std::memory_order_relaxed); }

    void reset() override { m_value.store(0, std::memory_order_relaxed); }

    double value() const override { return static_cast<double>(get()); }

    // IGaugeInt interface
    void set(int64_t value) override
    {
        if (!m_enabled.load(std::memory_order_relaxed)) [[unlikely]]
        {
            return;
        }

        m_value.store(value, std::memory_order_relaxed);
    }

    void add(int64_t delta) override
    {
        if (!m_enabled.load(std::memory_order_relaxed)) [[unlikely]]
        {
            return;
        }

        m_value.fetch_add(delta, std::memory_order_relaxed);
    }

    void sub(int64_t delta) override
    {
        if (!m_enabled.load(std::memory_order_relaxed)) [[unlikely]]
        {
            return;
        }

        m_value.fetch_sub(delta, std::memory_order_relaxed);
    }

    int64_t get() const override { return m_value.load(std::memory_order_relaxed); }
};

/**
 * @brief Lock-free atomic double gauge implementation
 *
 * Note: For floating point, we use compare-and-swap since fetch_add
 * is not available for double in all platforms.
 */
class AtomicGaugeDouble : public IGaugeDouble
{
private:
    std::string m_name;
    std::atomic<double> m_value;
    std::atomic_bool m_enabled;

public:
    explicit AtomicGaugeDouble(std::string name)
        : m_name(std::move(name))
        , m_value(0.0)
        , m_enabled(true)
    {
    }

    ~AtomicGaugeDouble() override = default;

    AtomicGaugeDouble(const AtomicGaugeDouble&) = delete;
    AtomicGaugeDouble& operator=(const AtomicGaugeDouble&) = delete;
    AtomicGaugeDouble(AtomicGaugeDouble&&) = delete;
    AtomicGaugeDouble& operator=(AtomicGaugeDouble&&) = delete;

    // IMetric interface
    const std::string& name() const override { return m_name; }

    MetricType type() const override { return MetricType::GAUGE_DBL; }

    bool isEnabled() const override { return m_enabled.load(std::memory_order_relaxed); }

    void enable() override { m_enabled.store(true, std::memory_order_relaxed); }

    void disable() override { m_enabled.store(false, std::memory_order_relaxed); }

    void reset() override { m_value.store(0.0, std::memory_order_relaxed); }

    double value() const override { return get(); }

    // IGaugeDouble interface
    void set(double value) override
    {
        if (!m_enabled.load(std::memory_order_relaxed)) [[unlikely]]
        {
            return;
        }

        m_value.store(value, std::memory_order_relaxed);
    }

    double get() const override { return m_value.load(std::memory_order_relaxed); }
};

} // namespace fastmetrics

#endif // _FASTMETRICS_ATOMIC_GAUGE_HPP
