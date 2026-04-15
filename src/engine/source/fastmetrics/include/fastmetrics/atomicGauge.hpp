#ifndef FASTMETRICS_ATOMIC_GAUGE_HPP
#define FASTMETRICS_ATOMIC_GAUGE_HPP

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

    /** @copydoc fastmetrics::IMetric::name() */
    const std::string& name() const override { return m_name; }

    /** @copydoc fastmetrics::IMetric::type() */
    MetricType type() const override { return MetricType::GAUGE_INT; }

    /** @copydoc fastmetrics::IMetric::isEnabled() */
    bool isEnabled() const override { return m_enabled.load(std::memory_order_relaxed); }

    /** @copydoc fastmetrics::IMetric::enable() */
    void enable() override { m_enabled.store(true, std::memory_order_relaxed); }

    /** @copydoc fastmetrics::IMetric::disable() */
    void disable() override { m_enabled.store(false, std::memory_order_relaxed); }

    /** @copydoc fastmetrics::IMetric::reset() */
    void reset() override { m_value.store(0, std::memory_order_relaxed); }

    /** @copydoc fastmetrics::IMetric::value() */
    double value() const override { return static_cast<double>(get()); }

    /** @copydoc fastmetrics::IGaugeInt::set() */
    void set(int64_t value) override
    {
        if (!m_enabled.load(std::memory_order_relaxed)) [[unlikely]]
        {
            return;
        }

        m_value.store(value, std::memory_order_relaxed);
    }

    /** @copydoc fastmetrics::IGaugeInt::add() */
    void add(int64_t delta) override
    {
        if (!m_enabled.load(std::memory_order_relaxed)) [[unlikely]]
        {
            return;
        }

        m_value.fetch_add(delta, std::memory_order_relaxed);
    }

    /** @copydoc fastmetrics::IGaugeInt::sub() */
    void sub(int64_t delta) override
    {
        if (!m_enabled.load(std::memory_order_relaxed)) [[unlikely]]
        {
            return;
        }

        m_value.fetch_sub(delta, std::memory_order_relaxed);
    }

    /** @copydoc fastmetrics::IGaugeInt::get() */
    int64_t get() const override { return m_value.load(std::memory_order_relaxed); }
};

} // namespace fastmetrics

#endif // FASTMETRICS_ATOMIC_GAUGE_HPP
