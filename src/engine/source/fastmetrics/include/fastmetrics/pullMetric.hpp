#ifndef FASTMETRICS_PULL_METRIC_HPP
#define FASTMETRICS_PULL_METRIC_HPP

/**
 * @file pullMetric.hpp
 * @brief On-demand pull metric using callbacks
 *
 * Pull metrics execute a callback when read, avoiding state duplication.
 * Perfect for exposing existing data (queue sizes, connection counts, etc.)
 * without maintaining separate atomic counters.
 */

#include <atomic>
#include <functional>
#include <string>

#include <fastmetrics/iMetric.hpp>

namespace fastmetrics
{

/**
 * @brief Pull metric - executes callback on value() call
 *
 * Zero overhead until read. No state duplication.
 * WARNING: Caller must ensure callback's captured references remain valid.
 *
 * Example:
 *   registerPullMetric<size_t>("queue.size", [&queue]() { return queue.size(); });
 *
 * @tparam T Value type (must be convertible to double)
 */
template<typename T>
class PullMetric : public IMetric
{
private:
    std::string m_name;
    std::function<T()> m_getter;
    std::atomic_bool m_enabled;

public:
    explicit PullMetric(std::string name, std::function<T()> getter)
        : m_name(std::move(name))
        , m_getter(std::move(getter))
        , m_enabled(true)
    {
    }

    ~PullMetric() override = default;

    PullMetric(const PullMetric&) = delete;
    PullMetric& operator=(const PullMetric&) = delete;
    PullMetric(PullMetric&&) = delete;
    PullMetric& operator=(PullMetric&&) = delete;


    /// \copydoc fastmetrics::IMetric::name()
    const std::string& name() const override { return m_name; }

    /// \copydoc fastmetrics::IMetric::type()
    MetricType type() const override { return MetricType::PULL; }

    /// \copydoc fastmetrics::IMetric::isEnabled()
    bool isEnabled() const override { return m_enabled.load(std::memory_order_relaxed); }

    /// \copydoc fastmetrics::IMetric::enable()
    void enable() override { m_enabled.store(true, std::memory_order_relaxed); }

    /// \copydoc fastmetrics::IMetric::disable()
    void disable() override { m_enabled.store(false, std::memory_order_relaxed); }

    /// \copydoc fastmetrics::IMetric::reset()
    void reset() override
    {
        // Pull metrics can't be reset (they're read-only views)
    }

    /// \copydoc fastmetrics::IMetric::value()
    double value() const override
    {
        if (!m_enabled.load(std::memory_order_relaxed)) [[unlikely]]
        {
            return 0.0;
        }

        if (!m_getter) [[unlikely]]
        {
            return 0.0;
        }

        try
        {
            return static_cast<double>(m_getter());
        }
        catch (...)
        {
            // If callback throws, return 0 (metric system shouldn't crash)
            return 0.0;
        }
    }

    /**
     * @brief Get typed value directly (avoids double conversion)
     */
    T getValue() const
    {
        if (!m_enabled.load(std::memory_order_relaxed) || !m_getter)
        {
            return T{};
        }

        try
        {
            return m_getter();
        }
        catch (...)
        {
            return T{};
        }
    }
};

} // namespace fastmetrics

#endif // FASTMETRICS_PULL_METRIC_HPP
