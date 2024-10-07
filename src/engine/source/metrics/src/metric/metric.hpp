#ifndef _METRIC_METRIC_HPP
#define _METRIC_METRIC_HPP

#include <atomic>
#include <mutex>
#include <shared_mutex>

#include <metrics/imetric.hpp>

namespace metrics
{

/**
 * @brief Base metric interface.
 *
 * @tparam T Type of the value to update the metric with.
 */
template<typename T>
class BaseOtMetric : public detail::BaseMetric<T>
{
protected:
    std::shared_mutex m_mutex;
    std::atomic_bool m_enabled;
    std::string m_name;
    std::string m_description;
    std::string m_unit;

    BaseOtMetric(std::string&& name, std::string&& description, std::string&& unit)
        : m_enabled(true)
        , m_name(std::move(name))
        , m_description(std::move(description))
        , m_unit(std::move(unit))
        , m_mutex()
    {
    }

    BaseOtMetric() = delete;
    BaseOtMetric(const BaseOtMetric&) = delete;
    BaseOtMetric& operator=(const BaseOtMetric&) = delete;
    BaseOtMetric(BaseOtMetric&&) = delete;
    BaseOtMetric& operator=(BaseOtMetric&&) = delete;

    virtual void otUpdate(T value) = 0;

    virtual void otCreate() = 0;

    virtual void otDestroy() = 0;

public:
    static_assert(std::is_arithmetic_v<T>, "BaseMetric type must be arithmetic");
    static_assert(std::is_same_v<T, uint64_t> || std::is_same_v<T, double> || std::is_same_v<T, int64_t>,
                  "BaseMetric type must be uint64_t or double");

    ~BaseOtMetric() override = default;

    void enable() override { m_enabled.store(true, std::memory_order_relaxed); }

    void disable() override { m_enabled.store(false, std::memory_order_relaxed); }

    bool isEnabled() const override { return m_enabled.load(std::memory_order_relaxed); }

    void create() override
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        otCreate();
    }

    void destroy() override
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        otDestroy();
    }

    void update(T value)
    {
        if (isEnabled())
        {
            std::shared_lock<std::shared_mutex> lock(m_mutex);
            otUpdate(value);
        }
    }
};

} // namespace metrics

#endif // _METRIC_METRIC_HPP
