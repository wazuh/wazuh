#ifndef _METRIC_METRIC_HPP
#define _METRIC_METRIC_HPP

#include <atomic>
#include <mutex>

#include "managerImpl.hpp"

namespace metrics
{

/**
 * @brief Base metric interface.
 *
 * @tparam T Type of the value to update the metric with.
 */
template<typename T>
class BaseMetric : public Manager::ImplMetric
{
protected:
    std::shared_mutex m_mutex;
    std::atomic_bool m_enabled;
    std::string m_name;
    std::string m_description;
    std::string m_unit;

    BaseMetric(std::string&& name, std::string&& description, std::string&& unit)
        : m_enabled(true)
        , m_name(std::move(name))
        , m_description(std::move(description))
        , m_unit(std::move(unit))
    {
    }

    BaseMetric() = delete;
    BaseMetric(const BaseMetric&) = delete;
    BaseMetric& operator=(const BaseMetric&) = delete;
    BaseMetric(BaseMetric&&) = delete;
    BaseMetric& operator=(BaseMetric&&) = delete;

    virtual void otUpdate(T value) = 0;

    virtual void otCreate(const Manager::ImplOtPipeline& otPipeline) = 0;

    virtual void otDestroy() = 0;

public:
    static_assert(std::is_arithmetic_v<T>, "BaseMetric type must be arithmetic");
    static_assert(std::is_same_v<T, uint64_t> || std::is_same_v<T, double>,
                  "BaseMetric type must be uint64_t or double");

    ~BaseMetric() override = default;

    void enable() override { m_enabled.store(true, std::memory_order_relaxed); }

    void disable() override { m_enabled.store(false, std::memory_order_relaxed); }

    bool isEnabled() const override { return m_enabled.load(std::memory_order_relaxed); }

    void create(const Manager::ImplOtPipeline& otPipeline) override
    {
        std::unique_lock lock(m_mutex);
        otCreate(otPipeline);
    }

    void destroy() override
    {
        std::unique_lock lock(m_mutex);
        otDestroy();
    }

    void update(T value)
    {
        if (isEnabled())
        {
            std::shared_lock lock(m_mutex);
            otUpdate(value);
        }
    }
};

} // namespace metrics

#endif // _METRIC_METRIC_HPP
