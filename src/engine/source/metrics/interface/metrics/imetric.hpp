/**
 * @file imetric.hpp
 * @brief This file contains the declaration of the IMetric interface. The IMetric interface allows to update a metric
 * solely by its value, this is done by defining the BaseMetric class that transits static polymorphism to dynamic
 * polymorphism on the update method. Hiding exact metric type from the user.
 *
 */

#ifndef _METRICS_IMETRIC_HPP
#define _METRICS_IMETRIC_HPP

#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <typeinfo>

#include <fmt/format.h>

namespace metrics
{

// Forward declaration so that IMetric can downcast to BaseMetric
template<typename>
class BaseMetric;

/**
 * @brief Metric interface.
 *
 */
class IMetric : public std::enable_shared_from_this<IMetric>
{
public:
    virtual ~IMetric() = default;

    /**
     * @brief Cast the metric to a specific type.
     *
     * @tparam Metric The type to cast to. Must be derived from IMetric.
     * @return std::shared_ptr<Metric> The casted metric.
     */
    template<typename Metric>
    std::shared_ptr<Metric> as()
    {
        static_assert(std::is_base_of_v<IMetric, Metric>, "Metric must be derived from IMetric");
        auto ptr = std::dynamic_pointer_cast<Metric>(shared_from_this());
        if (!ptr)
        {
            throw std::runtime_error(fmt::format("Failed to cast IMetric '{}'", typeid(Metric).name()));
        }

        return ptr;
    }

    /**
     * @brief Update the metric with a new value. Exact behavior depends on the derived metric type.
     *
     * @tparam T The type of the value to update the metric with.
     * @param value The value to update the metric with.
     */
    template<typename T>
    void update(T value)
    {
        as<BaseMetric<T>>()->update(value);
    }
};

class ManagedMetric : public IMetric
{
protected:
    bool m_enabled;
    std::string m_name;
    std::string m_description;
    std::string m_unit;

    ManagedMetric() = default;

    ManagedMetric(std::string&& name, std::string&& description, std::string&& unit)
        : m_enabled(false)
        , m_name(std::move(name))
        , m_description(std::move(description))
        , m_unit(std::move(unit))
    {
    }

    ManagedMetric(const ManagedMetric&) = delete;
    ManagedMetric& operator=(const ManagedMetric&) = delete;
    ManagedMetric(ManagedMetric&&) = delete;
    ManagedMetric& operator=(ManagedMetric&&) = delete;

public:
    ~ManagedMetric() override = default;

    virtual void create() = 0;

    virtual void enable()
    {
        if (!m_enabled)
        {
            m_enabled = true;
        }
    }

    virtual void disable()
    {
        if (m_enabled)
        {
            m_enabled = false;
        }
    }

    virtual bool isEnabled() const { return m_enabled; }
};

/**
 * @brief Base metric interface.
 *
 * @tparam T Type of the value to update the metric with.
 */
template<typename T>
class BaseMetric : public ManagedMetric
{
protected:
    BaseMetric() = default;

    BaseMetric(std::string&& name, std::string&& description, std::string&& unit)
        : ManagedMetric(std::move(name), std::move(description), std::move(unit))
    {
    }

    BaseMetric(const BaseMetric&) = delete;
    BaseMetric& operator=(const BaseMetric&) = delete;
    BaseMetric(BaseMetric&&) = delete;
    BaseMetric& operator=(BaseMetric&&) = delete;

public:
    static_assert(std::is_arithmetic_v<T>, "BaseMetric type must be arithmetic");
    static_assert(std::is_same_v<T, uint64_t> || std::is_same_v<T, double>,
                  "BaseMetric type must be uint64_t or double");

    ~BaseMetric() override = default;

    virtual void update(T value) = 0;
};

enum class MetricType
{
    UINTCOUNTER,
    DOUBLECOUNTER,
    UINTHISTOGRAM,
    DOUBLEHISTOGRAM
};

} // namespace metrics

#endif // _METRICS_IMETRIC_HPP
