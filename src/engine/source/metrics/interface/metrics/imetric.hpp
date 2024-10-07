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
namespace detail
{
template<typename>
class BaseMetric;
}

/**
 * @brief Available metric types.
 *
 */
enum class MetricType
{
    UINTCOUNTER,
    DOUBLECOUNTER,
    UINTHISTOGRAM,
    DOUBLEHISTOGRAM,
    INTUPDOWNCOUNTER
};

/**
 * @brief Metric interface.
 *
 */
class IMetric : public std::enable_shared_from_this<IMetric>
{
protected:
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

public:
    virtual ~IMetric() = default;

    /**
     * @brief Update the metric with a new value. Exact behavior depends on the derived metric type.
     *
     * @tparam T The type of the value to update the metric with.
     * @param value The value to update the metric with.
     */
    template<typename T>
    void update(T value)
    {
        as<detail::BaseMetric<T>>()->update(value);
    }
};

namespace detail
{
/**
 * @brief Interface for managed metrics, defines methods to create, destroy, enable and disable the metric.
 *
 */
class IManagedMetric : public IMetric
{
public:
    virtual ~IManagedMetric() = default;

    /**
     * @brief Initialize and build all necessary resources for the metric to start working.
     *
     */
    virtual void create() = 0;

    /**
     * @brief Destroy all resources and clean up the metric.
     *
     */
    virtual void destroy() = 0;

    /**
     * @brief Allow the metric to start collecting data.
     *
     */
    virtual void enable() = 0;

    /**
     * @brief Stop the metric from collecting data.
     *
     */
    virtual void disable() = 0;

    /**
     * @brief Check if the metric is enabled.
     *
     * @return true If the metric is enabled.
     * @return false If the metric is disabled.
     */
    virtual bool isEnabled() const = 0;
};

/**
 * @brief Base metric class that defines the update method for all metric types.
 * This class is used to transit static polymorphism to dynamic polymorphism on the update method.
 *
 * @tparam T The type of the metric value. Only uint64_t and double are supported.
 */
template<typename T>
class BaseMetric : public IManagedMetric
{
public:
    virtual ~BaseMetric() = default;

    /**
     * @brief Update the metric with a new value.
     *
     * @param value The value to update the metric with.
     */
    virtual void update(T value) = 0;
};

} // namespace detail

} // namespace metrics

#endif // _METRICS_IMETRIC_HPP
