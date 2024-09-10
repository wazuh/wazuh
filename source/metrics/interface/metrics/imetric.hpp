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
protected:
    IMetric() = default;
    IMetric(const IMetric&) = delete;
    IMetric(IMetric&&) = delete;
    IMetric& operator=(const IMetric&) = delete;
    IMetric& operator=(IMetric&&) = delete;

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
    void update(T&& value)
    {
        as<BaseMetric<T>>()->update(std::forward<T>(value));
    }
};

/**
 * @brief Base metric interface.
 *
 * @tparam T Type of the value to update the metric with.
 */
template<typename T>
class BaseMetric : public IMetric
{
public:
    static_assert(std::is_arithmetic_v<T>, "BaseMetric type must be arithmetic");

    ~BaseMetric() override = default;

    // Check rvalue
    virtual void update(T&& value) = 0;
};

} // namespace metrics

#endif // _METRICS_IMETRIC_HPP
