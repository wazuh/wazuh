#ifndef _ROUTER_ROUTE_H
#define _ROUTER_ROUTE_H

#include <memory>
#include <string>

#include <fmt/format.h>

#include <baseTypes.hpp>
#include <json/json.hpp>

#include <asset.hpp>
#include <expression.hpp>

namespace router
{

constexpr int ROUTE_MAXIMUM_PRIORITY {0L};                          ///< Maximum priority allowed for a route
constexpr int ROUTE_MINIMUM_PRIORITY {255L};                        ///< Minimum priority allowed for a route
constexpr int TEST_ROUTE_MAXIMUM_PRIORITY {ROUTE_MAXIMUM_PRIORITY}; ///< Maximum priority allowed for a test route
constexpr int TEST_ROUTE_MINIMUM_PRIORITY {49L};                    ///< Minimum priority allowed for a test route
constexpr int USER_ROUTE_MAXIMUM_PRIORITY {50L};                    ///< Maximum priority allowed for a user route
constexpr int USER_ROUTE_MINIMUM_PRIORITY {ROUTE_MINIMUM_PRIORITY}; ///< Minimum priority allowed for a user route

/**
 * @brief Represents a route, it is used to route events to a destination ("target")
 *
 * The route is defined by a name, a target, a priority and the expression to match the event.
 */
class Route
{
private:
    std::string m_name;        ///< Name of the route
    std::string m_target;      ///< Target of the route
    std::size_t m_priority;    ///< Priority of the route, the lower the higher priority
    std::string m_filterName;  ///< Name of the filter
    base::Expression m_filter; ///< Expression to match the event

    /**
     * @brief Execute an expression
     *
     *  This function is used to execute an expression and return the result in the backend of the accepted function
     * @param expression Expression to execute
     * @param event Event to match
     * @return true if the expression is true, false otherwise
     */
    bool executeExpression(base::Expression expression, base::Event event) const;

public:
    /**
     * @brief Construct a new Route object
     *
     * @param name Name of the route
     * @param assetRoute Route asset (Contains the name and expression)
     * @param target Target of the route (Destination environment of the event)
     * @param priority Priority of the route
     * @throw std::runtime_error if the priority is out of range
     */
    Route(const std::string& name, builder::Asset assetRoute, const std::string& target, int priority);

    /**
     * @brief Get the Name of the route
     */
    const std::string& getName() const { return m_name; }

    /**
     * @brief Get the Name of the route
     * @return const std::string& Name of the route
     */
    const std::string& getFilterName() const { return m_filterName; }

    /**
     * @brief Get the Target of the route
     * @return const std::string& Target of the route
     */
    const std::string& getTarget() const { return m_target; }

    /**
     * @brief Get the Priority of the route
     * @return std::size_t Priority of the route
     */
    std::size_t getPriority() const { return m_priority; }

    /**
     * @brief Set the Priority of the route
     * @param priority Priority of the route
     * @throw std::runtime_error if the priority is out of range
     */
    void setPriority(int priority);

    /**
     * @brief Check if the route accept an event
     *
     * @param event Event to check
     * @return true if the route accept the event, false otherwise
     */
    bool accept(base::Event event) const { return executeExpression(m_filter, event); }
};

} // namespace router

#endif // _ROUTER_ROUTE_H
