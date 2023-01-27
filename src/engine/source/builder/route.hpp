#ifndef _BUILDER_ROUTE_H
#define _BUILDER_ROUTE_H

#include <memory>
#include <string>

#include <fmt/format.h>

#include <baseTypes.hpp>
#include <json/json.hpp>

#include "asset.hpp"
#include "expression.hpp"
#include "registry.hpp"

namespace builder
{

/**
 * @brief Represents a route asset, it is used to route events to a destination ("target")
 *
 * The route is defined by a name, a target and a priority and the expression to match the event.
 */
class Route
{
private:
    std::string m_name;     ///< Name of the route
    std::string m_target;   ///< Target of the route
    std::size_t m_priority; ///< Priority of the route, the lower the higher priority

    base::Expression m_expr; ///< Expression to match the event

    /**
     * @brief Execute an expression
     *
     *  This function is used to execute an expression and return the result, it the backend of the accept function.
     * @param expression Expression to execute
     * @param event Event to match
     * @return true if the expression is true, false otherwise
     */
    bool executeExpression(base::Expression expression, base::Event event) const;

public:

    /**
     * @brief Construct a new Route object
     *
     * The json definition must have the following fields:
     * - name: Name of the route
     * - target: Target of the route (Destination environment)
     * - priority: Priority of the route
     * - check: Optional, expression to match the event, if not present the route will match all events
     * @param jsonDefinition Json definition of the route
     * @param registry Registry to get the helpers and check stage
     */
    Route(json::Json jsonDefinition, std::shared_ptr<builder::internals::Registry> registry);

    /**
     * @brief Get the Name of the route
     * @return const std::string& Name of the route
     */
    const std::string& getName() const { return m_name; }

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
     * @throw std::runtime_error if the priority is out of range ( < 0 or > 255)
     */
    void setPriority(int priority);

    /**
     * @brief Check if the route accept an event
     *
     * @param event Event to check
     * @return true if the route accept the event, false otherwise
     */
    bool accept(base::Event event) const { return executeExpression(m_expr, event); }
};

} // namespace builder

#endif // _BUILDER_ROUTE_H
