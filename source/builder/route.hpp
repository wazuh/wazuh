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

class Route
{
private:
    std::string m_name;
    std::string m_target;
    base::Expression m_expr;

    bool executeExpression(base::Expression expression, base::Event event) const;

public:
    Route(json::Json jsonDefinition, std::shared_ptr<builder::internals::Registry> registry);

    const std::string& getName() const { return m_name; }
    const std::string& getTarget() const { return m_target; }

    bool accept(base::Event event) const { return executeExpression(m_expr, event); }
};

} // namespace builder

#endif // _BUILDER_ROUTE_H
