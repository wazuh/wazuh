#ifndef _METRICS_SCOPESERIALIZER_HPP
#define _METRICS_SCOPESERIALIZER_HPP

#include <base/json.hpp>

#include "ot.hpp"

namespace metrics::details
{
/**
 * @brief Serialize InstrumentationScope to json
 *
 * @param scope
 * @return json::Json
 */
inline json::Json scopeToJson(const otsdk::InstrumentationScope& scope)
{
    json::Json jsonScope;
    jsonScope.setString(scope.GetName(), "/name");
    jsonScope.setString(scope.GetSchemaURL(), "/schema");
    jsonScope.setString(scope.GetVersion(), "/version");
    return jsonScope;
}
} // namespace metrics::details

#endif // _METRICS_SCOPESERIALIZER_HPP
