#ifndef _METRICS_SCOPESERIALIZER_HPP
#define _METRICS_SCOPESERIALIZER_HPP

#include <opentelemetry/sdk/instrumentationscope/instrumentation_scope.h>

#include <base/json.hpp>

#include <metrics/ot.hpp>

namespace metrics::details
{
/**
 * @brief Serialize InstrumentationScope to json
 *
 * @param scope
 * @return json::Json
 */
inline json::Json scopeToJson(const ot::InstrumentationScope& scope)
{
    json::Json jsonScope;
    jsonScope.setString(scope.GetName(), "/name");
    jsonScope.setString(scope.GetSchemaURL(), "/schema");
    jsonScope.setString(scope.GetVersion(), "/version");
    return jsonScope;
}
} // namespace metrics::details

#endif // _METRICS_SCOPESERIALIZER_HPP
