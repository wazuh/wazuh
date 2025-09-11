#ifndef _METRICS_INCLUDES_HPP
#define _METRICS_INCLUDES_HPP

#include <opentelemetry/context/runtime_context.h>
#include <opentelemetry/metrics/provider.h>
#include <opentelemetry/sdk/common/global_log_handler.h>
#include <opentelemetry/sdk/instrumentationscope/instrumentation_scope.h>
#include <opentelemetry/sdk/metrics/data/metric_data.h>
#include <opentelemetry/sdk/metrics/data/point_data.h>
#include <opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h>
#include <opentelemetry/sdk/metrics/meter.h>
#include <opentelemetry/sdk/metrics/meter_context.h>
#include <opentelemetry/sdk/metrics/meter_provider.h>
#include <opentelemetry/sdk/metrics/push_metric_exporter.h>

namespace metrics
{
constexpr auto DEFAULT_METER_NAME = "default";

namespace otsdk
{
using namespace opentelemetry::sdk;
using namespace opentelemetry::sdk::common;
using namespace opentelemetry::sdk::metrics;
using namespace opentelemetry::sdk::instrumentationscope;
} // namespace otsdk

namespace otapi
{
using namespace opentelemetry::nostd;
using namespace opentelemetry::metrics;
using namespace opentelemetry::context;
} // namespace otapi
} // namespace metrics

#endif // _METRICS_INCLUDES_HPP
