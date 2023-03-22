#ifndef _METRICS_SCOPE_H
#define _METRICS_SCOPE_H

#include <string>

#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h"

#include <metrics/iMetricsScope.hpp>
#include <metrics/dataHub.hpp>
#include <metrics/dataHubExporter.hpp>

namespace metrics_manager
{

using OTSDKMeterProvider = opentelemetry::sdk::metrics::MeterProvider;

class MetricsScope : public IMetricsScope
{
public:
    // TODO: Add exceptions
    void initialize();

protected:
    std::shared_ptr<DataHub> m_dataHub;
    std::shared_ptr<OTSDKMeterProvider> m_meterProvider;
};

} // namespace metrics_manager

#endif // _METRICS_SCOPE_H
