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

class MetricsScope : public IMetricsScope
{
    using OTSDKMetricExporter = opentelemetry::sdk::metrics::PushMetricExporter;
    using OTSDKMetricReader = opentelemetry::sdk::metrics::MetricReader;
    using OTSDKMeterProvider = opentelemetry::sdk::metrics::MeterProvider;
    using OTDataHubExporter = opentelemetry::exporter::metrics::DataHubExporter;

public:
    MetricsScope(const std::string& name);

    void initialize();

protected:
    std::shared_ptr<DataHub> m_dataHub;

    std::unique_ptr<OTSDKMetricExporter> m_metricExporter;
    std::unique_ptr<OTSDKMetricReader> m_metricReader;
    std::shared_ptr<OTSDKMeterProvider> m_meterProvider;

    /// @brief Name of the Scope
    std::string m_name;
};

} // namespace metrics_manager

#endif // _METRICS_SCOPE_H
