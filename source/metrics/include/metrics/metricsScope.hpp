#ifndef _METRICS_SCOPE_H
#define _METRICS_SCOPE_H

#include <string>

#include "opentelemetry/sdk/metrics/meter_provider.h"
#include "opentelemetry/sdk/metrics/export/periodic_exporting_metric_reader.h"

#include <metrics/iMetricsScope.hpp>
#include <metrics/dataHub.hpp>
#include <metrics/dataHubExporter.hpp>

#include <metrics/metricsInstruments.hpp>

namespace metrics_manager
{

using OTSDKMeterProvider = opentelemetry::sdk::metrics::MeterProvider;

class MetricsScope : public IMetricsScope
{
public:
    // TODO: Add exceptions
    void initialize();

    json::Json getAllMetrics();

    std::shared_ptr<instruments::iCounterDouble> getCounterDouble(const std::string& name) override;
    std::shared_ptr<instruments::iCounterInteger> getCounterInteger(const std::string& name) override;

private:
    std::shared_ptr<DataHub> m_dataHub;
    std::shared_ptr<OTSDKMeterProvider> m_meterProvider;
    std::map<std::string, std::shared_ptr<instruments::CounterDouble>> m_instruments_counter_double;
    std::map<std::string, std::shared_ptr<instruments::CounterInteger>> m_instruments_counter_integer;
};

} // namespace metrics_manager

#endif // _METRICS_SCOPE_H
