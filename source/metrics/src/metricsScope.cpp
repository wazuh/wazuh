#include <metrics/metricsScope.hpp>

namespace metrics_manager
{

MetricsScope::MetricsScope(const std::string& name) 
    : m_name{name}
{
}

void MetricsScope::initialize() 
{
    m_metricExporter = std::unique_ptr<OTSDKMetricExporter>(new OTDataHubExporter(m_dataHub));
    
}

} // namespace metrics_manager
