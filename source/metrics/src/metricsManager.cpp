#include <metrics/metricsManager.hpp>
#include <metrics/metricsScope.hpp>

namespace metrics_manager {

std::shared_ptr<IMetricsScope> MetricsManager::getMetricsScope(const std::string& metricsScopeName)
{
    auto it = m_mapScopes.find(metricsScopeName);
    if (m_mapScopes.end() != it)
    {
        return it->second;
    }
    else 
    {
        auto newInstance = std::make_shared<MetricsScope>(metricsScopeName);
        m_mapScopes.insert(std::make_pair<std::string, std::shared_ptr<MetricsScope>>(std::string(metricsScopeName), std::move(newInstance)));
        return newInstance;
    }
}

} // namespace metrics_manager
