#include <metrics/metricsManager.hpp>
#include <metrics/metricsScope.hpp>

#include <logging/logging.hpp>

namespace metrics_manager
{

MetricsManager::MetricsManager() : 
    m_statusRunning{false}
{
    
}

void MetricsManager::start()
{
    // Configure
}

bool MetricsManager::isRunning()
{
    return m_statusRunning;
}

json::Json MetricsManager::getAllMetrics()
{
    const std::lock_guard<std::mutex> lock(m_mutexScopes);

    json::Json retValue;
    retValue.setNull();

    auto it = m_mapScopes.begin();
    while (it!=m_mapScopes.end())
    {
        auto scopeMetrics = it->second->getAllMetrics();
        auto path = "/" + it->first;
        retValue.set(path, scopeMetrics);
        it++;
    }

    return retValue;
}

std::shared_ptr<IMetricsScope> MetricsManager::getMetricsScope(const std::string& metricsScopeName, bool delta, int exporterIntervalMS, int exporterTimeoutMS)
{
    const std::lock_guard<std::mutex> lock(m_mutexScopes);

    auto it = m_mapScopes.find(metricsScopeName);
    if (m_mapScopes.end() != it)
    {
        return it->second;
    }
    else
    {
        WAZUH_LOG_INFO("MetricsManager: Created new scope: ({})", metricsScopeName);

        m_mapScopes.insert(
            std::make_pair<std::string, std::shared_ptr<MetricsScope>>(
                std::string(metricsScopeName),
                std::make_shared<MetricsScope>()));

        auto& retScope = m_mapScopes[metricsScopeName];

        retScope->initialize(delta, exporterIntervalMS, exporterTimeoutMS);
        
        return retScope;
    }
}

std::vector<std::string> MetricsManager::getScopeNames()
{
    std::vector<std::string> scopeNames;
    for (const auto& pairs : m_mapScopes)
    {
        scopeNames.push_back(pairs.first);
    }
    return scopeNames;
}


// API Commands

std::variant<std::string, base::Error> MetricsManager::dumpCmd()
{
    {
        const std::lock_guard<std::mutex> lock(m_mutexScopes);

        if (m_mapScopes.empty())
        {
            return base::Error {fmt::format("Metrics Module doesn't have any Instrumentation Scope implemented.")};
        }
    }
    
    auto retValue = getAllMetrics();
    if (retValue.isNull())
    {
        return "{}";
    }
    return retValue.prettyStr();
}

std::shared_ptr<MetricsScope> MetricsManager::getScope(const std::string& metricsScopeName)
{
    const std::lock_guard<std::mutex> lock(m_mutexScopes);

    auto it = m_mapScopes.find(metricsScopeName);
    if (m_mapScopes.end() != it)
    {
        return it->second;
    }
    else
    {
        throw std::runtime_error {"The scope " + metricsScopeName + " has not been created."};
    }
}

void MetricsManager::enableCmd(const std::string& scopeName, const std::string& instrumentName, bool newStatus)
{
    auto scope = getScope(scopeName);
    scope->setEnabledStatus(instrumentName, newStatus);
}

void MetricsManager::testCmd()
{
    static bool iterate = false;

    if (!iterate)
    {
        m_scopeMetrics = getMetricsScope("metrics");
        iterate = true;
    }

    auto counterTest = m_scopeMetrics->getCounterUInteger("test");
    counterTest->addValue(1UL);
}

} // namespace metrics_manager
