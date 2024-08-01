#include <metrics/metricsManager.hpp>
#include <metrics/metricsScope.hpp>

#include <base/logging.hpp>

namespace metricsManager
{

MetricsManager::MetricsManager() :
    m_statusRunning{false}
{
    opentelemetry::sdk::common::internal_log::GlobalLogHandler::SetLogLevel(opentelemetry::sdk::common::internal_log::LogLevel::Error);
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
        LOG_INFO("MetricsManager: Created new scope: ({})", metricsScopeName);

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
        return nullptr;
    }
}

std::optional<base::Error> MetricsManager::enableCmd(const std::string& scopeName, const std::string& instrumentName, bool newStatus)
{
    auto scope = getScope(scopeName);
    if (scope == nullptr)
    {
        return base::Error {fmt::format("The {} scope has not been created.", scopeName)};
    }
    auto succeeded = scope->setEnabledStatus(instrumentName, newStatus);
    if (!succeeded)
    {
        return base::Error {fmt::format("The {} scope does not have {} instrument.", scopeName, instrumentName)};
    }

    return std::nullopt;
}

std::variant<std::string, base::Error> MetricsManager::getCmd(const std::string& scopeName, const std::string& instrumentName)
{
    auto scope = getScope(scopeName);
    if (scope == nullptr)
    {
        return base::Error {fmt::format("The {} scope has not been created.", scopeName)};
    }

    auto json = scope->getAllMetrics(instrumentName);
    if (json.isNull())
    {
        return base::Error {fmt::format("The {} scope does not have {} instrument.", scopeName, instrumentName)};
    }
    return json.prettyStr();
}

void MetricsManager::testCmd()
{
    static bool iterate = false;

    if (!iterate)
    {
        m_scopeMetrics = getMetricsScope("Metrics");
        iterate = true;
    }

    auto counterTest = m_scopeMetrics->getCounterUInteger("test");
    counterTest->addValue(1UL);
}

std::variant<std::string, base::Error> MetricsManager::listCmd()
{
/* Generated Output - Json Array of Json Objects.
[
    {"scope": "kvdb", "name":"databeseCounter", "type":"counter", "status":"enable"},
    {"scope": "kvdb", "name":"databeseCounter", "type":"counter", "status":"enable"},
]
*/
    {
        const std::lock_guard<std::mutex> lock(m_mutexScopes);

        if (m_mapScopes.empty())
        {
            return base::Error {fmt::format("Metrics Module doesn't have any Instrumentation Scope implemented.")};
        }
    }

    auto scopes = getAllMetrics().getObject().value();
    json::Json result;

    result.setArray();
    // TODO: This section improve with improve the json::Json
    for (auto& [key, value] : scopes)
    {
        if (value.isNull())
        {
            continue;
        }

        std::string json = "";
        auto metrics = value.getObject().value();

        for (auto& [keyMetric, valueMetric] : metrics)
        {
            if (valueMetric.isNull())
            {
                continue;
            }
            auto recordArr = valueMetric.getArray("/records");
            auto type = recordArr.value()[0].getString("/type").value();
            auto scope = getScope(key);
            auto status = scope->getEnabledStatus(keyMetric) ? "enabled" : "disabled";
            json = "{\"scope\":\"" + key + "\",\"name\":\"" + keyMetric + "\",\"type\":\"" + type + "\",\"status\":\"" + status + "\"}";
            json::Json element(json.c_str());
            result.appendJson(element);
        }
    }

    return result.str();
}

} // namespace metricsManager
