#include <fmt/format.h>
#include <iostream>
#include <metrics/dataHub.hpp>
#include <mutex>
#include <thread>

namespace metricsManager
{

json::Json DataHub::getResource(const std::string& scope)
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    auto foundRes = m_resources.find(scope);
    if (m_resources.end() == foundRes)
    {
        return json::Json();
    }
    else
    {
        return m_resources[scope];
    }
}

void DataHub::setResource(const std::string& scope, const json::Json& object)
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    m_resources[scope] = json::Json {object};
}

json::Json DataHub::getAllResources()
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    json::Json retValue;

    for (auto& r : m_resources)
    {
        retValue.set("/" + r.first, r.second);
    }

    return retValue;
}
} // namespace metricsManager
