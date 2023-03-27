#include <metrics/dataHub.hpp>
#include <thread>
#include <mutex>
#include <iostream>
#include <fmt/format.h>
#include <metrics/dataHub.hpp>

namespace metrics_manager
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

void DataHub::setResource(const std::string& scope, json::Json object)
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    m_resources[scope] = object;
}

json::Json DataHub::getAllResources()
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    
    json::Json retValue;

    for (auto &r : m_resources) {
        retValue.appendJson(r.second, "/" + r.first);
    }
    
    return retValue;
}
} // namespace metrics_manager