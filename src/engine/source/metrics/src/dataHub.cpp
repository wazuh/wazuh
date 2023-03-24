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
    retValue.setArray();

    auto it = m_resources.begin();
    while (it!=m_resources.end())
    {
        retValue.appendJson(it->second);
    }
    return json::Json();
}
} // namespace metrics_manager