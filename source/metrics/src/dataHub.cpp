#include "dataHub.hpp"
#include <thread>
#include <mutex>
#include <iostream>

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

void DataHub::dump()
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    for (auto &r : m_resources) {
        auto &s = r.second;
        std::cout << s.prettyStr() << std::endl;
    }
}
