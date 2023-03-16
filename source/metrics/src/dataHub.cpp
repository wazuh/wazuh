#include <metrics/dataHub.hpp>
#include <thread>
#include <mutex>
#include <iostream>
#include <fmt/format.h>

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

void DataHub::dump()
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    for (auto &r : m_resources) {
        auto &s = r.second;
        std::cout << s.prettyStr() << std::endl;
    }
}

std::variant<std::string, base::Error> DataHub::dumpCmd()
{
    const std::lock_guard<std::mutex> lock(m_mutex);
    json::Json contentDataHub;
    contentDataHub.setArray();

    if (m_resources.empty())
    {
        return base::Error {fmt::format("There is no instrument defined.")};
    }

    for (auto &r : m_resources) {
        contentDataHub.appendJson(r.second);
    }

    return contentDataHub.prettyStr();
}

std::variant<std::string, base::Error> DataHub::getCmd(const std::string& instrumentName)
{
    const std::lock_guard<std::mutex> lock(m_mutex);

    auto metric = m_resources.find(instrumentName);
    if (metric != m_resources.end())
    {
        return metric->second.prettyStr();
    }

    return base::Error {fmt::format("Instrument '{}' does not exist or wasn't loaded.", instrumentName)};
}

} // namespace metrics_manager