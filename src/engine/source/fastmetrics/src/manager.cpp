#include <chrono>
#include <fmt/format.h>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/logging.hpp>

#include <fastmetrics/iManager.hpp>
#include <fastmetrics/manager.hpp>

namespace fastmetrics
{

std::shared_ptr<IMetric> Manager::get(const std::string& name) const
{
    std::shared_lock lock(m_mutex);
    auto it = m_metrics.find(name);
    return (it != m_metrics.end()) ? it->second : nullptr;
}

bool Manager::exists(const std::string& name) const
{
    std::shared_lock lock(m_mutex);
    return m_metrics.find(name) != m_metrics.end();
}

std::vector<std::string> Manager::getAllNames() const
{
    std::shared_lock lock(m_mutex);

    std::vector<std::string> names;
    names.reserve(m_metrics.size());

    for (const auto& [name, _] : m_metrics)
    {
        names.push_back(name);
    }

    return names;
}

size_t Manager::count() const
{
    std::shared_lock lock(m_mutex);
    return m_metrics.size();
}

void Manager::enableAll()
{
    m_globalEnabled.store(true, std::memory_order_relaxed);

    std::shared_lock lock(m_mutex);
    for (auto& [_, metric] : m_metrics)
    {
        metric->enable();
    }
}

void Manager::disableAll()
{
    m_globalEnabled.store(false, std::memory_order_relaxed);

    std::shared_lock lock(m_mutex);
    for (auto& [_, metric] : m_metrics)
    {
        metric->disable();
    }
}

bool Manager::isEnabled() const
{
    return m_globalEnabled.load(std::memory_order_relaxed);
}

void Manager::clear()
{
    std::unique_lock lock(m_mutex);
    m_metrics.clear();
}

void Manager::writeAllMetrics(std::shared_ptr<streamlog::WriterEvent> metricsWriter) const
{
    try
    {
        // Get all metrics and write as JSON
        auto metricNames = getAllNames();
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

        for (const auto& name : metricNames)
        {
            auto metric = get(name);
            if (metric)
            {
                // Always write the value (disabled metrics return 0)
                std::string jsonLine =
                    fmt::format(R"({{"timestamp":{},"name":"{}","value":{}}})", timestamp, name, metric->value());

                (*metricsWriter)(std::move(jsonLine));
            }
        }
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Metrics logging error: {}", e.what());
    }
}

} // namespace fastmetrics
