#include <fastmetrics/manager.hpp>

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <fastmetrics/atomicCounter.hpp>
#include <fastmetrics/atomicGauge.hpp>
#include <fastmetrics/iManager.hpp>

namespace fastmetrics
{

std::shared_ptr<ICounter>
Manager::getOrCreateCounter(const std::string& name, const std::string& description, const std::string& unit)
{
    // Fast path: try to get existing metric with shared lock
    {
        std::shared_lock lock(m_mutex);
        auto it = m_metrics.find(name);
        if (it != m_metrics.end())
        {
            return std::dynamic_pointer_cast<ICounter>(it->second);
        }
    }

    // Slow path: create new metric with unique lock
    std::unique_lock lock(m_mutex);

    // Double-check after acquiring unique lock
    auto it = m_metrics.find(name);
    if (it != m_metrics.end())
    {
        return std::dynamic_pointer_cast<ICounter>(it->second);
    }

    // Create new counter
    auto counter = std::make_shared<AtomicCounter>(name);
    if (!m_globalEnabled.load(std::memory_order_relaxed))
    {
        counter->disable();
    }

    m_metrics[name] = counter;
    return counter;
}

std::shared_ptr<IGaugeInt>
Manager::getOrCreateGaugeInt(const std::string& name, const std::string& description, const std::string& unit)
{
    // Fast path
    {
        std::shared_lock lock(m_mutex);
        auto it = m_metrics.find(name);
        if (it != m_metrics.end())
        {
            return std::dynamic_pointer_cast<IGaugeInt>(it->second);
        }
    }

    // Slow path
    std::unique_lock lock(m_mutex);

    auto it = m_metrics.find(name);
    if (it != m_metrics.end())
    {
        return std::dynamic_pointer_cast<IGaugeInt>(it->second);
    }

    auto gauge = std::make_shared<AtomicGaugeInt>(name);
    if (!m_globalEnabled.load(std::memory_order_relaxed))
    {
        gauge->disable();
    }

    m_metrics[name] = gauge;
    return gauge;
}

std::shared_ptr<IGaugeDouble>
Manager::getOrCreateGaugeDouble(const std::string& name, const std::string& description, const std::string& unit)
{
    // Fast path
    {
        std::shared_lock lock(m_mutex);
        auto it = m_metrics.find(name);
        if (it != m_metrics.end())
        {
            return std::dynamic_pointer_cast<IGaugeDouble>(it->second);
        }
    }

    // Slow path
    std::unique_lock lock(m_mutex);

    auto it = m_metrics.find(name);
    if (it != m_metrics.end())
    {
        return std::dynamic_pointer_cast<IGaugeDouble>(it->second);
    }

    auto gauge = std::make_shared<AtomicGaugeDouble>(name);
    if (!m_globalEnabled.load(std::memory_order_relaxed))
    {
        gauge->disable();
    }

    m_metrics[name] = gauge;
    return gauge;
}

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

} // namespace fastmetrics
