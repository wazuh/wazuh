#ifndef _METRICS_H
#define _METRICS_H

#include <memory>
#include <mutex>
#include <unordered_map>

#include <utils/baseMacros.hpp>
#include <metrics/iMetricsManager.hpp>

#include <metrics/dataHub.hpp>

namespace metrics_manager
{

class MetricsScope;

class MetricsManager : public IMetricsManager
{
public:
    MetricsManager();

    /// @copydoc IMetricsManager::getMetricsScope
    std::shared_ptr<IMetricsScope> getMetricsScope(const std::string& name) override;
    
    /// @copydoc IMetricsManager::getScopeNames
    std::vector<std::string> getScopeNames() override;

    /// @copydoc IMetricsManager::start
    void start() override;

    /// @copydoc IMetricsManager::isRunning
    bool isRunning() override;

private:

    /// @brief Instrumentation scopes across the application.
    std::unordered_map<std::string, std::shared_ptr<MetricsScope>> m_mapScopes;

    bool m_statusRunning;

    std::mutex m_mutexScopes;
};

} // namespace metrics_manager

#endif // _METRICS_H
