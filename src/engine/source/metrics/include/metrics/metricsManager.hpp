#ifndef _METRICS_MANAGER_H
#define _METRICS_MANAGER_H

#include <memory>
#include <mutex>
#include <unordered_map>

#include <metrics/iMetricsManager.hpp>
#include <metrics/iMetricsManagerAPI.hpp>
#include <metrics/dataHub.hpp>
#include <metrics/metricsScope.hpp>

namespace metricsManager
{

/**
 * @brief Metrics Module implementation. This
 *
 */
class MetricsManager : public IMetricsManager, public IMetricsManagerAPI
{
public:
    MetricsManager();

    /**
     * @copydoc IMetricsManager::getMetricsScope
    */
    std::shared_ptr<IMetricsScope> getMetricsScope(const std::string& name, bool delta = false, int exporterIntervalMS = 1000, int exporterTimeoutMS = 300) override;

    /**
     * @copydoc IMetricsManager::getScopeNames
    */
    std::vector<std::string> getScopeNames() override;

    /**
     * @copydoc IMetricsManager::start
    */
    void start() override;

    /**
     * @copydoc IMetricsManager::isRunning
    */
    bool isRunning() override;

    /**
     * @copydoc IMetricsManager::getAllMetrics
    */
    json::Json getAllMetrics() override;

    // API Commands
    std::variant<std::string, base::Error> dumpCmd() override;

    /**
     * @copydoc iMetricsManagerAPI::getCmd
    */
    std::variant<std::string, base::Error> getCmd(const std::string& scopeName, const std::string& instrumentName) override;

    /**
     * @copydoc iMetricsManagerAPI::enableCmd
    */
    std::optional<base::Error> enableCmd(const std::string& scopeName, const std::string& instrumentName, bool newStatus) override;

    /**
     * @copydoc iMetricsManagerAPI::testCmd
    */
    void testCmd() override;

    /**
     * @copydoc iMetricsManagerAPI::listCmd
    */
    std::variant<std::string, base::Error> listCmd() override;

private:
    /**
     * @brief Mapping of Metric Scopes by their respective names.
     */
    std::map<std::string, std::shared_ptr<MetricsScope>> m_mapScopes;

    /**
     * @brief Holds the Running Status of the Manager
     */
    bool m_statusRunning;

    /**
     * @brief Synchronization Object for the Scopes Mapping
     */
    std::mutex m_mutexScopes;

    /**
     * @brief Metrics Scope for Testing Instrument
     */
    std::shared_ptr<metricsManager::IMetricsScope>  m_scopeMetrics;

    /**
     * @brief Get the MetricsScope object.
     *
     * @param metricsScopeName Name of the Scope.
     * @return Shared Pointer to the Scope itself.
     */
    std::shared_ptr<MetricsScope> getScope(const std::string& metricsScopeName);
};

} // namespace metricsManager

#endif // _METRICS_MANAGER_H
