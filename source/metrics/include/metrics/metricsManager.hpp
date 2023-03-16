#ifndef _METRICS_H
#define _METRICS_H

#include <memory>
#include <unordered_map>

#include <utils/baseMacros.hpp>
#include <metrics/iMetricsManager.hpp>


namespace metrics_manager
{

class MetricsScope;

class MetricsManager : public IMetricsManager
{
public:

    WAZUH_DISABLE_COPY_ASSIGN(MetricsManager);
    MetricsManager();

    std::shared_ptr<IMetricsScope> getMetricsScope(const std::string& name) override;

private:
    std::unordered_map<std::string, std::shared_ptr<MetricsScope>> m_mapScopes;
};

} // namespace metrics_manager

#endif // _METRICS_H
