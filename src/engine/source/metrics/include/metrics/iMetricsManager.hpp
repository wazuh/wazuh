#ifndef _I_METRICS_MANAGER_H
#define _I_METRICS_MANAGER_H

#include <string>
#include <unordered_map>

namespace metrics_manager
{

class IMetricsScope;

class IMetricsManager
{
public:
    virtual std::shared_ptr<IMetricsScope> getMetricsScope(const std::string& name) = 0;
};

} // namespace metrics_manager

#endif // _I_METRICS_MANAGER_H
