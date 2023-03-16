#ifndef _METRICS_SCOPE_H
#define _METRICS_SCOPE_H

#include <string>
#include <metrics/iMetricsScope.hpp>

namespace metrics_manager
{

class MetricsScope : public IMetricsScope
{
public:
    MetricsScope(const std::string& scopeName) : m_name(scopeName) {}

protected:
    std::string m_name;
};

} // namespace metrics_manager

#endif // _METRICS_SCOPE_H
