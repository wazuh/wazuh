#ifndef _I_METRICS_MANAGER_API_H
#define _I_METRICS_MANAGER_API_H

#include <variant>

#include <json/json.hpp>

namespace metrics_manager
{

class IMetricsManagerAPI
{
public:
    /// @brief Command: Dump all resources
    virtual std::variant<json::Json, base::Error> dumpCmd() = 0;
};

}
#endif // _I_METRICS_MANAGER_API_H
