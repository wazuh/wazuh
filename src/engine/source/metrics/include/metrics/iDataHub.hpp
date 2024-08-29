#ifndef _I_METRICS_DATAHUB_H
#define _I_METRICS_DATAHUB_H

#include <base/json.hpp>
#include <string>

namespace metricsManager
{

/**
 * @brief Inteface for DataHub Container
 */
class IDataHub
{
public:
    /**
     * @brief Updates the data of the referenced object.
     *
     * @param scope Name of the resource scope.
     * @param object JSON object with updated information.
     */
    virtual void setResource(const std::string& scope, const json::Json& object) = 0;
};

} // namespace metricsManager

#endif // _I_METRICS_DATAHUB_H
