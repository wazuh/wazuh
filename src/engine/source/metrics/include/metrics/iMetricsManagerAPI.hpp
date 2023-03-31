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
    virtual std::variant<std::string, base::Error> dumpCmd() = 0;

    /**
     * @brief
     *
     * @param scopeName
     * @param instrumentName
     * @param newStatus
     */
    virtual void enableCmd(const std::string& scopeName, const std::string& instrumentName, bool newStatus) = 0;

    /**
     * @brief
     *
     */
    virtual void testCmd() = 0;
    virtual std::variant<std::string, base::Error> listCmd() = 0;
};

}
#endif // _I_METRICS_MANAGER_API_H
