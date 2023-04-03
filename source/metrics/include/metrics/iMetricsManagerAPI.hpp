#ifndef _I_METRICSMANAGER_API_H
#define _I_METRICSMANAGER_API_H

#include <variant>

#include <json/json.hpp>

namespace metricsManager
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
     * @brief Get the Cmd object
     * 
     * @param scopeName 
     * @param instrumentName 
     * @return std::variant<std::string, base::Error> 
     */
    virtual std::variant<std::string, base::Error> getCmd(const std::string& scopeName, const std::string& instrumentName) = 0;

    /**
     * @brief 
     * 
     */
    virtual void testCmd() = 0;
    virtual std::variant<std::string, base::Error> listCmd() = 0;
};

}
#endif // _I_METRICSMANAGER_API_H
