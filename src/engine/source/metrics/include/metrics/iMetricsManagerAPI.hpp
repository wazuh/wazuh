#ifndef _I_METRICS_MANAGER_API_H
#define _I_METRICS_MANAGER_API_H

#include <variant>

#include <base/json.hpp>

namespace metricsManager
{
/**
 * @brief The Interface of the API commands that the Metrics Manager must implement.
 */
class IMetricsManagerAPI
{
public:
    /**
     * @brief Implements the DUMP command, which retrieves all the contained instrument data in all of the Scopes.
     *
     * @return The Json representation of the data or Error.
     */
    virtual std::variant<std::string, base::Error> dumpCmd() = 0;

    /**
     * @brief Implements the Enable command, which sets wether the instrument updates their value or not.
     *
     * @param scopeName Name of the Scope.
     * @param instrumentName Name of the Instrument.
     * @param newStatus The new status. True Enabled. False Disabled.
     * @return The Error code.
     */
    virtual std::optional<base::Error> enableCmd(const std::string& scopeName, const std::string& instrumentName, bool newStatus) = 0;

    /**
     * @brief Implements the GET command, which retrieves instrument data based on scope and instrument names.
     *
     * @param scopeName Name of the Scope.
     * @param instrumentName Name of the Instrument.
     * @return The json representation of the instrument data or Error.
     */
    virtual std::variant<std::string, base::Error> getCmd(const std::string& scopeName, const std::string& instrumentName) = 0;

    /**
     * @brief Implements the TEST command, which creates a testing counter and increases its value for testing purposes.
     *
     */
    virtual void testCmd() = 0;

    /**
     * @brief Implements the LIST command, which returns a brief list of scopes, instruments, types and status.
     *
     * @return The Json representation of the list in array of objects form or Error.
     */
    virtual std::variant<std::string, base::Error> listCmd() = 0;
};

}
#endif // _I_METRICS_MANAGER_API_H
