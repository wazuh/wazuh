#ifndef _DATA_HUB_H
#define _DATA_HUB_H

#include <map>
#include <mutex>
#include <variant>

#include <json/json.hpp>
#include <metrics/iDataHub.hpp>

namespace metricsManager
{

class DataHub : public IDataHub
{
public:
    /**
     * @brief Get a copy of the resource data in JSON object.
     *
     * @param scope Name of the resource scope.
     * @return Copy of resource data in JSON object.
     */
    json::Json getResource(const std::string& scope);

    /**
     * @copydoc IDataHub.setResource
     */
    void setResource(const std::string& scope, json::Json object) override;

    /**
     * @brief Gets a json representation of the contained resources.
     *
     * @return JSON object with the information.
     */
    json::Json getAllResources();

private:
    /**
     * @brief Map of strings to json objects containing resources
     */
    std::map<std::string, json::Json> m_resources;

    /**
     * @brief Synchronization object
     *
     */
    std::mutex m_mutex;
};
} // namespace metricsManager

#endif // _DATA_HUB_H
