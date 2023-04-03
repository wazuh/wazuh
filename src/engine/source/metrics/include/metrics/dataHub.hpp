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
    /// @brief get a copy of the resource data in json object
    /// @param scope  name of the resource scope
    /// @return copy of resource data in json object
    json::Json getResource(const std::string& scope);

    /// @brief updates the data of the referenced object
    /// @param scope name of the resource scope
    /// @param object json object with updated information
    void setResource(const std::string& scope, json::Json object) override;

    json::Json getAllResources();

private:
    std::map<std::string, json::Json> m_resources;
    std::mutex m_mutex;
};
} // namespace metricsManager

#endif // _DATA_HUB_H
