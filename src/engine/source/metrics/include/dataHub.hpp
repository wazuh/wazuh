#ifndef _DATA_HUB_H
#define _DATA_HUB_H

#include <dataHubInterface.hpp>
#include <json/json.hpp>
#include <map>
#include <mutex>
#include <variant>

class DataHub : public DataHubInterface
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

    /// @brief dumps the content of m_resources to standard output
    void dump();

    /// @brief dumps the content of m_resources to cmd
    std::variant<json::Json, base::Error> dumpCmd();
    /// @brief get an element of m_resources to cmd
    std::variant<json::Json, base::Error> getCmd(const std::string& instrumentName);

    /// @brief return instance of DataHub
    static std::shared_ptr<DataHub> get();

private:
    std::map<std::string, json::Json> m_resources;
    std::mutex m_mutex;
};

#endif // _DATA_HUB_H
