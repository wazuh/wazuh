#ifndef _I_DATA_HUB_H
#define _I_DATA_HUB_H

#include <json/json.hpp>
#include <string>

namespace metrics_manager
{

class IDataHub
{
public:
    /// @brief updates the data of the referenced object
    /// @param scope name of the resource scope
    /// @param object json object with updated information
    virtual void setResource(const std::string& scope, json::Json object) = 0;
};

} // namespace metrics_manager

#endif // _I_DATA_HUB_H
