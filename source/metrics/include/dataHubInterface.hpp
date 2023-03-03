#ifndef _DATA_HUB_INTERFACE_H
#define _DATA_HUB_INTERFACE_H

#include <json/json.hpp>
#include <string>

class DataHubInterface
{
public:
    /// @brief updates the data of the referenced object
    /// @param scope name of the resource scope
    /// @param object json object with updated information
    virtual void setResource(const std::string& scope, json::Json object) = 0;
};

#endif // _DATA_HUB_INTERFACE_H
