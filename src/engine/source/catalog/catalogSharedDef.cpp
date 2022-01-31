#include "catalogSharedDef.hpp"

#include <stdexcept>
#include <string>

AssetType stringToAssetType(const std::string & name)
{
    if (name == "decoder")
    {
        return AssetType::Decoder;
    }
    else if (name == "rule")
    {
        return AssetType::Rule;
    }
    else if (name == "output")
    {
        return AssetType::Output;
    }
    else if (name == "filter")
    {
        return AssetType::Filter;
    }
    else if (name == "schema")
    {
        return AssetType::Schema;
    }
    else if (name == "environment")
    {
        return AssetType::Environment;
    }
    else
    {
        throw std::invalid_argument("Error, asset type " + name + " is not supported");
    }
}
