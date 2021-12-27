#ifndef __STORAGEDRIVERINTERFACE_H__
#define __STORAGEDRIVERINTERFACE_H__

#include "../catalogSharedDef.hpp"
#include "nlohmann/json.hpp"

class storageDriverInterface {

public:

    virtual ~storageDriverInterface() = default;
    virtual std::vector<std::string> getAssetList(const AssetType type) = 0;
    virtual nlohmann::ordered_json getAsset(const AssetType type, const std::string_view assetName) = 0;
};

#endif // __STORAGEDRIVERINTERFACE_H__
