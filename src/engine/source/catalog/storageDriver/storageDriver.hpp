#ifndef __STORAGEDRIVER_H__
#define __STORAGEDRIVER_H__

#include "../catalogSharedDef.hpp"
#include "nlohmann/json.hpp"

class storageDriver{

public:
    storageDriver();
    ~storageDriver();
    std::vector<std::string> getAssetList(const AssetType type);
    nlohmann::json getAsset(const AssetType type, const std::string_view assetName);
};

#endif // __STORAGEDRIVER_H__
