#ifndef __STORAGEDRIVERINTERFACE_H__
#define __STORAGEDRIVERINTERFACE_H__

#include "../catalogSharedDef.hpp"
#include "rapidjson/document.h"

class storageDriverInterface
{

    public:

        virtual ~storageDriverInterface() = default;
        virtual std::vector<std::string> getAssetList(const AssetType type) = 0;
        virtual rapidjson::Document getAsset(const AssetType type, const std::string_view assetName) = 0;
};

#endif // __STORAGEDRIVERINTERFACE_H__
