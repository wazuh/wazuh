#ifndef __DISKSTORAGE_H__
#define __DISKSTORAGE_H__

#include <iostream>
#include <vector>
#include <map>
#include "../storageDriverInterface.hpp"
#include "../yml_to_json.hpp"


class diskStorage : public storageDriverInterface
{

    private:

        const std::string_view path;
        // #FIXME Optimize: search a maps with number 4 keys
        static const inline std::map<AssetType, std::string> assetTypeToPath
        {
            {AssetType::Decoder, "decoders"},
            {AssetType::Rule, "rules"},
            {AssetType::Output, "outputs"},
            {AssetType::Filter, "filters"},
            {AssetType::Schemas, "schemas"},
            {AssetType::Environments, "environments"}
        };

    public:

        diskStorage(std::string_view path) : path(path)
        {
            //std::cout << "New driver | Path: " << this->path << std::endl;
        }
        ~diskStorage() = default;

        std::vector<std::string> getAssetList(const AssetType type) override;
        rapidjson::Document getAsset(const AssetType type, const std::string_view assetName) override;

};

#endif // __DISKSTORAGE_H__
