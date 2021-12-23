#ifndef __DISKSTORAGE_H__
#define __DISKSTORAGE_H__

#include <iostream>
#include <vector>

#include "../../catalogSharedDef.hpp"

#include "nlohmann/json.hpp"
// using json = nlohmann::json;

class diskStorage {

    private:

        const std::string_view path;

    public:

        diskStorage(std::string_view path) : path(path) {
            std::cout << "New driver | Path: " << this->path << std::endl;
        }
        ~diskStorage() = default;

        std::vector<std::string> getAssetList(const AssetType type);
        nlohmann::ordered_json getAsset(const AssetType type, const std::string_view assetName);

};


#endif // __DISKSTORAGE_H__