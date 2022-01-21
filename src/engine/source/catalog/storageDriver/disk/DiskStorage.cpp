#include <filesystem>
#include <fstream>
#include <iostream>

#include "DiskStorage.hpp"
#include "rapidjson/istreamwrapper.h"

constexpr std::string_view EXT_JSON_SCHEMA {".json"};
constexpr std::string_view EXT_OTHER_ASSET {".yml"};

// Overridden method
std::vector<std::string> DiskStorage::getAssetList(const AssetType type)
{
    using std::string;

    std::vector<string> assetList {};
    std::filesystem::path base_dir {this->path};

    // Get the path to the asset directory
    base_dir /= assetTypeToPath.at(type);

    for (const auto& entry : std::filesystem::directory_iterator(base_dir))
    {
        if (entry.is_regular_file() && entry.path().has_extension())
        {
            // Only the json schema has the json extension
            const auto extension = entry.path().extension().string();

            if (extension == EXT_OTHER_ASSET ||
                    (extension == EXT_JSON_SCHEMA && type == AssetType::Schemas))
            {
                assetList.push_back(string {entry.path().stem().string()});
            }
        }

    }

    return assetList;
}

// Overridden method
std::string DiskStorage::getAsset(const AssetType type, std::string assetName)
{
    using std::string;
    using rapidjson::Document;
    namespace fs = std::filesystem;

    fs::path base_dir {this->path};
    string assetStr {};

    /* Get the path to the asset directory */
    base_dir /= assetTypeToPath.at(type);

    if (type == AssetType::Schemas)
    {
        assetName.append(EXT_JSON_SCHEMA);
    }
    else
    {
        assetName.append(EXT_OTHER_ASSET);
    }

    /* Get full path to the asset file */
    fs::path file_path {base_dir / assetName};

    // Throws std::filesystem::filesystem_error
    if (fs::exists(file_path))
    {
        std::ifstream ifs {file_path.string()};

        if (ifs)
        {
            std::ostringstream oss {};
            oss << ifs.rdbuf();
            assetStr = oss.str();
        }
        else
        {
            // Non regular file or not readable
            throw std::runtime_error {"Error reading file: '" + assetTypeToPath.at(type)
                                      + "/" + assetName + "'"};
        }
    }
    else
    {
        throw std::runtime_error {"Asset not found in file: '" + assetTypeToPath.at(type)
                                  + "/" + assetName + "'"};
    }

    return assetStr;
}
