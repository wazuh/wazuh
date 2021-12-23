#include <filesystem>
#include "diskStorage.hpp"
#include "../../yml2json.hpp"

std::vector<std::string> diskStorage::getAssetList(const AssetType type)
{
    using std::string;
    using std::string_view;
    std::vector<string> assetList {};

    std::filesystem::path base_dir {this->path};
    std::cout << "Listing files | Type: ";

    switch (type)
    {
        case AssetType::Decoder:
            std::cout << "Decoder" << std::endl;
            base_dir /= "decoders";
            break;

        case AssetType::Rule:
            std::cout << "Rules" << std::endl;
            base_dir /= "rules";
            break;

        case AssetType::JSONSchema:
            std::cout << "JSONSchema" << std::endl;
            base_dir /= "schemas";
            break;

        case AssetType::Filter:
            std::cout << "Filter" << std::endl;
            base_dir /= "filters";
            break;

        default:
            std::cout << "Unknown" << std::endl;
            break;
    }

    for (const auto& entry : std::filesystem::directory_iterator(base_dir))
    {
        if (entry.is_regular_file() && entry.path().has_extension() && entry.path().extension().string() == ".yml")
        {
            std::cout << "Adding file: '" << entry.path() << "' . A yml file"  << std::endl;
            const string asset_name {entry.path().stem().string()};
            assetList.push_back(std::move(asset_name));
            // } else
            // {
            //     std::cout << "ignoring file: '" << entry.path() << "' . Not a yml file"  << std::endl;
        }
    }

    return assetList;
}

nlohmann::ordered_json diskStorage::getAsset(const AssetType type, const std::string_view assetName)
{
    using std::string;
    using std::string_view;
    using nlohmann::json;

    std::filesystem::path base_dir {this->path};
    //    std::cout << "Getting file | Type: ";

    switch (type)
    {
        case AssetType::Decoder:
            //          std::cout << "Decoder" << std::endl;
            base_dir /= "decoders";
            break;

        case AssetType::Rule:
            //        std::cout << "Rules" << std::endl;
            base_dir /= "rules";
            break;

        case AssetType::JSONSchema:
            //        std::cout << "JSONSchema" << std::endl;
            base_dir /= "schemas";
            break;

        case AssetType::Filter:
            //        std::cout << "Filter" << std::endl;
            base_dir /= "filters";
            break;

        default:
            //        std::cout << "Unknown" << std::endl;
            break;
    }

    string asset_name {assetName};
    string ext {".yml"};
    string_view file_name {asset_name + ext};
    std::filesystem::path file_path {base_dir / file_name};

    if (std::filesystem::exists(file_path))
    {
        std::cout << "File found: " << file_path << std::endl;

        nlohmann::ordered_json j {tojson::detail::loadyaml(file_path.string())};
        return j;
    }
    else
    {
        std::cout << "File not found: " << file_path << std::endl;
        return json {};
    }

    return json {};
}
