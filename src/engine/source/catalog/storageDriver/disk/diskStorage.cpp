#include <filesystem>
#include "diskStorage.hpp"
#include "../../yml2json.hpp"

/*
#TODO Replace witch RapidJSON
#TODO Create Test for DiskStorage that create a dir struct
*/
std::vector<std::string> diskStorage::getAssetList(const AssetType type)
{
    using std::string;
    using std::string_view;
    std::vector<string> assetList {};

    std::filesystem::path base_dir {this->path};
    //std::cout << "Listing files | Type: ";
    base_dir /= assetTypeToPath.at(type);

    for (const auto& entry : std::filesystem::directory_iterator(base_dir))
    {
        if (entry.is_regular_file() && entry.path().has_extension() && entry.path().extension().string() == ".yml")
        {
            //std::cout << "Adding file: '" << entry.path() << std::endl;
            const string asset_name {entry.path().stem().string()};
            assetList.push_back(std::move(asset_name));
        }
        // else {
        //     std::cout << "ignoring file: '" << entry.path() << std::endl;
        // }
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
    base_dir /= assetTypeToPath.at(type);


    string asset_name {assetName};
    string ext {};

    if (type != AssetType::Schemas) {
        ext = ".yml";
    } else {
        ext = ".json";
    }

    string_view file_name {asset_name.append(ext)};
    std::filesystem::path file_path {base_dir / file_name};

    if (std::filesystem::exists(file_path))
    {
        //std::cout << "File found: " << file_path << std::endl;
        nlohmann::ordered_json j {};

        if (type != AssetType::Schemas) {
            // @FIXME Check the exeptions
            nlohmann::ordered_json j_array {tojson::detail::loadyaml(file_path.string())};
            j = std::move(j_array[0]);
        } else {
            std::ifstream i(file_path.string());
            i >> j;
        }

        return j;
    }
    else
    {
        std::cout << "File not found: " << file_path << std::endl;
        return json {};
    }

    return json {};
}
