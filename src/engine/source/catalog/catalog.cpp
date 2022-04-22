#include "catalog.hpp"

#include <filesystem>
#include <fstream>
#include <unordered_map>

#include <fmt/format.h>
#include <rapidjson/schema.h>

#include "yml2Json.hpp"

namespace catalog
{
namespace
{
static constexpr const char* EXT_JSON_SCHEMA {".json"};
static constexpr const char* EXT_OTHER_ASSET {".yml"};

/** @brief Mapping the assets types and their schemas validator. */
static const std::unordered_map<AssetType, std::string> assetTypeToSchema {
    {AssetType::Decoder, "wazuh-decoders"},
    {AssetType::Rule, "wazuh-rules"},
    {AssetType::Output, "wazuh-outputs"},
    {AssetType::Filter, "wazuh-filters"},
    {AssetType::Environment, "wazuh-environments"},
    {AssetType::Schema, ""}};

/** @brief Mapping the assets and the storage directory */
static const std::unordered_map<AssetType, std::string> assetTypeToPath {
    {AssetType::Decoder, "decoders"},
    {AssetType::Rule, "rules"},
    {AssetType::Output, "outputs"},
    {AssetType::Filter, "filters"},
    {AssetType::Schema, "schemas"},
    {AssetType::Environment, "environments"}};

static const std::unordered_map<std::string, AssetType> stringToAssetType {
    {"decoder", AssetType::Decoder},
    {"rule", AssetType::Rule},
    {"output", AssetType::Output},
    {"filter", AssetType::Filter},
    {"schema", AssetType::Schema},
    {"environment", AssetType::Environment},
};

std::string readFileFromDisk(std::filesystem::path const& file)
{
    std::ifstream in(file, std::ios::in | std::ios::binary);
    if (in)
    {
        std::string contents;
        in.seekg(0, std::ios::end);
        contents.resize(in.tellg());
        in.seekg(0, std::ios::beg);
        in.read(&contents[0], contents.size());
        in.close();
        return contents;
    }

    throw std::runtime_error(fmt::format(
        "Error oppening asset [{}]. Error [{}]", file.string(), errno));
}
} // namespace

std::optional<std::string> validateJSON(rapidjson::Document& json,
                                        rapidjson::Document& schema)
{
    rapidjson::SchemaDocument schemaDocument {schema};
    rapidjson::SchemaValidator validator {schemaDocument};

    if (!json.Accept(validator))
    {
        // Input JSON is invalid according to the schema
        rapidjson::StringBuffer sb;
        rapidjson::StringBuffer docPtr;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        validator.GetInvalidDocumentPointer().StringifyUriFragment(docPtr);
        return fmt::format("Invalid JSON schema: [{}]\n"
                           "Invalid keyword: [{}]\n"
                           "Invalid document: [{}]",
                           sb.GetString(),
                           validator.GetInvalidSchemaKeyword(),
                           docPtr.GetString());
    }

    return {};
}

Catalog::Catalog(StorageType stype, std::string const& basePath)
    : mStorageType(stype)
    , mBasePath(basePath)
{
}

rapidjson::Document Catalog::getAsset(const std::string& type,
                                      std::string const& assetName) const
{
    auto it = stringToAssetType.find(type);
    if (it == stringToAssetType.end())
    {
        throw std::runtime_error("Invalid Asset type");
    }

    return getAsset(it->second, assetName);
}

rapidjson::Document Catalog::getAsset(const AssetType type,
                                      std::string const& assetName) const
{
    auto assetStr = getFileContents(type, assetName);
    if (assetStr.empty())
    {
        throw std::runtime_error("Asset " + assetName + " is empty");
    }

    rapidjson::Document jsonSchema;
    if (type == AssetType::Schema)
    {
        jsonSchema.Parse(assetStr.c_str());
        if (jsonSchema.HasParseError())
        {
            throw std::runtime_error("Could not parse the schema.");
        }
        return jsonSchema;
    }

    auto schema = assetTypeToSchema.find(type);
    if (schema == assetTypeToSchema.end())
    {
        throw std::runtime_error(
            fmt::format("Could not get the schema [{}].", schema->second));
    }

    auto schemaStr = getFileContents(AssetType::Schema, schema->second);
    jsonSchema.Parse(schemaStr.c_str());
    if (jsonSchema.HasParseError())
    {
        throw std::runtime_error(
            "Could not parse the schema for the asset type.");
    }

    rapidjson::Document asset {yml2json::loadYMLfromString(assetStr)};
    if (auto errorStr = validateJSON(asset, jsonSchema); errorStr)
    {
        throw std::runtime_error(fmt::format("Invalid asset type [{}]: [{}]",
                                             std::string {assetName},
                                             errorStr.value()));
    }

    return asset;
}

std::string Catalog::getFileContents(AssetType type,
                                     std::string const& file) const
{
    if (mStorageType == StorageType::Local)
    {
        std::filesystem::path fullPath = mBasePath;

        auto assetPath = assetTypeToPath.find(type);
        if (assetPath == assetTypeToPath.end())
        {
            throw std::runtime_error(
                fmt::format("Invalid asset type [{}]", static_cast<int>(type)));
        }

        fullPath /= assetPath->second;
        fullPath /= file;

        if (type == AssetType::Schema)
        {
            fullPath += EXT_JSON_SCHEMA;
        }
        else
        {
            fullPath += EXT_OTHER_ASSET;
        }

        return readFileFromDisk(fullPath);
    }

    return {};
}
} // namespace catalog
