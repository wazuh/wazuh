#include "catalog.hpp"

#include <unordered_map>

#include <fmt/format.h>
#include <rapidjson/schema.h>

#include "assetStorage/diskStorage.hpp"
#include "assetStorage/storageInterface.hpp"
#include "yml2Json.hpp"

namespace catalog
{
namespace
{
static constexpr const char* EXT_JSON_SCHEMA {".json"};
static constexpr const char* EXT_OTHER_ASSET {".yml"};

/** @brief Mapping the assets types and their schemas validator. */
static const std::unordered_map<AssetType, std::string> assetTypeToSchema {
    {AssetType::Decoder, "wazuh-decoders.json"},
    {AssetType::Rule, "wazuh-rules.json"},
    {AssetType::Output, "wazuh-outputs.json"},
    {AssetType::Filter, "wazuh-filters.json"},
    {AssetType::Environment, "wazuh-environments.json"},
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
{
    switch (stype)
    {
        case StorageType::Local:
        {
            mStorage = std::make_unique<DiskStorage>(basePath);
            break;
        }
        default:
        {
            throw std::runtime_error("Storage type not supported");
            break;
        }
    }
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
    std::string assetSchemaStr;
    rapidjson::Document jsonSchema;

    auto assetPath = assetTypeToPath.find(type);
    if (assetPath == assetTypeToPath.end())
    {
        throw std::runtime_error(
            fmt::format("Invalid asset type [{}]", static_cast<int>(type)));
    }

    std::filesystem::path fullPath = assetPath->second;
    fullPath /= assetName;

    if (type == AssetType::Schema)
    {
        fullPath += EXT_JSON_SCHEMA;
        assetSchemaStr = mStorage->getFileContents(fullPath);
        jsonSchema.Parse(assetSchemaStr.c_str());
        // TODO parse error
        return jsonSchema;
    }

    fullPath += EXT_OTHER_ASSET;
    auto assetStr = mStorage->getFileContents(fullPath);

    if (assetStr.empty())
    {
        throw std::runtime_error("Asset " + assetName + " is empty");
    }

    auto schema = assetTypeToSchema.find(type);
    if (schema == assetTypeToSchema.end())
    {
        throw std::runtime_error(
            fmt::format("Could not get the schema [{}].", schema->second));
    }

    //TODO hardcoded schemas
    assetSchemaStr = mStorage->getFileContents("schemas/" + schema->second);

    jsonSchema.Parse(assetSchemaStr.c_str());

    if (jsonSchema.HasParseError())
    {
        throw std::runtime_error(
            "Could not parse the schema for the asset type.");
    }

    // if not, parse asset. Throw a YML::ParserException if the asset is not
    // valid
    rapidjson::Document asset {yml2json::loadYMLfromString(assetStr)};

    if (auto errorStr = validateJSON(asset, jsonSchema); errorStr)
    {
        throw std::runtime_error(fmt::format("Invalid asset type [{}]: [{}]",
                                             std::string {assetName},
                                             errorStr.value()));
    }

    return asset;
}

std::vector<std::string> Catalog::getAssetList(const AssetType type)
{
    auto it = assetTypeToPath.find(type);
    if (it == assetTypeToPath.end())
    {
        throw std::runtime_error(
            fmt::format("Invalid asset type [{}]", static_cast<int>(type)));
    }

    return mStorage->getFileList(it->second);
}

Catalog::~Catalog() {}
} // namespace catalog
