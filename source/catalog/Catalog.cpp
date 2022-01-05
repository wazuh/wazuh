#include "Catalog.hpp"
#include "rapidjson/schema.h"

rapidjson::Document Catalog::getDecoder(std::string_view decoderName) {

    using std::string;
    using rapidjson::Document;

    auto decoderStr = storageDriver->getAsset(AssetType::Decoder, decoderName);
    auto jsonSchemaStr = storageDriver->getAsset(AssetType::Schemas, "wazuh-decoder");

    Document decoder {yml2json::loadYMLfromString(std::move(decoderStr))};
    Document jsonSchema {yml2json::loadYMLfromString(std::move(jsonSchemaStr))};

    // Validate the decoder
    auto errorStr = validateJSON(decoder, jsonSchema);
    std::cout << "Validation result: " << errorStr.value_or("OK") << std::endl;

    if (errorStr) {
        return {};
    }

    return decoder;
}

std::vector<std::string_view> Catalog::getDecoderList() {
    // #TODO
    return {};
}

rapidjson::Document getJSONSchema(AssetType assetType) {
    // #TODO
    return {};
}

std::optional<std::string> Catalog::validateJSON(rapidjson::Document& json, rapidjson::Document& schema) {

    rapidjson::SchemaDocument schemaDocument(schema);
    rapidjson::SchemaValidator validator(schemaDocument);

    if (!json.Accept(validator)) {
        // Input JSON is invalid according to the schema
        std::ostringstream oss {};
        rapidjson::StringBuffer sb;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        oss << "Invalid JSON schema: '" << sb.GetString() << "'" << std::endl;

        oss << "Invalid keyword: '" << validator.GetInvalidSchemaKeyword() << "'" << std::endl;
        sb.Clear();

        validator.GetInvalidDocumentPointer().StringifyUriFragment(sb);
        oss << "Invalid document: '" << sb.GetString() << "'" << std::endl;

        return oss.str();
    }

    return {};
}

rapidjson::Document Catalog::getAsset(const AssetType type, std::string_view assetName) {

    using std::string;
    using rapidjson::Document;

    string assetStr {};
    string assetSchemaStr {};

    switch (type) {
        case AssetType::Decoder:
        case AssetType::Rule:
        case AssetType::Output:
        case AssetType::Filter:

            assetStr = storageDriver->getAsset(type, assetName);
            if (assetStr.empty()) {
                return {};
            }

            assetSchemaStr = storageDriver->getAsset(AssetType::Schemas, assetTypeToSchema.at(type));
            if (assetSchemaStr.empty()) {
                throw std::runtime_error("Could not get the schema '" + assetTypeToSchema.at(type) + "' for the asset type.");
            }

            break;
        case AssetType::Schemas:
        case AssetType::Environments:
        default:
            throw std::runtime_error("Not implemented");
            break;
    }

    // Throw a YML::ParserException if the asset is not valid
    Document asset {yml2json::loadYMLfromString(assetStr)};
    Document jsonSchema {yml2json::loadYMLfromString(assetSchemaStr)};

    // Validate the asset
    auto errorStr = validateJSON(asset, jsonSchema);
    if (errorStr) {
        throw std::runtime_error("The asset '" + string{assetName} + "' is invalid: " + errorStr.value());
    }

    return asset;
}
