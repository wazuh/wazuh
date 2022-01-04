#include "Catalog.hpp"

rapidjson::Document Catalog::getDecoder(std::string_view decoderName) {
    rapidjson::Document decoder;
    rapidjson::Document jsonSchema;

    decoder = storageDriver->getAsset(AssetType::Decoder, decoderName);
    jsonSchema = storageDriver->getAsset(AssetType::Schemas, "wazuh-decoder");

    // #TODO
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

bool Catalog::validateJSON(rapidjson::Document& json, rapidjson::Document& schema) {
    // #TODO
    return false;
}
