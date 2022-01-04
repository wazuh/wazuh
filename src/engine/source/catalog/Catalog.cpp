#include "Catalog.hpp"

rapidjson::Document Catalog::getDecoder(std::string_view decoderName) {

    using std::string;
    using rapidjson::Document;

    auto decoderStr = storageDriver->getAsset(AssetType::Decoder, decoderName);
    auto jsonSchemaStr = storageDriver->getAsset(AssetType::Schemas, "wazuh-decoder");

    Document decoder {yml2json::loadYMLfromString(std::move(decoderStr))};

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
