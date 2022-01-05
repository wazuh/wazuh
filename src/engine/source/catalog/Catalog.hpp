#ifndef __CATALOG_H__
#define __CATALOG_H__

#include <string>
#include <vector>
#include <memory>

#include "yml_to_json.hpp"
#include "rapidjson/document.h"
#include "catalogSharedDef.hpp"
#include "storageDriver/StorageDriverInterface.hpp"

/**
 * @brief The Catalog class
 *
 * The Catalog class is used to manage the catalog and will be in charge of managing
 * the load, update and storage of all the assets needed by the engine.
 * It should support multiple storage systems and should make versioning easy to manage.
 * ----------TODO Singleton
 * The Catalog class is a singleton. (@warning not implemented yet)
 */
class Catalog {

    private:

        //! @brief The storage driver.
        std::unique_ptr<StorageDriverInterface> storageDriver;

        /**
         * @brief Validate json through the schema.
         *
         * @param json The json to validate.
         * @param schema The schema to validate against.
         * @return std::optional<std::string> The error message if the json is not valid.
         */
        std::optional<std::string> validateJSON(rapidjson::Document& json, rapidjson::Document& schema);

        /** @brief Mapping the assets and the schema validator */
        static const inline std::map<AssetType, std::string> assetTypeToSchema
        {
            {AssetType::Decoder, "wazuh-decoders"},
            {AssetType::Rule, "wazuh-rules"},
            {AssetType::Output, "wazuh-outputs"},
            {AssetType::Filter, "wazuh-filters"},
            {AssetType::Schemas, ""},
            {AssetType::Environments, ""}
        };

        std::string jsonToString(rapidjson::Document& json) {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            json.Accept(writer);
            return buffer.GetString();
        }

    public:
        /**
         * @brief Create the catalog manager from the given driver to connect.
         *
         * The catalog take the ownership of the driver.
         * The driver will be deleted when the catalog is destroyed.
         * @param storageDriver The storage driver to connect to. The driver is destroyed when the catalog is freed.
         */
        Catalog(std::unique_ptr<StorageDriverInterface> storageDriver) {
            this->storageDriver = std::move(storageDriver);
        }

        /**
         * @brief Dump pending changes and freed driver storage.
         */
        ~Catalog() {
            storageDriver.reset();
        }

        /**
         * @brief Get the Asset object
         *
         * @param type The type of the asset. Only decoder, rules, filter and schema are supported.
         * @param assetName The name of the asset.
         * @return rapidjson::Document The asset object. If the asset is not found, the document is empty.
         * @throws std::runtime_error If the asset is corrupted or cannot get the json schema to validate against.
         * @throws CatalogExeptions The storage driver throws an exception.
         *
         */
        rapidjson::Document getAsset(const AssetType type, std::string_view assetName);

        /**
         * @brief Get the decoder for the given decoder name.
         * @param decoderName The name of the decoder.
         * @return The decoder or an empty document if could not be found.
         * @throw std::runtime_error if the decoder its invalid or the storage driver failed to get the decoder.
         */
        rapidjson::Document getDecoder(std::string_view decoderName);

        /**
         * @brief Get the JSON schema for the given assetType
         *
         * Only decoder, rule, filter and output are valid assetType.
         * @param assetType The type of the asset ()
         * @return The JSON schema or an empty document if could not be found.
         * @throws std::runtime_error if the assetType is invalid or the storage driver failed to get the JSON schema.
         */
        rapidjson::Document getJSONSchema(AssetType assetType);

        /**
         * @brief Get the Decoder list
         * @return std::vector<std::string_view> the list of decoders.
         * @throw std::runtime_error if the storage driver failed to get the decoder list.
         */
        std::vector<std::string_view> getDecoderList();
};
#endif // __CATALOG_H__
