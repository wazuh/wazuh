#ifndef __CATALOG_H__
#define __CATALOG_H__

#include <string>
#include <vector>
#include <memory>

#include "storageDriver/StorageDriverInterface.hpp"
#include "yml_to_json.hpp"

/**
 * @brief The Catalog class
 *
 * The Catalog class is used to manage the catalog and will be in charge of managing
 * the load, update and storage of all the assets needed by the engine.
 * It should support multiple storage systems and should make versioning easy to manage.
 *
 * #TODO Singleton
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
         * @return true if the json is valid.
         * @return false if the json is invalid.
         */
        bool validateJSON(rapidjson::Document& json, rapidjson::Document& schema);

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
