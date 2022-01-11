#ifndef __DISKSTORAGE_H__
#define __DISKSTORAGE_H__

#include <iostream>
#include <vector>
#include <map>
#include "../StorageDriverInterface.hpp"

/*
 * #TODO Implement thread-safe mechanism
 * @warning this class is not thread-safe
 */

/**
 * @brief Disk storage driver
 *
 * This class is a disk storage driver.
 * It is used to manage assets on disk.
 *
 * Directory structure is:
 * - /decoders
 *  - <decoder_name>.yml
 * - /rules
 *  - <rule_name>.yml
 * - /outputs
 *  - <output_name>.yml
 * - /filters
 *  - <filter_name>.yml
 * - /environments
 *  - <environment_name>.yml
 * - /schemas
 *  - <schema_name>.json
 *
 * @warning This class is not thread-safe
 * @see StorageDriverInterface
 */
class diskStorage : public StorageDriverInterface
{

    private:

        /** @brief The path to the database directory */
        const std::string_view path;

        /** @brief Mapping the assets and the storage directory */
        static const inline std::map<AssetType, std::string> assetTypeToPath
        {
            {AssetType::Decoder, "decoders"},
            {AssetType::Rule, "rules"},
            {AssetType::Output, "outputs"},
            {AssetType::Filter, "filters"},
            {AssetType::Schemas, "schemas"},
            {AssetType::Environments, "environments"}
        };

    public:

        /**
         * @brief Instance of a database from its directory
         * @param path The path to the database directory
         */
        diskStorage(std::string_view path) : path(path) {}
        ~diskStorage() = default;

        // Overridden methods must be documented in the interface

        /**
         * @copydoc StorageDriverInterface::getAssetList
         * @throws std::filesystem::filesystem_error whens the file cannot be read
        */
        std::vector<std::string> getAssetList(const AssetType type) override;
        /**
         * @copydoc StorageDriverInterface::getAsset
         * @throws std::runtime_error when the asset does not exist
         * @throws std::filesystem::filesystem_error whens the file cannot be read
         */
        std::string getAsset(const AssetType type, std::string_view assetName) override;

};

#endif // __DISKSTORAGE_H__
