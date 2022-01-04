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
        std::vector<std::string_view> getAssetList(const AssetType type) override;
        std::string getAsset(const AssetType type, std::string_view assetName) override;

};

#endif // __DISKSTORAGE_H__
