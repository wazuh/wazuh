#ifndef __STORAGEDRIVERINTERFACE_H__
#define __STORAGEDRIVERINTERFACE_H__

#include <vector>
#include <string>

#include "../catalogSharedDef.hpp"
#include "rapidjson/document.h"

/**
 * @brief The StorageDriverInterface class
 *
 * This class is the interface for all storage drivers,
 * which will be used to store the data of the catalog.
 *
 * The classes that implement this interface are stateless, they connect to
 * the database and without storing the state.
 *
 * Implementations are thread-safe.
 */
class StorageDriverInterface
{

    public:
        //! @brief The destructor
        virtual ~StorageDriverInterface() = default;

        /**
         * @brief Gets a list of available assets of a specific type
         *
         * @param type The asset type
         * @return std::vector<std::string_view> List of assets
         */
        virtual std::vector<std::string_view> getAssetList(const AssetType type) = 0;

        /**
         * @brief Get the Asset object
         *
         * @param type Type of the asset
         * @param assetName Name of the asset
         * @return rapidjson::Document The asset object
         */
        virtual rapidjson::Document getAsset(const AssetType type, std::string_view assetName) = 0;
};

#endif // __STORAGEDRIVERINTERFACE_H__
