#ifndef __STORAGEDRIVERINTERFACE_H__
#define __STORAGEDRIVERINTERFACE_H__

#include "../catalogSharedDef.hpp"
#include "rapidjson/document.h"

/**
 * @brief The StorageDriverInterface class
 *
 * This class is the interface for all storage drivers,
 * which will be used to store the data of the catalog.
 */
class storageDriverInterface
{

    public:
        //! @brief The destructor
        virtual ~storageDriverInterface() = default;

        /**
         * @brief Gets a list of available assets of a specific type
         *
         * @param type The asset type (\ref assetType)
         * @return std::vector<std::string> List of assets
         */
        virtual std::vector<std::string> getAssetList(const AssetType type) = 0;

        /**
         * @brief Get the Asset object
         *
         * @param type Type of the asset (\ref assetType)
         * @param assetName Name of the asset
         * @return rapidjson::Document The asset object
         */
        virtual rapidjson::Document getAsset(const AssetType type, const std::string_view assetName) = 0;
};

#endif // __STORAGEDRIVERINTERFACE_H__
