#ifndef _STORAGE_DRIVER_INTERFACE_H
#define _STORAGE_DRIVER_INTERFACE_H

#include <vector>
#include <string>

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
class IStorage
{

    public:
        //! @brief The destructor
        virtual ~IStorage() = default;

        /**
         * @brief Gets a list of available assets of a specific type
         *
         * @param type The asset type
         * @return std::vector<std::string> List of assets
         */
        virtual std::vector<std::string> getFileList(std::string const& folder) = 0;

        /**
         * @brief Get the Asset object
         *
         * @param type Type of the asset
         * @param assetName Name of the asset
         * @throw std::runtime_error If the asset does not exist or cannot be recovered
         * @return std::string The asset as a string
         */
        virtual std::string getFileContents(std::string const& file) = 0;
};

#endif // _STORAGEDRIVERINTERFACE_H
