#ifndef _DISK_STORAGE_H
#define _DISK_STORAGE_H

#include <filesystem>
#include <vector>

#include "storageInterface.hpp"

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
class DiskStorage final : public IStorage
{

    /** @brief The path to the database directory */
    const std::filesystem::path mBaseDir;

public:
    /**
     * @brief Instance of a database from its directory
     * @param path The path to the database directory
     */
    DiskStorage(std::string const& baseDir);

    // Overridden methods must be documented in the interface

    /**
     * @copydoc StorageDriverInterface::getAssetList
     * @throws std::filesystem::filesystem_error whens the file cannot be read
     */
    std::vector<std::string> getFileList(const std::string& folder) override;
    /**
     * @copydoc StorageDriverInterface::getAsset
     * @throws std::runtime_error when the asset does not exist
     * @throws std::filesystem::filesystem_error whens the file cannot be read
     */
    std::string getFileContents(std::string const& file) override;
};

#endif // _DISKSTORAGE_H
