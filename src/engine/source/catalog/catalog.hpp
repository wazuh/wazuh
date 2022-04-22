#ifndef _CATALOG_H
#define _CATALOG_H

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <rapidjson/document.h>

class IStorage;

namespace catalog
{

enum class AssetType
{
    Decoder,
    Rule,
    Output,
    Filter,
    Schema,
    Environment
};

enum class StorageType
{
    Local,
    Network,
    Invalid,
};

/**
 * @brief The Catalog class
 *
 * The Catalog class is used to manage the catalog and will be in charge of
 * managing the load, update and storage of all the assets needed by the engine.
 * It should support multiple storage systems and should make versioning easy to
 * manage.
 *
 * @note The Catalog class is thread-safe. Not implemented yet (#TODO this)
 *
 * @warning Each asset type should have a schema associated to it.
 *  - Decoder schema: "wazuh-decoders" (i.e. in diskDriver
 * /schemas/wazuh-decoders.json)
 *  - Rule schema: "wazuh-rules" (i.e. in diskDriver /schemas/wazuh-rules.json)
 *  - Output schema: "wazuh-outputs" (i.e. in diskDriver
 * /schemas/wazuh-outputs.json)
 *  - Filter schema: "wazuh-filters" (i.e. in diskDriver
 * /schemas/wazuh-filters.json)
 *  - Environment schema: "wazuh-environments" (i.e. in diskDriver
 * /schemas/wazuh-environments.json)
 */
class Catalog
{

private:
    //This can be a local or network path
    const std::string mBasePath;
    StorageType mStorageType;

public:
    /**
     * @brief Create the catalog manager from the given driver to connect.
     *
     * The catalog take the ownership of the driver.
     * The driver will be deleted when the catalog is destroyed.
     *
     * @param spStorageDriver The storage driver to connect to.
     * The driver is destroyed when the catalog is freed.
     */
    Catalog(StorageType type, std::string const& basePath);

    /**
     * @brief Get the Asset object
     *
     * @param type The type of the asset. Only decoder, rules, filter and
     *             schema are supported.
     * @param assetName The name of the asset.
     * @return rapidjson::Document The asset object. If the asset is not found,
     *                             the document is empty.
     * @throws std::runtime_error If the asset is corrupted or cannot get
     *                            the json schema to validate against.
     * @throws std::runtime_error If the asset is not valid.
     * @throws YML::ParserException If the yaml in the storage is corrupted.
     * @throws filesystem::filesystem_error if the storage driver fails to get
     *                                      the asset. Only if driver is
     * diskDriver.
     *
     */
    rapidjson::Document getAsset(const AssetType type,
                                 std::string const& assetName) const;

    /**
     * @brief Get the Asset object
     *
     * @param type The type of the asset.
     * @param assetName The name of the asset.
     * @return rapidjson::Document The asset object. If the asset is not found,
     *                             the document is empty.
     * @throws std::runtime_error If the asset is corrupted or cannot get
     *                            the json schema to validate against.
     * @throws std::runtime_error If the asset is not valid.
     * @throws YML::ParserException If the yaml in the storage is corrupted.
     * @throws filesystem::filesystem_error if the storage driver fails to get
     *                                      the asset. Only if driver is
     * diskDriver.
     *
     */
    rapidjson::Document getAsset(const std::string &type,
                                 std::string const& assetName) const;

    std::string getFileContents(AssetType type, std::string const& file) const;
};

} // namespace catalog

#endif // _CATALOG_H
