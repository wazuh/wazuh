
#ifndef _CTI_STORE_ICMREADER
#define _CTI_STORE_ICMREADER

#include <cstdint>
#include <string>
#include <vector>

#include <base/name.hpp>
#include <base/json.hpp>

namespace cti::store
{

// Aviable asset types in the CTI Store
enum class AssetType : std::uint8_t
{
    DECODER,
    INTEGRATION,
    ERROR_TYPE
};

/**
 * @brief Interface for reading from a CTI (local) store.
 *
 * This interface provides methods to read locally stored CTI assets, kvdb and policies.
 * It does not provide methods to write or modify the store.
 * Should be a thread safe and not block the caller.
 * Cannot be used meanwhile a sync remote operation is being performed.
 * TODO: Should be posible locked externally to avoid being used while a sync operation is being performed. (?) or
 * may manage snapshots internally (?)
 */
class ICMReader
{
public:
    virtual ~ICMReader() = default;

    /**
     * @brief Get the list of available assets of a given type
     *
     * @param type Type of asset to list
     * @return std::vector<base::Name> List of asset names available
     * @throw std::runtime_error on error (if the type is not valid, unable to read the store, etc)
     */
    virtual std::vector<base::Name> getAssetList(cti::store::AssetType type) const = 0;

    /**
     * @brief Get the asset content, should be a valid JSON Asset
     *
     * @param name Name of the asset to get (Title only)
     * @return json::Json Content of the asset
     * @throw std::runtime_error on error (if the asset does not exist, unable to read the store, etc)
     */
    virtual json::Json getAsset(const base::Name& name) const = 0;

    /**
     * @brief Check if an asset exists in the store
     *
     * @param name Name of the asset to check (Title only)
     * @return true if the asset exists
     * @return false if the asset does not exist
     * @throw std::runtime_error on error (if unable to read the store, etc)
     */
    virtual bool assetExists(const base::Name& name) const = 0;


    /**
     * @brief Resolve an asset name from its UUID
     *
     * @param uuid UUID of the asset to resolve
     * @return std::string Name of the asset
     * @throw std::runtime_error on error (if the asset does not exist, unable to read the store, etc)
     */
    virtual std::string resolveNameFromUUID(const std::string& uuid) const = 0;

    // TODO: Analize if we need to add metadata functions
    // virtual XXX getMetadata() const = 0;
    // virtual XXX getAssetMetadata(const base::Name& name) const = 0;

    /**
     * @brief List all the available KVDBs in the store
     * @return std::vector<std::string> List of KVDB names
     * @throw std::runtime_error on error (if unable to read the store, etc)
     */
    virtual std::vector<std::string> listKVDB() const = 0;

    /**
     * @brief List all KVDB owned by an integration
     * @param integrationName Name of the integration
     * @return std::vector<std::string> List of KVDB names owned by the integration, can be empty if no KVDBs are owned
     * @throw std::runtime_error on error (if unable to read the store, etc
     * or the integration does not exist)
     */
    virtual std::vector<std::string> listKVDB(const base::Name& integrationName) const = 0;

    /**
     * @brief Check if a KVDB exists in the store
     * @param kdbName Name of the KVDB to check
     * @return true if the KVDB exists
     * @return false if the KVDB does not exist
     * @throw std::runtime_error on error (if unable to read the store, etc)
     */
    virtual bool kvdbExists(const std::string& kdbName) const = 0;

    /**
     * @brief Dump the content of a KVDB as a JSON object
     * @param kdbName Name of the KVDB to dump
     * @return json::Json JSON object with the content of the KVDB
     * @throw std::runtime_error on error (if unable to read the store, etc or the KVDB does not exist)
     * TODO: Maybe we should add parameters to limit the number of entries returned, pagination, filters, etc
     */
    virtual json::Json kvdbDump(const std::string& kdbName) const = 0;

    // Policy management
    /**
     * @brief Get the list of all integrations in the policy
     * @return std::vector<base::Name> List of integration names in the policy
     * @throw std::runtime_error on error (if unable to read the store, etc)
     */
    virtual std::vector<base::Name> getPolicyIntegrationList() const = 0;

    /**
     * @brief Get a policy document by its ID or title
     * @param name Policy identifier (can be an ID or a title)
     * @return json::Json Policy JSON document
     * @throw std::runtime_error if not found or on error
     */
    virtual json::Json getPolicy(const base::Name& name) const = 0;

    /**
     * @brief List all available policy names (titles)
     * @return std::vector<base::Name> Vector of policy Names (titles)
     * @throw std::runtime_error on error (if unable to read the store, etc)
     */
    virtual std::vector<base::Name> getPolicyList() const = 0;

    /**
     * @brief Check if a policy exists by ID or title
     * @param name Policy identifier (can be an ID or a title)
     * @return true if the policy exists, false otherwise
     * @throw std::runtime_error on error (if unable to read the store, etc)
     */
    virtual bool policyExists(const base::Name& name) const = 0;
};

} // namespace cti::store

#endif // _CTI_STORE_ICMREADER
