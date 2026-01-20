#ifndef _CMSTORE_STORENS_HPP
#define _CMSTORE_STORENS_HPP

#include <filesystem>
#include <string>
#include <tuple>
#include <vector>

#include <cmstore/icmstore.hpp>

#include "cachens.hpp"

namespace cm::store
{

namespace pathns
{
constexpr std::string_view JSON_ID_PATH = "/id";      ///< Universal path for UUID field in JSON/YML objects
constexpr std::string_view YML_PAIR_FMT = "id: {}\n"; ///< YML pair format for UUID field
// Files and extensions
constexpr std::string_view CACHE_NS_FILE = "cache_ns.json";
constexpr std::string_view ASSET_EXTENSION = ".yml";
constexpr std::string_view POLICY_FILE = "policy.json";
// Directories
constexpr std::string_view KVDBS_DIR = "kvdbs";
constexpr std::string_view DECODERS_DIR = "decoders";
constexpr std::string_view OUTPUTS_DIR = "outputs";
constexpr std::string_view FILTERS_DIR = "filters";
constexpr std::string_view INTEGRATIONS_DIR = "integrations";

} // namespace pathns

/**
 * @brief Concrete implementation of ICMstoreNS interface, representing a namespace in the CMStore
 * @warning Only one instance of CMStoreNS should exist per NamespaceId to avoid race conditions on files and cache
 */
class CMStoreNS : public ICMstoreNS
{
private:
    NamespaceId m_namespaceId;                  ///< Namespace ID associated to this CMStoreNS
    std::filesystem::path m_storagePath;        ///< Path to the storage directory for this namespace
    std::filesystem::path m_defaultOutputsPath; ///< Path to the default outputs directory for all namespaces
    std::filesystem::path m_cachePath;          ///< Path to the cache file for this namespace
    CacheNS m_cache;                            ///< Cache for UUID to name-type mappings
    mutable std::shared_mutex m_mutex;          ///< Mutex for file and cache access

    /**
     * @brief Flush the current cache to disk
     * @throws std::runtime_error if flushing fails (This never should happen)
     */
    void flushCacheToDisk();

    /**
     * @brief Load the cache from disk into memory
     *
     * If fail to load, the cache will by rebuilt from the storage directory
     * If fail to rebuild, an exception will be thrown
     * @throw std::runtime_error if loading or rebuilding the cache fails
     */
    void loadCacheFromDisk();

    /**
     * @brief Rebuild the cache by scanning the storage directory
     * @throw std::runtime_error if rebuilding the cache fails
     */
    void rebuildCacheFromStorage();

    /**
     * @brief Upsert the UUID field in the given YML/Json content and compute content hash
     *
     * If the UUID field already exists, it will be checked for validity and returned.
     * If it does not exist, a new UUID will be generated, inserted into the content, and returned.
     * Additionally, computes a hash of the normalized JSON content (compact format),
     * ignoring formatting differences and comments.
     * @param ymlContent YML content as a string (will be modified if UUID is added)
     * @return std::pair<std::string, std::string> UUID and computed hash of the content
     * @throw std::runtime_error if the existing UUID is invalid or content parsing fails
     */
    std::pair<std::string, std::string> upsertUUIDAndComputeHash(std::string& ymlContent);

    /**
     * @brief Get the path for a resource based on its name and type
     * @param name Name of the resource
     * @param type Type of the resource
     * @return std::filesystem::path Path to the resource
     * @throw std::runtime_error if the resource type or name is invalid
     */
    std::filesystem::path getResourcePaths(const std::string& name, ResourceType type) const;

    /**
     * @brief Resolve the name and type of a resource from its UUID without locking
     * @param uuid UUID of the resource
     * @return std::tuple<std::string, ResourceType> Name and type of the resource
     * @throw std::runtime_error if the UUID does not exist
     */
    std::tuple<std::string, ResourceType> resolveNameFromUUIDUnlocked(const std::string& uuid) const;

    /**
     * @brief Resolve the UUID of a resource from its name and type without locking
     * @param name Name of the resource
     * @param type Type of the resource
     * @return std::string UUID of the resource
     * @throw std::runtime_error if the name/type does not exist
     */
    std::string resolveUUIDFromNameUnlocked(const std::string& name, ResourceType type) const;

public:
    /**
     * @brief Construct a new CMStoreNS
     * @param nsId Namespace ID associated to this CMStoreNS
     * @param storagePath Path to the storage directory for this namespace
     */
    CMStoreNS(NamespaceId nsId, std::filesystem::path storagePath, std::filesystem::path defaultOutputsPath)
        : m_namespaceId(std::move(nsId))
        , m_storagePath(std::move(storagePath))
        , m_defaultOutputsPath(std::move(defaultOutputsPath))
        , m_cachePath(m_storagePath / pathns::CACHE_NS_FILE)
        , m_cache()
        , m_mutex()
    {
        // Check if storage path exists, if path exist and is a directory
        if (!std::filesystem::exists(m_storagePath))
        {
            throw std::runtime_error("Storage path does not exist: " + m_storagePath.string());
        }
        if (!std::filesystem::is_directory(m_storagePath))
        {
            throw std::runtime_error("Storage path is not a directory: " + m_storagePath.string());
        }

        // Load or rebuild cache
        try
        {
            loadCacheFromDisk();
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Failed to initialize CMStoreNS for namespace '{}': {}", m_namespaceId.toStr(), e.what()));
        }
    }

    ~CMStoreNS() override = default; // TODO Dump cache to disk on destruction

    /***********************************  General Methods ************************************/

    /** @copydoc ICMStoreNSReader::getNamespaceId */
    const NamespaceId& getNamespaceId() const override;

    /** @copydoc ICMStoreNSReader::getCollection */
    std::vector<std::tuple<std::string, std::string>> getCollection(ResourceType type) const override;
    /** @copydoc ICMStoreNSReader::resolveNameFromUUID */
    std::tuple<std::string, ResourceType> resolveNameFromUUID(const std::string& uuid) const override;
    /** @copydoc ICMStoreNSReader::resolveHashFromUUID */
    std::string resolveHashFromUUID(const std::string& uuid) const override;
    /** @copydoc ICMStoreNSReader::resolveUUIDFromName */
    std::string resolveUUIDFromName(const std::string& name, ResourceType type) const override;

    /** @copydoc ICMStoreNSReader::assetExistsByName */
    bool assetExistsByName(const base::Name& name) const override;
    /** @copydoc ICMStoreNSReader::assetExistsByUUID */
    bool assetExistsByUUID(const std::string& uuid) const override;
    /** @copydoc ICMStoreNSReader::getDefaultOutputs */
    const std::vector<json::Json> getDefaultOutputs() const override;

    /*********************************** General Resource ************************************/

    /** @copydoc ICMStoreNS::createResource */
    std::string createResource(const std::string& name, ResourceType type, const std::string& ymlContent) override;
    /** @copydoc ICMStoreNS::updateResourceByName */
    void updateResourceByName(const std::string& name, ResourceType type, const std::string& ymlContent) override;
    /** @copydoc ICMStoreNS::updateResourceByUUID */
    void updateResourceByUUID(const std::string& uuid, const std::string& ymlContent) override;
    /** @copydoc ICMStoreNS::deleteResourceByName */
    void deleteResourceByName(const std::string& name, ResourceType type) override;
    /** @copydoc ICMStoreNS::deleteResourceByUUID */
    void deleteResourceByUUID(const std::string& uuid) override;

    /**************************************** Policy ****************************************/

    /** @copydoc ICMStoreNSReader::getPolicy */
    dataType::Policy getPolicy() const override;
    /** @copydoc ICMStoreNS::upsertPolicy */
    void upsertPolicy(const dataType::Policy& policy) override;
    /** @copydoc ICMStoreNS::deletePolicy */
    void deletePolicy() override;

    /************************************* INTEGRATIONS *************************************/

    /** @copydoc ICMStoreNSReader::getIntegrationByName */
    dataType::Integration getIntegrationByName(const std::string& name) const override;
    /** @copydoc ICMStoreNSReader::getIntegrationByUUID */
    dataType::Integration getIntegrationByUUID(const std::string& uuid) const override;

    /**************************************** KVDB ******************************************/

    /** @copydoc ICMStoreNSReader::getKVDBByName */
    dataType::KVDB getKVDBByName(const std::string& name) const override;
    /** @copydoc ICMStoreNSReader::getKVDBByUUID */
    dataType::KVDB getKVDBByUUID(const std::string& uuid) const override;

    /**************************************** ASSETS ****************************************/

    /** @copydoc ICMStoreNSReader::getAssetByName */
    json::Json getAssetByName(const base::Name& name) const override;
    /** @copydoc ICMStoreNSReader::getAssetByUUID */
    json::Json getAssetByUUID(const std::string& uuid) const override;
};
} // namespace cm::store

#endif // _CMSTORE_STORENS
