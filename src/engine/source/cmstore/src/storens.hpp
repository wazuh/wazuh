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
constexpr std::string_view CACHE_NS_FILE = "cache_ns.json";
// KVDB
constexpr std::string_view KVDBS_DIR = "kvdbs";


constexpr std::string_view POLICIES_DIR = "policies";
constexpr std::string_view INTEGRATIONS_DIR = "integrations";

constexpr std::string_view ASSETS_DIR = "assets";
} // namespace pathns

/**
 * @brief Concrete implementation of ICMstoreNS interface, representing a namespace in the CMStore
 * @warning Only one instance of CMStoreNS should exist per NamespaceId to avoid race conditions on files and cache
 */
class CMStoreNS : public ICMstoreNS
{
private:
    NamespaceId m_namespaceId;           ///< Namespace ID associated to this CMStoreNS
    std::filesystem::path m_storagePath; ///< Path to the storage directory for this namespace
    std::filesystem::path m_cachePath;   ///< Path to the cache file for this namespace
    CacheNS m_cache;                  ///< Cache for UUID to name-type mappings
    mutable std::shared_mutex m_mutex;        ///< Mutex for file and cache access

    /**
     * @brief Flush the current cache to disk
     * @throws std::runtime_error if flushing fails (This never should happen)
     */
    void flushCacheToDisk();

    // TODO: Load and rebuild cache from disk on construction
public:
    /**
     * @brief Construct a new CMStoreNS
     * @param nsId Namespace ID associated to this CMStoreNS
     * @param storagePath Path to the storage directory for this namespace
     */
    CMStoreNS(NamespaceId nsId, std::filesystem::path storagePath)
        : m_namespaceId(std::move(nsId))
        , m_storagePath(std::move(storagePath))
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

        // TODO: Load cache from disk
    }

    ~CMStoreNS() override = default; // TODO Dump cache to disk on destruction

    /** @copydoc ICMStoreNSReader::getNamespaceId */
    const NamespaceId& getNamespaceId() const override;

    std::vector<std::tuple<std::string, std::string>> getCollection(ResourceType type) const override;
    std::tuple<std::string, ResourceType> resolveNameFromUUID(const std::string& uuid) const override;
    std::string resolveUUIDFromName(const std::string& name, ResourceType type) const override;

    dataType::Policy getPolicy() const override;
    void upsertPolicy(const dataType::Policy& policy) override;
    void deletePolicy() override;

    dataType::Integration getIntegrationByName(const std::string& name) const override;
    dataType::Integration getIntegrationByUUID(const std::string& uuid) const override;
    bool integrationExistsByName(const std::string& name) const override;
    bool integrationExistsByUUID(const std::string& uuid) const override;
    std::string createIntegration(const dataType::Integration& integration) override;
    void updateIntegration(const dataType::Integration& integration) override;
    void deleteIntegrationByName(const std::string& name) override;
    void deleteIntegrationByUUID(const std::string& uuid) override;

    json::Json getKVDBByName(const std::string& name) const override;
    json::Json getKVDBByUUID(const std::string& uuid) const override;
    bool kvdbExistsByName(const std::string& name) const override;
    bool kvdbExistsByUUID(const std::string& uuid) const override;
    std::string createKVDB(const std::string& name, json::Json&& data) override;
    void updateKVDB(const dataType::KVDB& kvdb) override;
    void deleteKVDBByName(const std::string& name) override;
    void deleteKVDBByUUID(const std::string& uuid) override;

    json::Json getAssetByName(const base::Name& name) const override;
    json::Json getAssetByUUID(const std::string& uuid) const override;
    bool assetExistsByName(const base::Name& name) const override;
    bool assetExistsByUUID(const std::string& uuid) const override;
    std::string createAsset(const json::Json& asset) override;
    void updateAsset(const json::Json& asset) override;
    void deleteAssetByName(const base::Name& name) override;
    void deleteAssetByUUID(const std::string& uuid) override;
};
} // namespace cm::store

#endif // _CMSTORE_STORENS
