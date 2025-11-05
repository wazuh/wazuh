#ifndef _CMSTORE_STORENS_HPP
#define _CMSTORE_STORENS_HPP

#include <filesystem>
#include <string>
#include <tuple>
#include <vector>

#include <cmstore/icmstore.hpp>

namespace cm::store
{
class CMStoreNS : public ICMstoreNS
{
private:
    std::filesystem::path m_storagePath; ///< Path to the storage directory for this namespace
    NamespaceId m_namespaceId;           ///< Namespace ID associated to this CMStoreNS
public:
    /**
     * @brief Construct a new CMStoreNS
     * @param nsId Namespace ID associated to this CMStoreNS
     * @param storagePath Path to the storage directory for this namespace
     */
    CMStoreNS(NamespaceId nsId, std::filesystem::path storagePath)
        : m_namespaceId(std::move(nsId))
        , m_storagePath(std::move(storagePath))
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
    }

    ~CMStoreNS() override = default;

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
    bool kvdbExistsByName(const base::Name& name) const override;
    bool kvdbExistsByUUID(const std::string& uuid) const override;
    std::string createKVDB(const dataType::KVDB&) override;
    void updateKVDB(const dataType::KVDB&) override;
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
