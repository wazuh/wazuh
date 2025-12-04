#ifndef _CMSTORE_STORECTI_HPP
#define _CMSTORE_STORECTI_HPP

#include <filesystem>
#include <string>
#include <tuple>
#include <vector>

#include <ctistore/adapter.hpp>
#include <ctistore/icmreader.hpp>

#include <cmstore/icmstore.hpp>

namespace cm::store
{

/**
 * @brief Implementation of ICMstoreNS interface for CTI resources, representing a namespace in the CMStore
 */
class CMStoreCTI : public ICMstoreNS
{
private:
    NamespaceId m_namespaceId;                     ///< Namespace ID associated to this CMStoreCTI
    std::filesystem::path m_defaultOutputsPath;    ///< Path to the default outputs directory for all namespaces
    std::weak_ptr<cti::store::ICMReader> m_reader; ///< CTI Store Reader

public:
    /**
     * @brief Construct a new CMStoreCTI
     * @param nsId Namespace ID associated to this CMStoreCTI
     */
    CMStoreCTI(std::shared_ptr<cti::store::ICMReader> reader,
               NamespaceId nsId,
               std::filesystem::path defaultOutputsPath)
        : m_namespaceId(std::move(nsId))
        , m_defaultOutputsPath(std::move(defaultOutputsPath))
        , m_reader(reader) {};

    ~CMStoreCTI() override = default; // TODO Dump cache to disk on destruction

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
