#ifndef _CMSTORE_ICMSTORE
#define _CMSTORE_ICMSTORE

#include <string>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>

#include <cmstore/types.hpp>

namespace cm::store
{

/**
 * @brief Interface for CMStore Namespace Reader
 *
 * This interface provides read-only access to the resources within a specific namespace
 */
class ICMStoreNSReader
{
public:
    virtual ~ICMStoreNSReader() = default;

    /**
     * @brief Get the policy of the namespace
     * @return dataType::Policy The policy of the namespace
     * @throw std::runtime_error if the policy does not exist or failed to be retrieved
     */
    virtual dataType::Policy getPolicy() const = 0;

    /**
     * @brief Get the Namespace ID of this CMStoreNSReader
     * @return const NamespaceId& The namespace ID
     */
    virtual const NamespaceId& getNamespaceId() const = 0;

    /****************************** Integration access methods ******************************/

    /**
     * @brief Get Integration by its name
     *
     * @param name Name of the integration
     * @return dataType::Integration The integration object
     * @throw std::runtime_error if the integration does not exist or failed to be retrieved
     */
    virtual dataType::Integration getIntegrationByName(const std::string& name) const = 0;

    /**
     * @brief Get Integration by its UUID
     * @param uuid UUID of the integration
     * @return dataType::Integration The integration object
     * @throw std::runtime_error if the integration does not exist or failed to be retrieved
     */
    virtual dataType::Integration getIntegrationByUUID(const std::string& uuid) const = 0;

    /**
     * @brief Check if an integration exists by its name
     * @param name Name of the integration to check
     * @return bool 'true' if the integration exists, false otherwise
     */
    virtual bool integrationExistsByName(const std::string& name) const = 0;

    /**
     * @brief Check if an integration exists by its UUID
     * @param uuid UUID of the integration to check
     * @return bool 'true' if the integration exists, false otherwise
     */
    virtual bool integrationExistsByUUID(const std::string& uuid) const = 0;

    /******************************    KVDB access methods   ******************************/

    /**
     * @brief Get KVDB by its name
     * @param name Name of the KVDB
     * @return json::Json The KVDB dump in JSON format
     * @throw std::runtime_error if the KVDB does not exist or failed to be retrieved
     */
    virtual json::Json getKVDBByName(const std::string& name) const = 0;

    /**
     * @brief Get KVDB by its UUID
     * @param uuid UUID of the KVDB
     * @return json::Json The KVDB dump in JSON format
     * @throw std::runtime_error if the KVDB does not exist or failed to be retrieved
     */
    virtual json::Json getKVDBByUUID(const std::string& uuid) const = 0;

    /**
     * @brief Check if a KVDB exists by its name
     * @param name Name of the KVDB to check
     * @return bool 'true' if the KVDB exists, false otherwise
     */
    virtual bool kvdbExistsByName(const std::string& name) const = 0;

    /**
     * @brief Check if a KVDB exists by its UUID
     * @param uuid UUID of the KVDB to check
     * @return bool 'true' if the KVDB exists, false otherwise
     */
    virtual bool kvdbExistsByUUID(const std::string& uuid) const = 0;

    /******************************    Asset access methods   ******************************/

    /**
     * @brief Get Asset by its name (decoder, rule, filter, output.)
     * @param name Name of the asset
     * @return json::Json The asset in JSON format
     * @throw std::runtime_error if the asset does not exist or failed to be retrieved
     */
    virtual json::Json getAssetByName(const base::Name& name) const = 0;

    /**
     * @brief Get Asset by its UUID (decoder, rule, filter, output.)
     * @param uuid UUID of the asset
     * @return json::Json The asset in JSON format
     * @throw std::runtime_error if the asset does not exist or failed to be retrieved
     */
    virtual json::Json getAssetByUUID(const std::string& uuid) const = 0;

    /**
     * @brief Check if an asset exists by its name
     * @param name Name of the asset to check
     * @return bool 'true' if the asset exists, false otherwise
     */
    virtual bool assetExistsByName(const base::Name& name) const = 0;

    /**
     * @brief Check if an asset exists by its UUID
     * @param uuid UUID of the asset to check
     * @return bool 'true' if the asset exists, false otherwise
     */
    virtual bool assetExistsByUUID(const std::string& uuid) const = 0;

    /**
     * @brief Get all resources of a specific type in the namespace
     * @param type ResourceType to filter
     * @return std::vector<std::tuple<std::string, std::string>> Vector of tuples with (UUID, Name)
     */
    virtual std::vector<std::tuple<std::string, std::string>> getCollection(ResourceType type) const = 0;

    // Name/UUID resolution

    /**
     * @brief Resolve resource name and type from its UUID
     * @param uuid UUID of the resource
     * @return std::tuple<std::string, ResourceType> Tuple with (Name, ResourceType)
     * @throw std::runtime_error if the UUID does not exist
     */
    virtual std::tuple<std::string, ResourceType> resolveNameFromUUID(const std::string& uuid) const = 0;

    /**
     * @brief Resolve resource UUID from its name and type
     * @param name Name of the resource
     * @param type ResourceType of the resource
     * @return std::string UUID of the resource
     * @throw std::runtime_error if the name/type does not exist
     */
    virtual std::string resolveUUIDFromName(const std::string& name, ResourceType type) const = 0;

    // Get lock for read transaction
    // virtual TransaccionLock getSharedLock() const = 0;
    // virtual TransaccionLock tryGetSharedLock() const = 0;
};

/**
 * @brief Interface for CMStore Namespace
 *
 * This interface provides read and write access to the resources within a specific namespace
 */
class ICMstoreNS : public ICMStoreNSReader
{
public:
    virtual ~ICMstoreNS() = default;

    /****************************** Policy CRUD operations ******************************/

    /**
     * @brief Upsert the policy of the namespace
     * @param policy The policy to upsert
     */
    virtual void upsertPolicy(const dataType::Policy& policy) = 0;

    /**
     * @brief Delete the policy of the namespace, the namespace will have no policy after this operation
     */
    virtual void deletePolicy() = 0;

    // Integration CRUD operations

    /**
     * @brief Add a new integration to the namespace
     * @param integration The integration to add
     * @return std::string UUID of the created integration
     * @throw std::runtime_error if an integration with the same name already exists
     */
    virtual std::string createIntegration(const dataType::Integration& integration) = 0;

    /**
     * @brief Update an existing integration in the namespace
     * @param integration The integration to update
     * @throw std::runtime_error if the integration does not exist, or if updating the integration would cause a name
     * conflict
     */
    virtual void updateIntegration(const dataType::Integration& integration) = 0;

    /**
     * @brief Delete an integration by its name
     * @param name Name of the integration to delete
     * @throw std::runtime_error if the integration does not exist
     */
    virtual void deleteIntegrationByName(const std::string& name) = 0;

    /**
     * @brief Delete an integration by its UUID
     * @param uuid UUID of the integration to delete
     * @throw std::runtime_error if the integration does not exist
     */
    virtual void deleteIntegrationByUUID(const std::string& uuid) = 0;

    // KVDB CRUD operations

    /**
     * @brief Add a new KVDB to the namespace
     * @param name Name of the KVDB to add
     * @param data Data of the KVDB to add
     * @return std::string UUID of the created KVDB
     * @throw std::runtime_error if a KVDB with the same name already exists
     */
    virtual std::string createKVDB(const std::string& name, json::Json&& data) = 0;

    /**
     * @brief Update an existing KVDB in the namespace
     * @param kvdb The KVDB to update
     * @throw std::runtime_error if the KVDB does not exist, or if updating the KVDB would cause a name conflict
     */
    virtual void updateKVDB(const dataType::KVDB& kvdb) = 0;

    /**
     * @brief Delete a KVDB by its name
     * @param name Name of the KVDB to delete
     * @throw std::runtime_error if the KVDB does not exist
     */
    virtual void deleteKVDBByName(const std::string& name) = 0;

    /**
     * @brief Delete a KVDB by its UUID
     * @param uuid UUID of the KVDB to delete
     * @throw std::runtime_error if the KVDB does not exist
     */
    virtual void deleteKVDBByUUID(const std::string& uuid) = 0;

    // Asset CRUD operations

    /**
     * @brief Add a new asset to the namespace (decoder, rule, filter, output.)
     * @param asset The asset to add
     * @return std::string UUID of the created asset
     * @throw std::runtime_error if an asset with the same name already exists
     */
    virtual std::string createAsset(const json::Json& asset) = 0;

    /**
     * @brief Update an existing asset in the namespace (decoder, rule, filter, output.)
     * @param asset The asset to update
     * @throw std::runtime_error if the asset does not exist, or if updating the asset would cause a name conflict
     */
    virtual void updateAsset(const json::Json& asset) = 0;

    /**
     * @brief Delete an asset by its name (decoder, rule, filter, output.)
     * @param name Name of the asset to delete
     * @throw std::runtime_error if the asset does not exist
     */
    virtual void deleteAssetByName(const base::Name& name) = 0;

    /**
     * @brief Delete an asset by its UUID (decoder, rule, filter, output.)
     * @param uuid UUID of the asset to delete
     * @throw std::runtime_error if the asset does not exist
     */
    virtual void deleteAssetByUUID(const std::string& uuid) = 0;
};

/**
 * @brief Interface for CMStore
 *
 * This interface provides access to namespaces and their resources
 */
class ICMstore
{
public:
    virtual ~ICMstore() = default;

    // Get namespace reader

    /**
     * @brief Get a read-only interface to a namespace
     * @param nsId NamespaceId of the namespace
     * @return std::shared_ptr<ICMStoreNSReader> Shared pointer to the namespace reader
     */
    virtual std::shared_ptr<ICMStoreNSReader> getNSReader(const NamespaceId& nsId) const = 0;

    /**
     * @brief Get a read-write interface to a namespace
     * @param nsId NamespaceId of the namespace
     * @return std::shared_ptr<ICMstoreNS> Shared pointer to the namespace
     */
    virtual std::shared_ptr<ICMstoreNS> getNS(const NamespaceId& nsId) = 0;

    // NS operations

    /**
     * @brief Create a new namespace
     * @param nsId NamespaceId of the namespace to create
     * @throw std::runtime_error if the namespace already exists
     */
    virtual void createNamespace(const NamespaceId& nsId) = 0;

    /**
     * @brief Clone an existing namespace into a new namespace
     * @param sourceNsId NamespaceId of the source namespace
     * @param targetNsId NamespaceId of the target namespace
     * @throw std::runtime_error if the source namespace does not exist or the target namespace already exists
     */
    virtual void cloneNamespace(const NamespaceId& sourceNsId, const NamespaceId& targetNsId) = 0;

    /**
     * @brief Delete an existing namespace
     * @param nsId NamespaceId of the namespace to delete
     * @throw std::runtime_error if the namespace does not exist
     */
    virtual void deleteNamespace(const NamespaceId& nsId) = 0;

    /**
     * @brief Get all existing namespaces
     * @return std::vector<NamespaceId> Vector of NamespaceId
     */
    virtual std::vector<NamespaceId> getNamespaces() const = 0;
};

} // namespace cm::store

#endif // _CMSTORE_ICMSTORE
