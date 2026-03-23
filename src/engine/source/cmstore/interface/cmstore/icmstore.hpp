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

    /***********************************  General Methods ************************************/

    /**
     * @brief Get the Namespace ID of this CMStoreNSReader
     * @return const NamespaceId& The namespace ID
     */
    virtual const NamespaceId& getNamespaceId() const = 0;

    /**
     * @brief Get all resources of a specific type in the namespace
     * @param type ResourceType to filter
     * @return std::vector<std::tuple<std::string, std::string>> Vector of tuples with (UUID, Name)
     */
    virtual std::vector<std::tuple<std::string, std::string>> getCollection(ResourceType type) const = 0;

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

    /**************************************** Policy ****************************************/

    /**
     * @brief Get the policy of the namespace
     * @return dataType::Policy The policy of the namespace
     * @throw std::runtime_error if the policy does not exist or failed to be retrieved
     */
    virtual dataType::Policy getPolicy() const = 0;

    /************************************* INTEGRATIONS *************************************/

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

    /**************************************** KVDB ******************************************/

    /**
     * @brief Get KVDB by its name
     * @param name Name of the KVDB
     * @return json::Json The KVDB dump in JSON format
     * @throw std::runtime_error if the KVDB does not exist or failed to be retrieved
     */
    virtual dataType::KVDB getKVDBByName(const std::string& name) const = 0;

    /**
     * @brief Get KVDB by its UUID
     * @param uuid UUID of the KVDB
     * @return json::Json The KVDB dump in JSON format
     * @throw std::runtime_error if the KVDB does not exist or failed to be retrieved
     */
    virtual dataType::KVDB getKVDBByUUID(const std::string& uuid) const = 0;

    /**************************************** ASSETS ****************************************/

    /**
     * @brief Get Asset by its name (decoder, filter, output.)
     * @param name Name of the asset
     * @return json::Json The asset in JSON format
     * @throw std::runtime_error if the asset does not exist or failed to be retrieved
     */
    virtual json::Json getAssetByName(const base::Name& name) const = 0;

    /**
     * @brief Get Asset by its UUID (decoder, filter, output.)
     * @param uuid UUID of the asset
     * @return json::Json The asset in JSON format
     * @throw std::runtime_error if the asset does not exist or failed to be retrieved
     */
    virtual json::Json getAssetByUUID(const std::string& uuid) const = 0;

    /**
     * @brief Get the Default Outputs Integration object
     *
     * @return dataType::Integration
     */
    virtual const std::vector<json::Json> getDefaultOutputs() const = 0;

    /*********************************** Resources ***************************************/

    /**
     * @brief Get resource by its name
     *
     * @tparam T Type of the resource to get (dataType::Integration, dataType::KVDB, json::Json)
     * @param name Name of the resource
     * @return auto The resource object
     * @throw std::runtime_error if the resource does not exist or failed to be retrieved
     */
    template<typename T>
    auto getResourceByName(const std::string& name) const
    {
        if constexpr (std::is_same_v<T, dataType::Integration>)
        {
            return getIntegrationByName(name);
        }
        else if constexpr (std::is_same_v<T, dataType::KVDB>)
        {
            return getKVDBByName(name);
        }
        else if constexpr (std::is_same_v<T, json::Json>)
        {
            return getAssetByName(base::Name(name));
        }
        else
        {
            static_assert(std::is_same_v<T, void>, "Unsupported type for getResourceByName");
        }
    }

    /**
     * @brief Get resource by its UUID
     *
     * @tparam T Type of the resource to get (dataType::Integration, dataType::KVDB, json::Json)
     * @param uuid UUID of the resource
     * @return auto The resource object
     * @throw std::runtime_error if the resource does not exist or failed to be retrieved
     */
    template<typename T>
    auto getResourceByUUID(const std::string& uuid) const
    {
        if constexpr (std::is_same_v<T, dataType::Integration>)
        {
            return getIntegrationByUUID(uuid);
        }
        else if constexpr (std::is_same_v<T, dataType::KVDB>)
        {
            return getKVDBByUUID(uuid);
        }
        else if constexpr (std::is_same_v<T, json::Json>)
        {
            return getAssetByUUID(uuid);
        }
        else
        {
            static_assert(std::is_same_v<T, void>, "Unsupported type for getResourceByUUID");
        }
    }

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

    /*********************************** General Resource ************************************/

    /**
     * @brief Create a resource in the namespace
     *
     * @param name Name of the resource to create
     * @param type Type of the resource to create
     * @param ymlContent YAML content of the resource
     * @return std::string UUID of the created resource
     * @throw std::runtime_error if a resource with the same name and type already exists or any error occurs
     * @warning This method not validate the content of the YML has the correct schema for the resource type
     */
    virtual std::string createResource(const std::string& name, ResourceType type, const std::string& ymlContent) = 0;

    /**
     * @brief Update a resource in the namespace by its name and type
     *
     * @param name Name of the resource to update
     * @param type Type of the resource to update
     * @param ymlContent New YAML content of the resource
     * @throw std::runtime_error if the resource does not exist or any error occurs
     * @warning This method not validate the content of the YML has the correct schema for the resource type
     */
    virtual void updateResourceByName(const std::string& name, ResourceType type, const std::string& ymlContent) = 0;

    /**
     * @brief Update a resource in the namespace by its UUID
     *
     * @param uuid UUID of the resource to update
     * @param ymlContent New YAML content of the resource
     * @throw std::runtime_error if the resource does not exist or any error occurs
     * @warning This method not validate the content of the YML has the correct schema for the resource type
     */
    virtual void updateResourceByUUID(const std::string& uuid, const std::string& ymlContent) = 0;

    /**
     * @brief Delete a resource in the namespace by its name and type
     *
     * @param name Name of the resource to delete
     * @param type Type of the resource to delete
     * @throw std::runtime_error if the resource does not exist or any error occurs
     */
    virtual void deleteResourceByName(const std::string& name, ResourceType type) = 0;

    /**
     * @brief Delete a resource in the namespace by its UUID
     *
     * @param uuid UUID of the resource to delete
     * @throw std::runtime_error if the resource does not exist or any error occurs
     */
    virtual void deleteResourceByUUID(const std::string& uuid) = 0;

    /**************************************** Policy ****************************************/

    /**
     * @brief Upsert the policy of the namespace
     * @param policy The policy to upsert
     */
    virtual void upsertPolicy(const dataType::Policy& policy) = 0;

    /**
     * @brief Delete the policy of the namespace, the namespace will have no policy after this operation
     */
    virtual void deletePolicy() = 0;
};

/**
 * @brief Interface for CMStore
 *
 * This interface provides access to namespaces and their resources
 */
class ICMStore
{
public:
    virtual ~ICMStore() = default;

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
     * @return std::shared_ptr<ICMstoreNS> Shared pointer to the created namespace
     * @throw std::runtime_error if the namespace already exists
     */
    virtual std::shared_ptr<ICMstoreNS> createNamespace(const NamespaceId& nsId) = 0;

    /**
     * @brief Delete an existing namespace
     * @param nsId NamespaceId of the namespace to delete
     * @throw std::runtime_error if the namespace does not exist
     */
    virtual void deleteNamespace(const NamespaceId& nsId) = 0;

    /**
     * @brief Rename an existing namespace
     * @param from NamespaceId of the namespace to rename
     * @param to NamespaceId of the new namespace
     * @throw std::runtime_error if the namespace does not exist or any error occurs
     */
    virtual void renameNamespace(const NamespaceId& from, const NamespaceId& to) = 0;

    /**
     * @brief Check if a namespace exists
     * @param nsId NamespaceId of the namespace to check
     * @return true if the namespace exists, false otherwise
     */
    virtual bool existsNamespace(const NamespaceId& nsId) const = 0;

    /**
     * @brief Get all existing namespaces
     * @return std::vector<NamespaceId> Vector of NamespaceId
     */
    virtual std::vector<NamespaceId> getNamespaces() const = 0;
};

} // namespace cm::store

#endif // _CMSTORE_ICMSTORE
