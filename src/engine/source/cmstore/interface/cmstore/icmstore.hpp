#ifndef _CMSTORE_ICMSTORE
#define _CMSTORE_ICMSTORE

#include <string>
#include <vector>

#include <base/json.hpp>
#include <base/name.hpp>

#include <cmstore/types.hpp>

namespace cm::store
{


class ICMstoreReader
{
public:

    virtual ~ICMstoreReader() = default;

    // Policy
    virtual dataType::Policy getPolicy(const NamespaceId& nsId) const = 0;

    // Integration access methods
    virtual dataType::Integration getIntegrationByName(const std::string& name, const NamespaceId& nsId) const = 0;
    virtual dataType::Integration getIntegrationByUUID(const std::string& uuid, const NamespaceId& nsId) const = 0;

    // KVDB Dump access method
    virtual json::Json getKVDBByName(const std::string& name, const NamespaceId& nsId) const = 0;
    virtual json::Json getKVDBByUUID(const std::string& uuid, const NamespaceId& nsId) const = 0;
    // virtual bool kvdbExistsByName(const base::Name& name, const NamespaceId& nsId) const = 0;
    // virtual bool kvdbExistsByUUID(const std::string& uuid, const NamespaceId& nsId) const = 0;

    // Asset access methods
    virtual json::Json getAssetByName(const base::Name& name, const NamespaceId& nsId) const = 0;
    virtual json::Json getAssetByUUID(const std::string& uuid, const NamespaceId& nsId) const = 0;

    // virtual bool assetExistsByName(const base::Name& name, const NamespaceId& nsId) const = 0;
    // virtual bool assetExistsByUUID(const std::string& uuid, const NamespaceId& nsId) const = 0;

    // Collection access methods
    virtual std::vector<std::tuple<std::string, std::string>> getCollection(ResourceType type, const NamespaceId& nsId) const = 0;

    virtual std::tuple<std::string, ResourceType> resolveNameFromUUID(const std::string& uuid, const NamespaceId& nsId) const = 0;
    virtual std::string resolveUUIDFromName(const std::string& name, ResourceType type, const NamespaceId& nsId) const = 0;

    virtual bool isCustomResource(const std::string& uuid, const NamespaceId& nsId) const = 0;
    virtual bool isCustomResource(const std::string& name, ResourceType type, const NamespaceId& nsId) const = 0;

    // Get lock for read transaction
    // virtual TransaccionLock getSharedLock() const = 0;
    // virtual TransaccionLock tryGetSharedLock() const = 0;


};

class ICMstore : public ICMstoreReader
{
public:
    virtual ~ICMstore() = default;

    // Policy CRUD operations
    virtual void upsertPolicy(const dataType::Policy& policy, const NamespaceId& nsId) = 0;
    virtual void deletePolicy(const NamespaceId& nsId) = 0;

    // Integration CRUD operations
    virtual std::string createIntegration(const dataType::Integration& integration, const NamespaceId& nsId) = 0;
    virtual void updateIntegration(const dataType::Integration& integration, const NamespaceId& nsId) = 0;
    virtual void deleteIntegrationByName(const std::string& name, const NamespaceId& nsId) = 0;
    virtual void deleteIntegrationByUUID(const std::string& uuid, const NamespaceId& nsId) = 0;

    // KVDB Dump CRUD operations
    virtual std::string createKVDB(const dataType::KVDB&, const NamespaceId& nsId) = 0;
    virtual void updateKVDB(const dataType::KVDB&, const NamespaceId& nsId) = 0;
    virtual void deleteKVDBByName(const std::string& name, const NamespaceId& nsId) = 0;
    virtual void deleteKVDBByUUID(const std::string& uuid, const NamespaceId& nsId) = 0;

    // Asset CRUD operations
    virtual std::string createAsset(const json::Json& asset, const NamespaceId& nsId) = 0;
    virtual void updateAsset(const json::Json& asset, const NamespaceId& nsId) = 0;
    virtual void deleteAssetByName(const base::Name& name, const NamespaceId& nsId) = 0;
    virtual void deleteAssetByUUID(const std::string& uuid, const NamespaceId& nsId) = 0;

    // NS operations
    virtual void createNamespace(const NamespaceId& nsId) = 0;
    virtual void cloneNamespace(const NamespaceId& sourceNsId, const NamespaceId& targetNsId) = 0;
    virtual void deleteNamespace(const NamespaceId& nsId) = 0;
    virtual std::vector<NamespaceId> getNamespaces() const = 0;



};

} // namespace cm::store

#endif // _CMSTORE_ICMSTORE
