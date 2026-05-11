#include <fmt/format.h>

#include <base/logging.hpp>
#include <cmstore/detail.hpp>
#include <cmstore/types.hpp>

#include <cmcrud/cmcrudservice.hpp>

namespace
{
constexpr std::string_view PATH_KEY_ID = "/id";

std::string assetUuidFromJson(const json::Json& jsonDoc, const base::Name& assetName)
{
    std::string uuid;
    if (jsonDoc.getString(uuid, PATH_KEY_ID) != json::RetGet::Success || uuid.empty())
    {
        throw std::runtime_error(
            fmt::format("Asset '{}' is missing required UUID at JSON path '{}'", assetName.toStr(), PATH_KEY_ID));
    }

    if (!base::utils::generators::isValidUUIDv4(uuid))
    {
        throw std::runtime_error(fmt::format(
            "Asset '{}' has an invalid UUIDv4 '{}' at JSON path '{}'", assetName.toStr(), uuid, PATH_KEY_ID));
    }

    return uuid;
}

void throwIfError(base::OptError err, std::string_view context)
{
    if (err.has_value())
    {
        const auto& e = base::getError(err);
        throw std::runtime_error(fmt::format("{}: {}", context, e.message));
    }
}

cm::store::dataType::Policy policyFromDocument(const json::Json& policyDocument)
{
    return cm::store::dataType::Policy::fromJson(policyDocument);
}

cm::store::dataType::Integration integrationFromDocument(const json::Json& integrationDocument, bool requireUUID)
{
    return cm::store::dataType::Integration::fromJson(integrationDocument, requireUUID);
}

cm::store::dataType::KVDB kvdbFromDocument(const json::Json& kvdbDocument, bool requireUUID)
{
    return cm::store::dataType::KVDB::fromJson(kvdbDocument, requireUUID);
}

base::Name assetNameFromJson(const json::Json& jsonDoc)
{
    std::string name;
    if (jsonDoc.getString(name, "/name") != json::RetGet::Success || name.empty())
    {
        throw std::runtime_error("Missing or empty asset name at JSON path '/name'");
    }
    return base::Name {name};
}
} // namespace

namespace cm::crud
{

CrudService::CrudService(const std::shared_ptr<cm::store::ICMStore>& store,
                         const std::shared_ptr<builder::IValidator>& validator)
    : m_store(store)
    , m_validator(validator)
{
    if (!store)
    {
        throw std::invalid_argument("CrudService: store pointer cannot be null");
    }
    if (!validator)
    {
        throw std::invalid_argument("CrudService: validator pointer cannot be null");
    }
}

std::shared_ptr<cm::store::ICMStore> CrudService::getStore() const
{
    auto store = m_store.lock();
    if (!store)
    {
        throw std::runtime_error("CMStore is no longer available");
    }
    return store;
}

std::shared_ptr<builder::IValidator> CrudService::getValidator() const
{
    auto validator = m_validator.lock();
    if (!validator)
    {
        throw std::runtime_error("Validator is no longer available");
    }
    return validator;
}

std::vector<cm::store::NamespaceId> CrudService::listNamespaces() const
{
    return getStore()->getNamespaces();
}

bool CrudService::existsNamespace(const cm::store::NamespaceId& nsId) const
{
    return getStore()->existsNamespace(nsId);
}

void CrudService::createNamespace(const cm::store::NamespaceId& nsId)
{
    try
    {
        getStore()->createNamespace(nsId);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to create namespace '{}': {}", nsId.toStr(), e.what()));
    }
}

void CrudService::deleteNamespace(const cm::store::NamespaceId& nsId)
{
    try
    {
        getStore()->deleteNamespace(nsId);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to delete namespace '{}': {}", nsId.toStr(), e.what()));
    }
}

cm::store::dataType::Policy CrudService::importNamespace(const cm::store::NamespaceId& nsId,
                                  std::string_view jsonDocument,
                                  std::string_view originSpace,
                                  bool force)
{
    auto store = getStore();

    auto bestEffortDelete = [store, functionName = logging::getLambdaName(__FUNCTION__, "bestEffortDelete")](
                                const cm::store::NamespaceId& id)
    {
        try
        {
            store->deleteNamespace(id);
        }
        catch (const std::exception& ex)
        {
            LOG_WARNING_L(functionName.c_str(), "Rollback delete failed for '{}': {}", id.toStr(), ex.what());
        }
    };

    bool destinationCreated = false;

    try
    {
        // Reject if destination namespace already exists
        if (store->existsNamespace(nsId))
        {
            throw std::runtime_error(fmt::format(
                "Namespace '{}' already exists. Import is only allowed into a new namespace.", nsId.toStr()));
        }

        // Parse and validate input JSON structure
        json::Json nsJson = [&jsonDocument]() -> json::Json
        {
            // Parse input JSON
            json::Json parsed;
            try
            {
                parsed = json::Json {jsonDocument};
            }
            catch (const std::exception& e)
            {
                throw std::runtime_error(fmt::format("Invalid JSON document for namespace import: {}", e.what()));
            }

            // Validate required structure: must have "policy" and "resources" keys
            if (!parsed.exists("/policy"))
            {
                throw std::runtime_error("Invalid namespace import JSON: missing required '/policy' key");
            }

            if (!parsed.exists("/resources"))
            {
                throw std::runtime_error("Invalid namespace import JSON: missing required '/resources' key");
            }

            // Validate that both are objects
            auto policyOpt = parsed.getObject("/policy");
            if (!policyOpt.has_value())
            {
                throw std::runtime_error("Invalid namespace import JSON: '/policy' must be an object");
            }

            auto resourcesOpt = parsed.getObject("/resources");
            if (!resourcesOpt.has_value())
            {
                throw std::runtime_error("Invalid namespace import JSON: '/resources' must be an object");
            }

            // Validate that only "policy" and "resources" keys exist (no additional keys)
            auto rootObj = parsed.getObject();
            if (rootObj.has_value())
            {
                const auto& root = rootObj.value();
                if (root.size() != 2)
                {
                    throw std::runtime_error("Invalid namespace import JSON: root object must contain exactly 2 keys: "
                                             "'policy' and 'resources'");
                }
            }

            return parsed;
        }();

        // Create empty destination namespace
        store->createNamespace(nsId);
        destinationCreated = true;

        // Import into the new namespace
        {
            auto ns = store->getNS(nsId);
            auto nsReader = store->getNSReader(nsId);

            auto importResources = [&](cm::store::ResourceType type, std::string_view key)
            {
                const auto path = fmt::format("/resources/{}", key);
                auto resourcesArrayOpt = nsJson.getArray(path);
                if (!resourcesArrayOpt)
                {
                    return;
                }

                const auto& resourcesArray = resourcesArrayOpt.value();
                for (const auto& item : resourcesArray)
                {
                    switch (type)
                    {
                        case cm::store::ResourceType::INTEGRATION:
                        {
                            auto integ = cm::store::dataType::Integration::fromJson(item, /*requireUUID:*/ true);
                            if (!force)
                            {
                                validateIntegration(nsReader, integ);
                            }

                            const std::string& name = integ.getName();
                            ns->createResource(name, type, integ.toJson());
                            break;
                        }

                        case cm::store::ResourceType::KVDB:
                        {
                            auto kvdb = cm::store::dataType::KVDB::fromJson(item, /*requireUUID:*/ true);

                            const std::string& name = kvdb.getName();
                            ns->createResource(name, type, kvdb.toJson());
                            break;
                        }

                        case cm::store::ResourceType::FILTER:
                        case cm::store::ResourceType::OUTPUT:
                        case cm::store::ResourceType::DECODER:
                        {
                            auto assetJson = [&item, type]() -> json::Json
                            {
                                switch (type)
                                {
                                    case cm::store::ResourceType::DECODER: return cm::store::detail::adaptDecoder(item);
                                    case cm::store::ResourceType::FILTER: return cm::store::detail::adaptFilter(item);
                                    case cm::store::ResourceType::OUTPUT: return cm::store::detail::adaptOutput(item);
                                }
                                __builtin_unreachable();
                            }();

                            auto name = assetNameFromJson(assetJson);

                            (void)assetUuidFromJson(assetJson, name);

                            const auto resourceStr = cm::store::resourceTypeToString(type);

                            if (resourceStr != name.parts().front())
                            {
                                throw std::runtime_error(fmt::format(
                                    "Asset name '{}' does not match resource type '{}'", name.toStr(), resourceStr));
                            }

                            if (!force)
                            {
                                validateAsset(nsReader, assetJson);
                            }

                            const std::string nameStr = name.toStr();
                            ns->createResource(nameStr, type, assetJson);
                            break;
                        }

                        default: throw std::runtime_error("Unsupported resource type in importNamespace");
                    }
                }
            };

            // Required order
            importResources(cm::store::ResourceType::KVDB, "kvdbs");
            importResources(cm::store::ResourceType::DECODER, "decoders");
            importResources(cm::store::ResourceType::FILTER, "filters");
            importResources(cm::store::ResourceType::OUTPUT, "outputs");
            importResources(cm::store::ResourceType::INTEGRATION, "integrations");

            // Policy
            if (auto policyObjOpt = nsJson.getJson("/policy"))
            {
                auto policy = cm::store::dataType::Policy::fromJson(*policyObjOpt);
                if (!force)
                {
                    validatePolicy(nsReader, policy);
                }
                // Only set origin space if provided
                if (!originSpace.empty())
                {
                    policy.setOriginSpace(originSpace);
                }
                ns->upsertPolicy(policy);
            }
        }
    }
    catch (const std::exception& e)
    {
        if (destinationCreated)
        {
            bestEffortDelete(nsId);
        }
        throw std::runtime_error(fmt::format("Failed to import namespace '{}': {}", nsId.toStr(), e.what()));
    }

    return store->getNS(nsId)->getPolicy();
}

void CrudService::importNamespace(const cm::store::NamespaceId& nsId,
                                  const std::vector<json::Json>& kvdbs,
                                  const std::vector<json::Json>& decoders,
                                  const std::vector<json::Json>& filters,
                                  const std::vector<json::Json>& integrations,
                                  const json::Json& policy,
                                  bool softValidation)
{
    const auto store = getStore();
    const auto validator = getValidator();
    // Reject if destination namespace already exists
    if (store->existsNamespace(nsId))
    {
        throw std::runtime_error(
            fmt::format("Namespace '{}' already exists. Import is only allowed into a new namespace.", nsId.toStr()));
    }

    // Create empty destination namespace
    auto ns = store->createNamespace(nsId);
    auto nsReader = std::static_pointer_cast<cm::store::ICMStoreNSReader>(ns);

    for (const auto& jkvdb : kvdbs)
    {
        auto kvdb = cm::store::dataType::KVDB::fromJson(jkvdb, true);
        ns->createResource(kvdb.getName(), cm::store::ResourceType::KVDB, kvdb.toJson());
    }

    for (const auto& jdec : decoders)
    {
        auto assetJson = store::detail::adaptDecoder(jdec);
        auto name = assetNameFromJson(assetJson);
        const auto resourceStr = cm::store::resourceTypeToString(cm::store::ResourceType::DECODER);

        if (resourceStr != name.parts().front())
        {
            throw std::runtime_error(
                fmt::format("Asset name '{}' does not match resource type '{}'", name.toStr(), resourceStr));
        }

        if (!softValidation)
        {
            validator->validateAsset(nsReader, assetJson);
        }
        ns->createResource(name.toStr(), cm::store::ResourceType::DECODER, assetJson);
    }

    for (const auto& jfilt : filters)
    {
        auto assetJson = store::detail::adaptFilter(jfilt);
        auto name = assetNameFromJson(assetJson);
        const auto resourceStr = cm::store::resourceTypeToString(cm::store::ResourceType::FILTER);

        if (resourceStr != name.parts().front())
        {
            throw std::runtime_error(
                fmt::format("Asset name '{}' does not match resource type '{}'", name.toStr(), resourceStr));
        }

        if (!softValidation)
        {
            validator->validateAsset(nsReader, assetJson);
        }
        ns->createResource(name.toStr(), cm::store::ResourceType::FILTER, assetJson);
    }

    for (const auto& jinteg : integrations)
    {
        auto integ = cm::store::dataType::Integration::fromJson(jinteg, true);
        if (!softValidation)
        {
            validator->softIntegrationValidate(nsReader, integ);
        }
        ns->createResource(integ.getName(), cm::store::ResourceType::INTEGRATION, integ.toJson());
    }

    auto pol = cm::store::dataType::Policy::fromJson(policy);

    if (!softValidation)
    {
        validatePolicy(nsReader, pol);
    }

    ns->upsertPolicy(pol);
}

void CrudService::upsertPolicy(const cm::store::NamespaceId& nsId, const json::Json& policyJson)
{
    try
    {
        auto ns = getNamespaceStore(nsId);

        auto policy = policyFromDocument(policyJson);

        std::shared_ptr<cm::store::ICMStoreNSReader> nsReader = ns;
        validatePolicy(nsReader, policy);

        ns->upsertPolicy(policy);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to upsert policy in namespace '{}': {}", nsId.toStr(), e.what()));
    }
}

void CrudService::deletePolicy(const cm::store::NamespaceId& nsId)
{
    try
    {
        auto ns = getNamespaceStore(nsId);
        ns->deletePolicy();
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to delete policy in namespace '{}': {}", nsId.toStr(), e.what()));
    }
}

std::vector<ResourceSummary> CrudService::listResources(const cm::store::NamespaceId& nsId,
                                                        cm::store::ResourceType type) const
{
    try
    {
        auto nsReader = getNamespaceStoreView(nsId);

        std::vector<ResourceSummary> result;
        const auto collection = nsReader->getCollection(type);

        result.reserve(collection.size());

        for (const auto& [uuid, name] : collection)
        {
            ResourceSummary summary;
            summary.uuid = uuid;
            summary.name = name;
            result.emplace_back(std::move(summary));
        }
        return result;
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to list resources of type '{}' in namespace '{}': {}",
                                             cm::store::resourceTypeToString(type),
                                             nsId.toStr(),
                                             e.what()));
    }
}

json::Json CrudService::getResourceByUUID(const cm::store::NamespaceId& nsId, const std::string& uuid) const
{
    try
    {
        auto nsView = getNamespaceStoreView(nsId);

        // Resolve name and type from UUID
        const auto [name, type] = nsView->resolveNameFromUUID(uuid);

        json::Json result;
        switch (type)
        {
            case cm::store::ResourceType::INTEGRATION:
            {
                auto integ = nsView->getIntegrationByUUID(uuid);
                result = integ.toJson();
                break;
            }

            case cm::store::ResourceType::KVDB:
            {
                auto kvdb = nsView->getKVDBByUUID(uuid);
                result = kvdb.toJson();
                break;
            }

            case cm::store::ResourceType::DECODER:
            case cm::store::ResourceType::OUTPUT:
            case cm::store::ResourceType::FILTER:
            {
                result = nsView->getAssetByUUID(uuid);
                break;
            }

            default: throw std::runtime_error("Unsupported resource type for getResourceByUUID");
        }
        return result;
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("Failed to get resource with UUID '{}' in namespace '{}': {}", uuid, nsId.toStr(), e.what()));
    }
}

void CrudService::upsertResource(const cm::store::NamespaceId& nsId,
                                 cm::store::ResourceType type,
                                 const json::Json& resource)
{
    try
    {
        auto ns = getNamespaceStore(nsId);
        auto nsReader = std::static_pointer_cast<cm::store::ICMStoreNSReader>(ns);

        switch (type)
        {
            case cm::store::ResourceType::INTEGRATION:
            {
                auto integ = integrationFromDocument(resource, /*requireUUID:*/ false);
                validateIntegration(nsReader, integ);

                const std::string& uuid = integ.getUUID();
                const std::string& name = integ.getName();

                if (!uuid.empty() && nsReader->assetExistsByUUID(uuid))
                {
                    ns->updateResourceByUUID(uuid, integ.toJson());
                }
                else
                {
                    ns->createResource(name, type, integ.toJson());
                }
                break;
            }

            case cm::store::ResourceType::KVDB:
            {
                auto kvdb = kvdbFromDocument(resource, /*requireUUID:*/ false);
                const auto kvdbJson = kvdb.toJson();

                const std::string& uuid = kvdb.getUUID();
                const std::string& name = kvdb.getName();

                if (!uuid.empty() && nsReader->assetExistsByUUID(uuid))
                {
                    ns->updateResourceByUUID(uuid, kvdbJson);
                }
                else
                {
                    ns->createResource(name, type, kvdbJson);
                }
                break;
            }

            case cm::store::ResourceType::DECODER:
            case cm::store::ResourceType::OUTPUT:
            case cm::store::ResourceType::FILTER:
            {
                auto adaptedPayload = [&resource, type]() -> json::Json
                {
                    switch (type)
                    {
                        case cm::store::ResourceType::DECODER: return cm::store::detail::adaptDecoder(resource);
                        case cm::store::ResourceType::FILTER: return cm::store::detail::adaptFilter(resource);
                        case cm::store::ResourceType::OUTPUT: return cm::store::detail::adaptOutput(resource);
                    }
                    __builtin_unreachable();
                }();

                auto name = assetNameFromJson(adaptedPayload);
                const auto resource = resourceTypeToString(type);

                if (resource != name.parts().front())
                {
                    throw std::runtime_error(fmt::format(
                        "Asset name '{}' does not match resource type '{}'", name, resourceTypeToString(type)));
                }

                validateAsset(nsReader, adaptedPayload);

                const std::string nameStr = name.toStr();

                if (nsReader->assetExistsByName(name))
                {
                    ns->updateResourceByName(nameStr, type, adaptedPayload);
                }
                else
                {
                    ns->createResource(nameStr, type, adaptedPayload);
                }
                break;
            }

            default: throw std::runtime_error("Unsupported resource type in upsertResource");
        }
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to upsert resource of type '{}' in namespace '{}': {}",
                                             cm::store::resourceTypeToString(type),
                                             nsId.toStr(),
                                             e.what()));
    }
}

void CrudService::deleteResourceByUUID(const cm::store::NamespaceId& nsId, const std::string& uuid)
{
    try
    {
        auto ns = getNamespaceStore(nsId);

        ns->deleteResourceByUUID(uuid);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format(
            "Failed to delete resource with UUID '{}' in namespace '{}': {}", uuid, nsId.toStr(), e.what()));
    }
}

void CrudService::validateResource(cm::store::ResourceType type, const json::Json& payload)
{
    try
    {
        switch (type)
        {
            case cm::store::ResourceType::DECODER:
            case cm::store::ResourceType::FILTER:
            {
                json::Json adaptedPayload;
                if (type == cm::store::ResourceType::DECODER)
                {
                    adaptedPayload = cm::store::detail::adaptDecoder(payload);
                }
                else
                {
                    adaptedPayload = cm::store::detail::adaptFilter(payload);
                }

                auto name = assetNameFromJson(adaptedPayload);

                (void)assetUuidFromJson(adaptedPayload, name);

                const auto resourceStr = cm::store::resourceTypeToString(type);

                if (resourceStr != name.parts().front())
                {
                    throw std::runtime_error(
                        fmt::format("Asset name '{}' does not match resource type '{}'", name.toStr(), resourceStr));
                }

                throwIfError(getValidator()->validateAssetShallow(adaptedPayload),
                             fmt::format("Validation failed for '{}'", cm::store::resourceTypeToString(type)));
                return;
            }

            case cm::store::ResourceType::INTEGRATION:
            {
                (void)cm::store::dataType::Integration::fromJson(payload, /*requireUUID:*/ true);
                return;
            }

            case cm::store::ResourceType::KVDB:
            {
                (void)cm::store::dataType::KVDB::fromJson(payload, /*requireUUID:*/ true);
                return;
            }

            default:
                throw std::runtime_error(
                    fmt::format("Unsupported resource type '{}'", cm::store::resourceTypeToString(type)));
        }
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format(
            "Failed to validate resource of type '{}': {}", cm::store::resourceTypeToString(type), e.what()));
    }
}

void CrudService::validatePolicy(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                 const cm::store::dataType::Policy& policy) const
{
    throwIfError(getValidator()->softPolicyValidate(nsReader, policy),
                 fmt::format("Policy validation failed in namespace '{}'", nsReader->getNamespaceId().toStr()));
}

void CrudService::validateIntegration(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                      const cm::store::dataType::Integration& integration) const
{
    throwIfError(getValidator()->softIntegrationValidate(nsReader, integration),
                 fmt::format("Integration validation failed for '{}' in namespace '{}'",
                             integration.getName(),
                             nsReader->getNamespaceId().toStr()));
}

void CrudService::validateAsset(const std::shared_ptr<cm::store::ICMStoreNSReader>& nsReader,
                                const json::Json& asset) const
{
    throwIfError(getValidator()->validateAsset(nsReader, asset),
                 fmt::format("Asset validation failed in namespace '{}'", nsReader->getNamespaceId().toStr()));
}

std::shared_ptr<cm::store::ICMStoreNSReader>
CrudService::getNamespaceStoreView(const cm::store::NamespaceId& nsId) const
{
    auto ns = getStore()->getNSReader(nsId);
    if (!ns)
    {
        throw std::runtime_error(fmt::format("Namespace '{}' does not exist", nsId.toStr()));
    }
    return ns;
}

std::shared_ptr<cm::store::ICMstoreNS> CrudService::getNamespaceStore(const cm::store::NamespaceId& nsId) const
{
    auto ns = getStore()->getNS(nsId);
    if (!ns)
    {
        throw std::runtime_error(fmt::format("Namespace '{}' does not exist", nsId.toStr()));
    }
    return ns;
}

} // namespace cm::crud
