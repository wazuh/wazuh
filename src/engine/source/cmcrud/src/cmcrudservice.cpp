#include <fmt/format.h>

#include <base/logging.hpp>
#include <cmstore/types.hpp>
#include <yml/yml.hpp>

#include <cmcrud/cmcrudservice.hpp>

namespace
{

json::Json yamlToJson(std::string_view document)
{
    rapidjson::Document doc = yml::Converter::loadYMLfromString(std::string {document});
    return json::Json {std::move(doc)};
}

std::string jsonToYaml(const json::Json& jsonDoc)
{
    rapidjson::Document doc;
    doc.Parse(jsonDoc.str().c_str());

    auto ymlNode = yml::Converter::jsonToYaml(doc);
    YAML::Emitter ymlEmitter;
    ymlEmitter << ymlNode;
    return ymlEmitter.c_str();
}

cm::store::dataType::Policy policyFromDocument(std::string_view policyDocument)
{
    return cm::store::dataType::Policy::fromJson(yamlToJson(policyDocument));
}

cm::store::dataType::Integration integrationFromDocument(std::string_view integrationDocument)
{
    return cm::store::dataType::Integration::fromJson(yamlToJson(integrationDocument));
}

cm::store::dataType::KVDB kvdbFromDocument(std::string_view kvdbDocument)
{
    return cm::store::dataType::KVDB::fromJson(yamlToJson(kvdbDocument));
}

base::Name assetNameFromJson(const json::Json& jsonDoc)
{
    auto optName = jsonDoc.getString("/name");
    if (!optName.has_value() || optName->empty())
    {
        throw std::runtime_error("Missing or empty asset name at JSON path '/name'");
    }
    return base::Name {optName.value()};
}
} // namespace

namespace cm::crud
{

CrudService::CrudService(std::shared_ptr<cm::store::ICMStore> store, std::shared_ptr<IContentValidator> validator)
    : m_store(std::move(store))
    , m_validator(std::move(validator))
{
    if (!m_store)
    {
        throw std::invalid_argument("CrudService: store pointer cannot be null");
    }
    if (!m_validator)
    {
        throw std::invalid_argument("CrudService: validator pointer cannot be null");
    }
}

std::vector<cm::store::NamespaceId> CrudService::listNamespaces() const
{
    return m_store->getNamespaces();
}

void CrudService::createNamespace(std::string_view nsName)
{
    try
    {
        // If the namespace name is invalid, this will throw an exception in the NamespaceId constructor
        cm::store::NamespaceId nsId {nsName};
        m_store->createNamespace(nsId);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to create namespace '{}': {}", nsName, e.what()));
    }
}

void CrudService::deleteNamespace(std::string_view nsName)
{
    try
    {
        // If the namespace name is invalid, this will throw an exception in the NamespaceId constructor
        cm::store::NamespaceId nsId {nsName};
        m_store->deleteNamespace(nsId);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to delete namespace '{}': {}", nsName, e.what()));
    }
}

void CrudService::importNamespace(std::string_view nsName, std::string_view jsonDocument, bool force)
{
    const cm::store::NamespaceId nsId {nsName};

    auto existsNS = [this](const cm::store::NamespaceId& id) -> bool
    {
        try
        {
            (void)m_store->getNSReader(id);
            return true;
        }
        catch (const std::exception& ex)
        {
            return false;
        }
    };

    auto bestEffortDelete = [this, functionName = logging::getLambdaName(__FUNCTION__, "bestEffortDelete")](
                                const cm::store::NamespaceId& id)
    {
        try
        {
            m_store->deleteNamespace(id);
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
        if (existsNS(nsId))
        {
            throw std::runtime_error(fmt::format(
                "Namespace '{}' already exists. Import is only allowed into a new namespace.", nsName));
        }

        // Parse input JSON
        json::Json nsJson;
        try
        {
            std::string jsonStr {jsonDocument};
            nsJson = json::Json {jsonStr.c_str()};
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format("Invalid JSON document for namespace import: {}", e.what()));
        }

        // Create empty destination namespace
        m_store->createNamespace(nsId);
        destinationCreated = true;

        // Import into the new namespace
        {
            auto ns = m_store->getNS(nsId);
            auto nsReader = m_store->getNSReader(nsId);

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
                    json::Json itemJson {item};

                    switch (type)
                    {
                        case cm::store::ResourceType::INTEGRATION:
                        {
                            auto integ = cm::store::dataType::Integration::fromJson(itemJson);
                            if (!force) { m_validator->validateIntegration(nsReader, integ); }

                            const std::string& name = integ.getName();
                            const std::string yml = jsonToYaml(integ.toJson());
                            ns->createResource(name, type, yml);
                            break;
                        }

                        case cm::store::ResourceType::KVDB:
                        {
                            auto kvdb = cm::store::dataType::KVDB::fromJson(itemJson);
                            if (!force) { m_validator->validateKVDB(nsReader, kvdb); }

                            const std::string& name = kvdb.getName();
                            const std::string yml = jsonToYaml(kvdb.toJson());
                            ns->createResource(name, type, yml);
                            break;
                        }

                        case cm::store::ResourceType::DECODER:
                        case cm::store::ResourceType::OUTPUT:
                        case cm::store::ResourceType::RULE:
                        case cm::store::ResourceType::FILTER:
                        {
                            auto assetJson = itemJson;
                            auto name = assetNameFromJson(assetJson);
                            const auto resourceStr = cm::store::resourceTypeToString(type);

                            if (resourceStr != name.parts().front())
                            {
                                throw std::runtime_error(fmt::format(
                                    "Asset name '{}' does not match resource type '{}'", name.toStr(), resourceStr));
                            }

                            if (!force) { m_validator->validateAsset(nsReader, assetJson); }

                            const std::string yml = jsonToYaml(assetJson);
                            const std::string nameStr = name.toStr();
                            ns->createResource(nameStr, type, yml);
                            break;
                        }

                        default:
                            throw std::runtime_error("Unsupported resource type in importNamespace");
                    }
                }
            };

            // Required order
            importResources(cm::store::ResourceType::KVDB, "kvdb");
            importResources(cm::store::ResourceType::FILTER, "filter");
            importResources(cm::store::ResourceType::DECODER, "decoder");
            importResources(cm::store::ResourceType::RULE, "rule");
            importResources(cm::store::ResourceType::OUTPUT, "output");
            importResources(cm::store::ResourceType::INTEGRATION, "integration");

            // Policy
            if (auto policyObjOpt = nsJson.getJson("/policy"))
            {
                auto policy = cm::store::dataType::Policy::fromJson(*policyObjOpt);
                if (!force) { m_validator->validatePolicy(nsReader, policy); }
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
        throw std::runtime_error(fmt::format("Failed to import namespace '{}': {}", nsName, e.what()));
    }
}

void CrudService::upsertPolicy(std::string_view nsName, std::string_view policyDocument)
{
    try
    {
        const auto nsId = cm::store::NamespaceId {nsName};
        auto ns = getNamespaceStore(nsId);

        auto policy = policyFromDocument(policyDocument);

        std::shared_ptr<cm::store::ICMStoreNSReader> nsReader = ns;
        m_validator->validatePolicy(nsReader, policy);

        ns->upsertPolicy(policy);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to upsert policy in namespace '{}': {}", nsName, e.what()));
    }
}

void CrudService::deletePolicy(std::string_view nsName)
{
    try
    {
        const auto nsId = cm::store::NamespaceId {nsName};
        auto ns = getNamespaceStore(nsId);
        ns->deletePolicy();
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to delete policy in namespace '{}': {}", nsName, e.what()));
    }
}

std::vector<ResourceSummary> CrudService::listResources(std::string_view nsName, cm::store::ResourceType type) const
{
    try
    {
        const auto nsId = cm::store::NamespaceId {nsName};
        auto nsReader = getNamespaceStoreView(nsId);

        std::vector<ResourceSummary> result;
        const auto collection = nsReader->getCollection(type);

        result.reserve(collection.size());

        for (const auto& [uuid, name] : collection)
        {
            ResourceSummary summary;
            summary.uuid = uuid;
            summary.name = name;
            summary.hash = nsReader->resolveHashFromUUID(uuid);

            result.emplace_back(std::move(summary));
        }
        return result;
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to list resources of type '{}' in namespace '{}': {}",
                                             cm::store::resourceTypeToString(type),
                                             nsName,
                                             e.what()));
    }
}

std::string CrudService::getResourceByUUID(std::string_view nsName, const std::string& uuid, bool asJson) const
{
    try
    {
        auto nsId = cm::store::NamespaceId {nsName};
        auto nsView = getNamespaceStoreView(nsId);

        // Resolve name and type from UUID
        const auto [name, type] = nsView->resolveNameFromUUID(uuid);

        switch (type)
        {
            case cm::store::ResourceType::INTEGRATION:
            {
                auto integ = nsView->getIntegrationByUUID(uuid);
                if (asJson)
                {
                    return integ.toJson().str();
                }
                return jsonToYaml(integ.toJson());
            }

            case cm::store::ResourceType::KVDB:
            {
                auto kvdb = nsView->getKVDBByUUID(uuid);
                if (asJson)
                {
                    return kvdb.toJson().str();
                }
                return jsonToYaml(kvdb.toJson());
            }

            case cm::store::ResourceType::DECODER:
            case cm::store::ResourceType::OUTPUT:
            case cm::store::ResourceType::RULE:
            case cm::store::ResourceType::FILTER:
            {
                auto assetJson = nsView->getAssetByUUID(uuid);
                if (asJson)
                {
                    return assetJson.str();
                }
                return jsonToYaml(assetJson);
            }

            default: throw std::runtime_error("Unsupported resource type for getResourceByUUID");
        }
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("Failed to get resource with UUID '{}' in namespace '{}': {}", uuid, nsName, e.what()));
    }
}

void CrudService::upsertResource(std::string_view nsName, cm::store::ResourceType type, std::string_view document)
{
    try
    {
        const auto nsId = cm::store::NamespaceId {nsName};
        auto ns = getNamespaceStore(nsId);
        auto nsReader = std::static_pointer_cast<cm::store::ICMStoreNSReader>(ns);

        const std::string yml {document};

        switch (type)
        {
            case cm::store::ResourceType::INTEGRATION:
            {
                auto integ = integrationFromDocument(document);
                m_validator->validateIntegration(nsReader, integ);

                const std::string& uuid = integ.getUUID();
                const std::string& name = integ.getName();

                if (!uuid.empty() && nsReader->assetExistsByUUID(uuid))
                {
                    ns->updateResourceByUUID(uuid, yml);
                }
                else
                {
                    ns->createResource(name, type, yml);
                }
                break;
            }

            case cm::store::ResourceType::KVDB:
            {
                auto kvdb = kvdbFromDocument(document);
                m_validator->validateKVDB(nsReader, kvdb);

                const std::string& uuid = kvdb.getUUID();
                const std::string& name = kvdb.getName();

                if (!uuid.empty() && nsReader->assetExistsByUUID(uuid))
                {
                    ns->updateResourceByUUID(uuid, yml);
                }
                else
                {
                    ns->createResource(name, type, yml);
                }
                break;
            }

            case cm::store::ResourceType::DECODER:
            case cm::store::ResourceType::OUTPUT:
            case cm::store::ResourceType::RULE:
            case cm::store::ResourceType::FILTER:
            {
                json::Json assetJson = yamlToJson(document);
                auto name = assetNameFromJson(assetJson);
                const auto resource = resourceTypeToString(type);

                if (resource != name.parts().front())
                {
                    throw std::runtime_error(fmt::format(
                        "Asset name '{}' does not match resource type '{}'", name, resourceTypeToString(type)));
                }

                m_validator->validateAsset(nsReader, assetJson);

                const std::string nameStr = name.toStr();

                if (nsReader->assetExistsByName(name))
                {
                    ns->updateResourceByName(nameStr, type, yml);
                }
                else
                {
                    ns->createResource(nameStr, type, yml);
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
                                             nsName,
                                             e.what()));
    }
}

void CrudService::deleteResourceByUUID(std::string_view nsName, const std::string& uuid)
{
    try
    {
        cm::store::NamespaceId nsId {nsName};
        auto ns = getNamespaceStore(nsId);

        ns->deleteResourceByUUID(uuid);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("Failed to delete resource with UUID '{}' in namespace '{}': {}", uuid, nsName, e.what()));
    }
}

std::shared_ptr<cm::store::ICMStoreNSReader>
CrudService::getNamespaceStoreView(const cm::store::NamespaceId& nsId) const
{
    auto ns = m_store->getNSReader(nsId);
    if (!ns)
    {
        throw std::runtime_error(fmt::format("Namespace '{}' does not exist", nsId.toStr()));
    }
    return ns;
}

std::shared_ptr<cm::store::ICMstoreNS> CrudService::getNamespaceStore(const cm::store::NamespaceId& nsId) const
{
    auto ns = m_store->getNS(nsId);
    if (!ns)
    {
        throw std::runtime_error(fmt::format("Namespace '{}' does not exist", nsId.toStr()));
    }
    return ns;
}

} // namespace cm::crud
