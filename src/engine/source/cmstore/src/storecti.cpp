#include <base/logging.hpp>

#include <cmstore/types.hpp>
#include <ctistore/adapter.hpp>

#include "fileutils.hpp"
#include "storecti.hpp"

namespace cm::store
{

const base::Name G_FILTER_NAME {"filter/allow-all/0"}; ///< Filter that allows all events
/***********************************  General Methods ************************************/
const NamespaceId& CMStoreCTI::getNamespaceId() const
{
    return m_namespaceId;
}

std::vector<std::tuple<std::string, std::string>> CMStoreCTI::getCollection(ResourceType rType) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();
    std::vector<std::tuple<std::string, std::string>> collection;

    try
    {
        switch (rType)
        {
            case ResourceType::DECODER: {
                auto assetList = reader->getAssetList(cti::store::AssetType::DECODER);
                for (const auto& name : assetList)
                {
                    try
                    {
                        std::string uuid = resolveUUIDFromName(name.toStr(), ResourceType::DECODER);
                        collection.emplace_back(uuid, name.toStr());
                    }
                    catch (const std::exception& e)
                    {
                        LOG_WARNING("Failed to resolve UUID for decoder '{}': {}", name.toStr(), e.what());
                        // Skip this entry but continue processing
                    }
                }
                break;
            }
            case ResourceType::INTEGRATION: {
                auto assetList = reader->getAssetList(cti::store::AssetType::INTEGRATION);
                for (const auto& name : assetList)
                {
                    try
                    {
                        std::string uuid = resolveUUIDFromName(name.toStr(), ResourceType::INTEGRATION);
                        collection.emplace_back(uuid, name.toStr());
                    }
                    catch (const std::exception& e)
                    {
                        LOG_WARNING("Failed to resolve UUID for integration '{}': {}", name.toStr(), e.what());
                        // Skip this entry but continue processing
                    }
                }
                break;
            }
            case ResourceType::KVDB: {
                auto kvdbList = reader->listKVDB();
                for (const auto& name : kvdbList)
                {
                    try
                    {
                        std::string uuid = resolveUUIDFromName(name, ResourceType::KVDB);
                        collection.emplace_back(uuid, name);
                    }
                    catch (const std::exception& e)
                    {
                        LOG_WARNING("Failed to resolve UUID for KVDB '{}': {}", name, e.what());
                        // Skip this entry but continue processing
                    }
                }
                break;
            }
            default:
                throw std::runtime_error(fmt::format("Unsupported resource type: {}",
                                                    static_cast<int>(rType)));
        }
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to get collection for type '{}': {}",
                                            static_cast<int>(rType), e.what()));
    }

    return collection;
}

std::tuple<std::string, ResourceType> CMStoreCTI::resolveNameFromUUID(const std::string& uuid) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();

    try
    {
        auto [name, type] = reader->resolveNameAndTypeFromUUID(uuid);
        ResourceType rType;
        if (type == "decoder")
        {
            rType = ResourceType::DECODER;
        }
        else if (type == "integration")
        {
            rType = ResourceType::INTEGRATION;
        }
        else if (type == "kvdb")
        {
            rType = ResourceType::KVDB;
        }
        else
        {
            // Note: CTI store does not currently support 'rule' or 'output' types
            throw std::runtime_error(fmt::format("Unsupported resource type string: {}", type));
        }

        return std::make_tuple(name, rType);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to resolve name from UUID '{}': {}", uuid, e.what()));
    }
}

std::string CMStoreCTI::resolveHashFromUUID(const std::string& uuid) const
{
    return {};
}

std::string CMStoreCTI::resolveUUIDFromName(const std::string& name, ResourceType type) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();

    try
    {
        std::string typeStr;
        switch (type)
        {
            case ResourceType::DECODER:
                typeStr = "decoder";
                break;
            case ResourceType::INTEGRATION:
                typeStr = "integration";
                break;
            case ResourceType::KVDB:
                typeStr = "kvdb";
                break;
            default:
                throw std::runtime_error(fmt::format("Unsupported resource type: {}",
                                                    static_cast<int>(type)));
        }

        return reader->resolveUUIDFromName(base::Name(name), typeStr);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to resolve UUID for name '{}' of type '{}': {}",
                                            name, static_cast<int>(type), e.what()));
    }
}

bool CMStoreCTI::assetExistsByName(const base::Name& name) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();
    try
    {
        bool exists = reader->assetExists(name);
        LOG_DEBUG("Asset '{}' exists? [{}]", name.toStr(), exists);

        return exists;
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Error checking existence of asset with name '{}': {}", name.toStr(), e.what());
        return false;
    }
}

bool CMStoreCTI::assetExistsByUUID(const std::string& uuid) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();
    try
    {
        // If resolveNameFromUUID succeeds, the asset exists
        reader->resolveNameFromUUID(uuid);
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Error checking existence of asset with name '{}': {}", uuid, e.what());
        return false;
    }
}

const std::vector<json::Json> CMStoreCTI::getDefaultOutputs() const
{
    std::vector<json::Json> outputs;

    for (const auto& entry : std::filesystem::directory_iterator(m_defaultOutputsPath))
    {
        if (!entry.is_regular_file())
        {
            continue;
        }

        const auto ext = entry.path().extension();
        if (ext != ".yml" && ext != ".yaml")
        {
            continue;
        }

        std::ifstream in(entry.path());
        if (!in)
        {
            throw std::runtime_error(fmt::format("Failed to open output file '{}'", entry.path().string()));
        }

        std::string ymlContent((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

        try
        {
            auto jsonContent = json::Json(yml::Converter::loadYMLfromString(ymlContent));
            outputs.emplace_back(std::move(jsonContent));
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(
                fmt::format("Failed to parse output file '{}': {}", entry.path().string(), e.what()));
        }
    }

    return outputs;
}

/*********************************** General Resource ************************************/

std::string CMStoreCTI::createResource(const std::string& name, ResourceType type, const std::string& ymlContent)
{
    throw std::runtime_error("This space is Read-Only. Resource creation is not allowed.");
}

void CMStoreCTI::updateResourceByName(const std::string& name, ResourceType type, const std::string& ymlContent)
{
    throw std::runtime_error("This space is Read-Only. Resource update is not allowed.");
}

void CMStoreCTI::updateResourceByUUID(const std::string& uuid, const std::string& ymlContent)
{
    throw std::runtime_error("This space is Read-Only. Resource update is not allowed.");
}

void CMStoreCTI::deleteResourceByName(const std::string& name, ResourceType type)
{
    throw std::runtime_error("This space is Read-Only. Resource deletion is not allowed.");
}

void CMStoreCTI::deleteResourceByUUID(const std::string& uuid)
{
    throw std::runtime_error("This space is Read-Only. Resource deletion is not allowed.");
}

/**************************************** Policy ****************************************/

dataType::Policy CMStoreCTI::getPolicy() const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }
    auto reader = m_reader.lock();
    auto policyList = reader->getPolicyList();

    if (policyList.empty())
    {
        throw std::runtime_error("No policy found in CTI Store");
    }

    // TODO: Implement logic to select the correct policy if multiple exist
    auto policyName = policyList.front();

    auto policyResponse = reader->getPolicy(policyName);

    // Return the payload/document of the returned json
    auto document = policyResponse.getJson("/payload/document");
    if (!document.has_value())
    {
        throw std::runtime_error("Policy document not found in CTI Store response");
    }
    return dataType::Policy::fromJson(document.value());
}

void CMStoreCTI::upsertPolicy(const dataType::Policy& policy)
{
    throw std::runtime_error("This space is Read-Only. Policy upsert is not allowed.");
}

void CMStoreCTI::deletePolicy()
{
    throw std::runtime_error("This space is Read-Only. Policy deletion is not allowed.");
}

/************************************* INTEGRATIONS *************************************/

dataType::Integration CMStoreCTI::getIntegrationByName(const std::string& name) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();

    try
    {
        // Get raw integration document from CTI Store
        json::Json rawDoc = reader->getAsset(base::Name(name));

        // Extract the /payload/document section which contains the integration data
        auto documentOpt = rawDoc.getJson("/payload/document");
        if (!documentOpt.has_value())
        {
            throw std::runtime_error("Integration document missing /payload/document section");
        }

        json::Json document = *documentOpt;

        // Check if /id exists in the document
        auto idOpt = document.getString("/id");
        if (!idOpt.has_value())
        {
            // Fallback: extract UUID from /name field (root level) and add it to document
            auto uuidOpt = rawDoc.getString("/name");
            if (!uuidOpt.has_value())
            {
                throw std::runtime_error("Integration document missing both /payload/document/id and /name (UUID) fields");
            }
            document.setString(*uuidOpt, "/id");
        }

        // Pass the document to Integration::fromJson
        return dataType::Integration::fromJson(document);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to get integration '{}': {}", name, e.what()));
    }
}

dataType::Integration CMStoreCTI::getIntegrationByUUID(const std::string& uuid) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();

    try
    {
        // Resolve UUID to name first
        std::string name = reader->resolveNameFromUUID(uuid);

        // Get by name
        return getIntegrationByName(name);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to get integration by UUID '{}': {}", uuid, e.what()));
    }
}

/**************************************** KVDB ******************************************/

dataType::KVDB CMStoreCTI::getKVDBByName(const std::string& name) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();

    try
    {
        // Get raw KVDB document from CTI Store
        json::Json rawDoc = reader->kvdbDump(name);

        // Extract the /payload/document section which contains the KVDB data
        auto documentOpt = rawDoc.getJson("/payload/document");
        if (!documentOpt.has_value())
        {
            throw std::runtime_error("KVDB document missing /payload/document section");
        }

        json::Json document = *documentOpt;

        // Check if /id exists in the document
        auto idOpt = document.getString("/id");
        if (!idOpt.has_value())
        {
            // Fallback: extract UUID from /name field (root level) and add it to document
            auto uuidOpt = rawDoc.getString("/name");
            if (!uuidOpt.has_value())
            {
                throw std::runtime_error("KVDB document missing both /payload/document/id and /name (UUID) fields");
            }
            document.setString(*uuidOpt, "/id");
        }

        // Pass the document to KVDB::fromJson
        return dataType::KVDB::fromJson(document);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to get KVDB '{}': {}", name, e.what()));
    }
}

dataType::KVDB CMStoreCTI::getKVDBByUUID(const std::string& uuid) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();

    try
    {
        // Resolve UUID to name first
        std::string name = reader->resolveNameFromUUID(uuid);

        // Get by name
        return getKVDBByName(name);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to get KVDB by UUID '{}': {}", uuid, e.what()));
    }
}

/**************************************** ASSETS ****************************************/

json::Json CMStoreCTI::getAssetByName(const base::Name& name) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();

    try
    {
        auto isFilter = (name.parts().front() == "filter") && (name.parts().size() == 3);
        if (isFilter)
        {
            json::Json filter {};
            filter.setString(G_FILTER_NAME.fullName(), "/name");
            return filter;
        }

        // Get raw asset document from CTI Store (only decoders supported)
        json::Json rawDoc = reader->getAsset(name);
        auto documentOpt = rawDoc.getJson("/payload/document");
        if (!documentOpt.has_value())
        {
            throw std::runtime_error("Asset document missing /payload/document section");
        }

        return adaptDecoder(*documentOpt);
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to get asset '{}': {}", name.toStr(), e.what()));
    }
}

json::Json CMStoreCTI::getAssetByUUID(const std::string& uuid) const
{
    if (m_reader.expired())
    {
        throw std::runtime_error("CTI Store Reader is expired");
    }

    auto reader = m_reader.lock();

    try
    {
        // Resolve UUID to name first
        std::string name = reader->resolveNameFromUUID(uuid);

        // Get by name
        return getAssetByName(base::Name(name));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Failed to get asset by UUID '{}': {}", uuid, e.what()));
    }
}

} // namespace cm::store
