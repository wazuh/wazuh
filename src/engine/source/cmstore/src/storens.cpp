#include <base/logging.hpp>

#include "fileutils.hpp"
#include "storens.hpp"

namespace cm::store
{

void CMStoreNS::flushCacheToDisk()
{
    auto error = fileutils::upsertFile(m_cachePath, m_cache.serialize().str());
    if (error.has_value())
    {
        // This never should happen.
        LOG_ERROR("Failed to dump cache of namespace to disk: {}", error.value());
        throw std::runtime_error("Failed to dump cache to disk: " + error.value());
    }
    LOG_TRACE("Cache flushed to disk successfully at {}", m_cachePath.string());
}

const NamespaceId& CMStoreNS::getNamespaceId() const
{
    return m_namespaceId;
}
std::vector<std::tuple<std::string, std::string>> CMStoreNS::getCollection(ResourceType) const
{
    return {};
}
std::tuple<std::string, ResourceType> CMStoreNS::resolveNameFromUUID(const std::string&) const
{
    return {"", ResourceType {}};
}
std::string CMStoreNS::resolveUUIDFromName(const std::string&, ResourceType) const
{
    return "";
}

dataType::Policy CMStoreNS::getPolicy() const
{
    return {};
}
void CMStoreNS::upsertPolicy(const dataType::Policy&) {}
void CMStoreNS::deletePolicy() {}

/**************************************** INTEGRATIONS ****************************************/

std::string CMStoreNS::createIntegration(const dataType::Integration& integration)
{

    return "";

}

dataType::Integration CMStoreNS::getIntegrationByName(const std::string&) const
{
    return {};
}
dataType::Integration CMStoreNS::getIntegrationByUUID(const std::string&) const
{
    return {};
}
bool CMStoreNS::integrationExistsByName(const std::string&) const
{
    return false;
}
bool CMStoreNS::integrationExistsByUUID(const std::string&) const
{
    return false;
}

void CMStoreNS::updateIntegration(const dataType::Integration&) {}
void CMStoreNS::deleteIntegrationByName(const std::string&) {}
void CMStoreNS::deleteIntegrationByUUID(const std::string&) {}

/**************************************** KVDB ****************************************/

std::string CMStoreNS::createKVDB(const std::string& name, json::Json&& data)
{

    // Validate name
    if (!fileutils::isValidFileName(name))
    {
        throw std::runtime_error(fmt::format("Invalid KVDB name: '{}'", name));
    }

    std::unique_lock lock(m_mutex);

    // Check if name already exists
    if (m_cache.existsNameType(name, ResourceType::KVDB))
    {
        throw std::runtime_error(fmt::format("KVDB with name '{}' already exists", name));
    }

    // Generate UUID and create KVDB object
    std::string uuid = base::utils::generators::generateUUIDv4();
    // Check if UUID already exists (extremely unlikely)
    while (m_cache.existsUUID(uuid))
    {
        LOG_DEBUG("Generated UUID '{}' already exists, generating a new one", uuid);
        uuid = base::utils::generators::generateUUIDv4();
    }

    dataType::KVDB kvdb {uuid, std::string {name}, std::move(data)};

    // Store KVDB to disk
    const auto filePath = m_storagePath / pathns::KVDBS_DIR / name;
    auto error = fileutils::upsertFile(filePath, kvdb.toJson().str());
    if (error.has_value())
    {
        throw std::runtime_error(fmt::format("Failed to create KVDB file '{}': {}", filePath.string(), error.value()));
    }

    // Update cache
    //m_cache.addEntry(uuid, name, ResourceType::KVDB);
    flushCacheToDisk();

    return uuid;
}

json::Json CMStoreNS::getKVDBByName(const std::string& name) const
{
    std::shared_lock lock(m_mutex);

    // Check if name exists
    if (!m_cache.existsNameType(name, ResourceType::KVDB))
    {
        throw std::runtime_error(fmt::format("KVDB with name '{}' does not exist", name));
    }

    // load KVDB from disk
    const auto filePath = m_storagePath / pathns::KVDBS_DIR / name;
    return fileutils::readJsonFile(filePath);
}

json::Json CMStoreNS::getKVDBByUUID(const std::string& uuid) const
{
    std::shared_lock lock(m_mutex);
    // Resolve name from UUID
    auto optNameType = m_cache.getNameTypeByUUID(uuid);
    if (!optNameType.has_value())
    {
        throw std::runtime_error(fmt::format("KVDB with UUID '{}' does not exist", uuid));
    }
    const auto& [name, type] = optNameType.value();
    if (type != ResourceType::KVDB)
    {
        throw std::runtime_error(fmt::format("Resource with UUID '{}' is a '{}' not a KVDB", uuid, resourceTypeToString(type)));
    }

    // load KVDB from disk
    const auto filePath = m_storagePath / pathns::KVDBS_DIR / name;
    return fileutils::readJsonFile(filePath);
}

bool CMStoreNS::kvdbExistsByName(const std::string& name) const
{
    std::shared_lock lock(m_mutex);
    return m_cache.existsNameType(name, ResourceType::KVDB);
}

bool CMStoreNS::kvdbExistsByUUID(const std::string& uuid) const
{
    std::shared_lock lock(m_mutex);
    auto optNameType = m_cache.getNameTypeByUUID(uuid);
    if (!optNameType.has_value())
    {
        return false;
    }
    const auto& [name, type] = optNameType.value();
    return type == ResourceType::KVDB;
}

void CMStoreNS::updateKVDB(const dataType::KVDB& kvdb)
{
    std::unique_lock lock(m_mutex); // Read for m_cache but write for file

    // Check if UUID exists
    auto optNameType = m_cache.getNameTypeByUUID(kvdb.getUUID());
    if (!optNameType.has_value())
    {
        throw std::runtime_error(fmt::format("KVDB with UUID '{}' does not exist", kvdb.getUUID()));
    }
    const auto& [existingName, type] = optNameType.value();
    if (type != ResourceType::KVDB)
    {
        throw std::runtime_error(fmt::format("Resource with UUID '{}' is a '{}' not a KVDB", kvdb.getUUID(), resourceTypeToString(type)));
    }

    // If name is different, is an error (name is immutable)
    if (existingName != kvdb.getName())
    {
        throw std::runtime_error(fmt::format(
            "Cannot change name of KVDB with UUID {} from '{}' to '{}'", kvdb.getUUID(), existingName, kvdb.getName()));
    }

    // Update KVDB on disk
    const auto filePath = m_storagePath / pathns::KVDBS_DIR / kvdb.getName();
    auto error = fileutils::upsertFile(filePath, kvdb.toJson().str());
    if (error.has_value())
    {
        throw std::runtime_error("Failed to update KVDB file: " + error.value());
    }
}

void CMStoreNS::deleteKVDBByName(const std::string& name)
{
    std::unique_lock lock(m_mutex);
    // Check if name exists
    if (!m_cache.existsNameType(name, ResourceType::KVDB))
    {
        throw std::runtime_error(fmt::format("KVDB with name '{}' does not exist", name));
    }

    // Delete KVDB file from disk
    const auto filePath = m_storagePath / pathns::KVDBS_DIR / name;
    std::error_code ec;
    std::filesystem::remove(filePath, ec);
    if (ec)
    {
        throw std::runtime_error(fmt::format("Failed to delete KVDB file '{}': {}", filePath.string(), ec.message()));
    }

    // Update cache
    m_cache.removeEntryByNameType(name, ResourceType::KVDB);
    flushCacheToDisk();
}

void CMStoreNS::deleteKVDBByUUID(const std::string& uuid)
{

    std::unique_lock lock(m_mutex);
    // Resolve name from UUID
    auto optNameType = m_cache.getNameTypeByUUID(uuid);
    if (!optNameType.has_value())
    {
        throw std::runtime_error(fmt::format("KVDB with UUID '{}' does not exist", uuid));
    }
    const auto& [name, type] = optNameType.value();
    if (type != ResourceType::KVDB)
    {
        throw std::runtime_error(
            fmt::format("Resource with UUID '{}' is a '{}' not a KVDB", uuid, resourceTypeToString(type)));
    }

    // Delete KVDB file from disk
    const auto filePath = m_storagePath / pathns::KVDBS_DIR / name;
    std::error_code ec;
    std::filesystem::remove(filePath, ec);
    if (ec)
    {
        throw std::runtime_error(fmt::format("Failed to delete KVDB file '{}': {}", filePath.string(), ec.message()));
    }

    // Update cache
    m_cache.removeEntryByUUID(uuid);
    flushCacheToDisk();
}

/**************************************** ASSETS ****************************************/

json::Json CMStoreNS::getAssetByName(const base::Name&) const
{
    return {};
}
json::Json CMStoreNS::getAssetByUUID(const std::string&) const
{
    return {};
}
bool CMStoreNS::assetExistsByName(const base::Name&) const
{
    return false;
}
bool CMStoreNS::assetExistsByUUID(const std::string&) const
{
    return false;
}
std::string CMStoreNS::createAsset(const json::Json&)
{
    return "";
}
void CMStoreNS::updateAsset(const json::Json&) {}
void CMStoreNS::deleteAssetByName(const base::Name&) {}
void CMStoreNS::deleteAssetByUUID(const std::string&) {}
} // namespace cm::store
