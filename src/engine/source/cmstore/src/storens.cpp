#include <base/logging.hpp>

#include <cmstore/types.hpp>

#include "fileutils.hpp"
#include "storens.hpp"

namespace cm::store
{

/************************************** Helpers  ****************************************/

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

void CMStoreNS::loadCacheFromDisk()
{
    try
    {
        json::Json cacheJson = fileutils::readJsonFile(m_cachePath);
        m_cache.deserialize(cacheJson);
        LOG_TRACE("Cache loaded from disk successfully");
    }
    catch (const std::exception& e)
    {
        LOG_WARNING("Failed to load cache from disk: {}. Rebuilding cache from storage.", e.what());
        rebuildCacheFromStorage();
        flushCacheToDisk();
    }
}

void CMStoreNS::rebuildCacheFromStorage()
{
    LOG_TRACE("Rebuilding cache from storage...");
    m_cache.reset();

    // Iterate over all resource type directories
    for (const auto& dirEntry : std::filesystem::directory_iterator(m_storagePath))
    {
        if (!dirEntry.is_directory())
        {
            continue;
        }

        // Check resource type from directory name
        ResourceType rType;
        const auto dirName = dirEntry.path().filename().string();
        if (dirName == pathns::DECODERS_DIR)
        {
            rType = ResourceType::DECODER;
        }
        else if (dirName == pathns::OUTPUTS_DIR)
        {
            rType = ResourceType::OUTPUT;
        }
        else if (dirName == pathns::FILTERS_DIR)
        {
            rType = ResourceType::FILTER;
        }
        else if (dirName == pathns::INTEGRATIONS_DIR)
        {
            rType = ResourceType::INTEGRATION;
        }
        else if (dirName == pathns::KVDBS_DIR)
        {
            rType = ResourceType::KVDB;
        }
        else
        {
            LOG_WARNING("Unknown resource type directory '{}' found in storage, skipping.", dirName);
            continue;
        }

        // Iterate over all files in the resource type directory
        for (const auto& fileEntry : std::filesystem::directory_iterator(dirEntry.path()))
        {
            if (!fileEntry.is_regular_file())
            {
                continue;
            }

            try
            {
                // Read file content
                auto fileContent = fileutils::readFileAsString(fileEntry.path());

                // Extract UUID
                auto uuid = upsertUUID(fileContent);

                // Extract resource name from file name
                std::string fileName = fileEntry.path().filename().string();
                if (fileName.size() <= pathns::ASSET_EXTENSION.size()
                    || fileName.substr(fileName.size() - pathns::ASSET_EXTENSION.size()) != pathns::ASSET_EXTENSION)
                {
                    throw std::runtime_error("Invalid file extension");
                }
                std::string resourceName = fileName.substr(0, fileName.size() - pathns::ASSET_EXTENSION.size());

                // If resource type is DECODER, OUTPUT or FILTER, revert only the first and last '_' to '/'
                // TODO: Find a better way to handle this case, this is a workaround for legacy naming
                if (rType == ResourceType::DECODER || rType == ResourceType::OUTPUT
                    || rType == ResourceType::FILTER)
                {
                    // Revert only the first and last '_' to '/'
                    size_t firstUnderscore = resourceName.find('_');
                    size_t lastUnderscore = resourceName.rfind('_');
                    if (firstUnderscore != std::string::npos)
                    {
                        resourceName[firstUnderscore] = '/';
                    }
                    if (lastUnderscore != std::string::npos && lastUnderscore != firstUnderscore)
                    {
                        resourceName[lastUnderscore] = '/';
                    }
                }

                // Add entry to cache
                m_cache.addEntry(uuid, resourceName, rType);
            }
            catch (const std::exception& e)
            {
                LOG_WARNING("Failed to process resource file '{}': {}", fileEntry.path().string(), e.what());
            }
        }
    }

    LOG_TRACE("Cache rebuilt from storage successfully");

    // Flush the rebuilt cache to disk
    flushCacheToDisk();
}

std::string CMStoreNS::upsertUUID(std::string& ymlContent)
{
    json::Json jsonContent;
    bool isJson = false;

    // Try to parse as JSON first, fallback to YAML
    try
    {
        jsonContent = json::Json(ymlContent.c_str());
        if (!jsonContent.isObject())
        {
            throw std::runtime_error("Content is not a valid JSON object");
        }
        isJson = true;
    }
    catch (const std::exception&)
    {
        // Try parsing as YAML
        try
        {
            jsonContent = json::Json(yml::Converter::loadYMLfromString(ymlContent));
            if (!jsonContent.isObject())
            {
                throw std::runtime_error("YAML content is not a valid JSON object");
            }
            isJson = false;
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error("Content is neither valid JSON nor valid YAML: " + std::string(e.what()));
        }
    }

    // Check if UUID field exists and validate it
    if (auto opt = jsonContent.getString(pathns::JSON_ID_PATH); opt.has_value())
    {
        const std::string& uuid = opt.value();
        if (!base::utils::generators::isValidUUIDv4(uuid))
        {
            throw std::runtime_error("Existing UUIDv4 is not valid: " + uuid);
        }
        return uuid;
    }

    // Generate new UUID and add it to content
    std::string uuid = base::utils::generators::generateUUIDv4();

    if (isJson)
    {
        // Handle JSON format
        jsonContent.setString(uuid, pathns::JSON_ID_PATH);
        ymlContent = jsonContent.prettyStr();
    }
    else
    {
        // Handle YAML format - append UUID at the end
        if (!ymlContent.empty() && ymlContent.back() != '\n')
        {
            ymlContent += '\n';
        }
        ymlContent += fmt::format(pathns::YML_PAIR_FMT, uuid);

        // Re-parse to ensure correctness and add UUID field
        try
        {
            jsonContent = json::Json(yml::Converter::loadYMLfromString(ymlContent));
        }
        catch (const std::exception& e)
        {
            // This never should happen, just in case log the error
            throw std::runtime_error(fmt::format("Failed to validate YML after inserting UUID: {}", e.what()));
        }
    }

    return uuid;
}

std::filesystem::path CMStoreNS::getResourcePaths(const std::string& name, ResourceType type) const
{
    std::filesystem::path rPath = m_storagePath;

    auto fileName = name;
    if (type == ResourceType::DECODER || type == ResourceType::OUTPUT
        || type == ResourceType::FILTER || type == ResourceType::INTEGRATION || type == ResourceType::KVDB)
    {
        // Replace '/' with '_' to avoid directory traversal on assets names
        std::replace(fileName.begin(), fileName.end(), '/', '_');
    }

    // Validate name
    if (!fileutils::isValidFileName(fileName))
    {
        throw std::runtime_error(
            fmt::format("Invalid resource name: '{}' for resource '{}'", name, resourceTypeToString(type)));
    }

    // Generate the paths based on resource type
    rPath /= [&]() -> std::filesystem::path
    {
        switch (type)
        {
            case ResourceType::DECODER: return pathns::DECODERS_DIR;
            case ResourceType::OUTPUT: return pathns::OUTPUTS_DIR;
            case ResourceType::FILTER: return pathns::FILTERS_DIR;
            case ResourceType::INTEGRATION: return pathns::INTEGRATIONS_DIR;
            case ResourceType::KVDB: return pathns::KVDBS_DIR;
            default: throw std::runtime_error("Unsupported resource type for path retrieval");
        }
    }() / fileName.append(pathns::ASSET_EXTENSION);

    return rPath;
}

/***********************************  General Methods ************************************/
const NamespaceId& CMStoreNS::getNamespaceId() const
{
    return m_namespaceId;
}

std::vector<std::tuple<std::string, std::string>> CMStoreNS::getCollection(ResourceType rType) const
{
    std::shared_lock lock(m_mutex);
    return m_cache.getCollection(rType);
}

std::tuple<std::string, ResourceType> CMStoreNS::resolveNameFromUUID(const std::string& uuid) const
{
    // Search in cache the name-type pair for the given UUID
    std::shared_lock lock(m_mutex);
    return resolveNameFromUUIDUnlocked(uuid);
}

std::string CMStoreNS::resolveUUIDFromName(const std::string& name, ResourceType type) const
{
    // Search in cache the UUID for the given name-type pair
    std::shared_lock lock(m_mutex);
    return resolveUUIDFromNameUnlocked(name, type);
}

bool CMStoreNS::assetExistsByName(const base::Name& name) const
{
    // Search asset as decoder, roule, filter, output or integration
    const auto rType = getResourceTypeFromAssetName(name);
    if (rType == ResourceType::UNDEFINED)
    {
        throw std::runtime_error("Asset type could not be determined from name: " + name.fullName());
    }

    // Check if asset exists
    std::shared_lock lock(m_mutex);
    const auto nameStr = name.fullName();
    return m_cache.existsNameType(nameStr, rType);
}

bool CMStoreNS::assetExistsByUUID(const std::string& uuid) const
{
    std::shared_lock lock(m_mutex);
    auto opt = m_cache.getNameTypeByUUID(uuid);
    if (!opt.has_value())
    {
        return false;
    }

    const auto& [name, rType] = opt.value();
    if (rType == ResourceType::KVDB)
    {
        return true;
    }
    const auto assetType = getResourceTypeFromAssetName(base::Name(name));
    return assetType != ResourceType::UNDEFINED && assetType == rType;
}

/*********************************** General Resource ************************************/

std::string CMStoreNS::createResource(const std::string& name, ResourceType type, const std::string& ymlContent)
{
    // Fast check if name already exists
    {
        std::shared_lock lock(m_mutex);
        if (m_cache.existsNameType(name, type))
        {
            throw std::runtime_error(
                fmt::format("Resource with name '{}' and type '{}' already exists", name, resourceTypeToString(type)));
        }
    }

    // Generate the file path, will throw if name/type invalid
    auto resourcePath = getResourcePaths(name, type);

    // Get the UUID from content, adding it if missing
    // Will throw if YML/Resource is invalid
    std::string modifiableYml = ymlContent;
    auto uuid = upsertUUID(modifiableYml);

    std::unique_lock lock(m_mutex); // Acquire write cache and file lock

    // Check if UUID already exists, its possible that the resource is being created with an existing UUID
    if (m_cache.existsUUID(uuid))
    {
        throw std::runtime_error(fmt::format("Resource with UUID '{}' already exists", uuid));
    }

    // Check again the name now with write lock
    if (m_cache.existsNameType(name, type))
    {
        throw std::runtime_error(
            fmt::format("Resource with name '{}' and type '{}' already exists", name, resourceTypeToString(type)));
    }

    // Store resource to disk
    auto error = fileutils::upsertFile(resourcePath, modifiableYml);
    if (error.has_value())
    {
        throw std::runtime_error(fmt::format("Failed to create resource file '{}' of type '{}': {}",
                                             resourcePath.string(),
                                             resourceTypeToString(type),
                                             error.value()));
    }

    // Update cache
    m_cache.addEntry(uuid, name, type);
    flushCacheToDisk();

    return uuid;
}

void CMStoreNS::updateResourceByName(const std::string& name, ResourceType type, const std::string& ymlContent)
{
    // Generate the file path, will throw if name/type invalid
    auto resourcePath = getResourcePaths(name, type);

    // Get the UUID from content (Throws if missing/invalid)
    json::Json jsonContent = json::Json(yml::Converter::loadYMLfromString(ymlContent));
    auto optUUID = jsonContent.getString(pathns::JSON_ID_PATH);
    if (!optUUID.has_value())
    {
        throw std::runtime_error("UUID field (/id) is missing in the provided content");
    }

    std::unique_lock lock(m_mutex); // Acquire write cache and file lock

    // Resolve existing UUID from name
    auto existingUUID = resolveUUIDFromNameUnlocked(name, type);
    auto& uuid = optUUID.value();

    // Check if the UUID in content matches the existing one
    if (uuid != existingUUID)
    {
        throw std::runtime_error(
            fmt::format("UUID '{}' in content does not match existing resource UUID '{}' for name '{}' and type '{}'",
                        uuid,
                        existingUUID,
                        name,
                        resourceTypeToString(type)));
    }

    // Store updated resource to disk
    auto error = fileutils::upsertFile(resourcePath, ymlContent);
    if (error.has_value())
    {
        throw std::runtime_error(fmt::format("Failed to update resource file '{}' of type '{}': {}",
                                             resourcePath.string(),
                                             resourceTypeToString(type),
                                             error.value()));
    }

    flushCacheToDisk();
}

void CMStoreNS::updateResourceByUUID(const std::string& uuid, const std::string& ymlContent)
{
    // Get the UUID from content (Throws if missing/invalid)
    json::Json jsonContent = json::Json(yml::Converter::loadYMLfromString(ymlContent));
    auto optUUID = jsonContent.getString(pathns::JSON_ID_PATH);
    if (!optUUID.has_value())
    {
        throw std::runtime_error("UUID field (/id) is missing in the provided content");
    }

    // Check if the UUID in content matches the provided one
    if (uuid != optUUID.value())
    {
        throw std::runtime_error(
            fmt::format("UUID '{}' in content does not match provided UUID '{}'", optUUID.value(), uuid));
    }

    std::unique_lock lock(m_mutex); // Acquire write cache and file lock
    // Resolve name-type from UUID
    auto [name, type] = resolveNameFromUUIDUnlocked(uuid);
    // Generate the file path
    auto resourcePath = getResourcePaths(name, type);
    // Store updated resource to disk
    auto error = fileutils::upsertFile(resourcePath, ymlContent);
    if (error.has_value())
    {
        throw std::runtime_error(fmt::format("Failed to update resource file '{}' of type '{}': {}",
                                             resourcePath.string(),
                                             resourceTypeToString(type),
                                             error.value()));
    }

    flushCacheToDisk();
}

void CMStoreNS::deleteResourceByName(const std::string& name, ResourceType type)
{
    std::unique_lock lock(m_mutex); // Acquire write cache and file lock

    // Resolve UUID from name
    auto uuid = resolveUUIDFromNameUnlocked(name, type);

    // Generate the file path
    auto resourcePath = getResourcePaths(name, type);

    // Delete resource file from disk
    auto error = fileutils::deleteFile(resourcePath);
    if (error.has_value())
    {
        throw std::runtime_error(fmt::format("Failed to delete resource file '{}' of type '{}': {}",
                                             resourcePath.string(),
                                             resourceTypeToString(type),
                                             error.value()));
    }

    // Update cache
    m_cache.removeEntryByUUID(uuid);
    flushCacheToDisk();
}

std::string CMStoreNS::resolveUUIDFromNameUnlocked(const std::string& name, ResourceType type) const
{
    auto optUUID = m_cache.getUUIDByNameType(name, type);
    if (!optUUID.has_value())
    {
        throw std::runtime_error(
            fmt::format("Resource with name '{}' and type '{}' does not exist", name, resourceTypeToString(type)));
    }
    return optUUID.value();
}

std::tuple<std::string, ResourceType> CMStoreNS::resolveNameFromUUIDUnlocked(const std::string& uuid) const
{
    auto opt = m_cache.getNameTypeByUUID(uuid);
    if (!opt)
    {
        throw std::runtime_error(fmt::format("Resource with UUID '{}' does not exist", uuid));
    }
    return *opt;
}

void CMStoreNS::deleteResourceByUUID(const std::string& uuid)
{
    std::unique_lock lock(m_mutex); // Acquire write cache and file lock

    // Resolve name-type from UUID
    auto [name, type] = resolveNameFromUUIDUnlocked(uuid);

    // Generate the file path
    auto resourcePath = getResourcePaths(name, type);

    // Delete resource file from disk
    auto error = fileutils::deleteFile(resourcePath);
    if (error.has_value())
    {
        throw std::runtime_error(fmt::format("Failed to delete resource file '{}' of type '{}': {}",
                                             resourcePath.string(),
                                             resourceTypeToString(type),
                                             error.value()));
    }

    // Update cache
    m_cache.removeEntryByUUID(uuid);
    flushCacheToDisk();
}

/**************************************** Policy ****************************************/

dataType::Policy CMStoreNS::getPolicy() const
{
    // Load policy from disk
    std::shared_lock lock(m_mutex);
    auto policyPath = m_storagePath / pathns::POLICY_FILE;
    auto json = fileutils::readJsonFile(policyPath);
    return dataType::Policy::fromJson(json);
}

void CMStoreNS::upsertPolicy(const dataType::Policy& policy)
{

    std::unique_lock lock(m_mutex);
    // Store policy to disk
    auto policyPath = m_storagePath / pathns::POLICY_FILE;
    auto err = fileutils::upsertFile(policyPath, policy.toJson().str());
    if (err.has_value())
    {
        throw std::runtime_error(
            fmt::format("Failed to upsert policy file '{}': {}", policyPath.string(), err.value()));
    }
}

void CMStoreNS::deletePolicy()
{
    std::unique_lock lock(m_mutex);
    // Delete policy from disk
    auto policyPath = m_storagePath / pathns::POLICY_FILE;
    auto err = fileutils::deleteFile(policyPath);
    if (err.has_value())
    {
        throw std::runtime_error(
            fmt::format("Failed to delete policy file '{}': {}", policyPath.string(), err.value()));
    }
}

/************************************* INTEGRATIONS *************************************/

dataType::Integration CMStoreNS::getIntegrationByName(const std::string& name) const
{
    // Search in cache for name
    std::shared_lock lock(m_mutex);

    auto optUUID = m_cache.getUUIDByNameType(name, ResourceType::INTEGRATION);
    if (!optUUID.has_value())
    {
        throw std::runtime_error(fmt::format("Integration with name '{}' does not exist", name));
    }

    // Load integration from disk
    const auto path = getResourcePaths(name, ResourceType::INTEGRATION);
    auto json = fileutils::readYMLFileAsJson(path);

    return dataType::Integration::fromJson(json, /*requireUUID:*/ true);
}

dataType::Integration CMStoreNS::getIntegrationByUUID(const std::string& uuid) const
{
    // Search in cache for UUID
    std::shared_lock lock(m_mutex);
    auto EntryOpt = m_cache.getNameTypeByUUID(uuid);
    if (!EntryOpt.has_value())
    {
        throw std::runtime_error(fmt::format("Integration with UUID '{}' does not exist", uuid));
    }
    const auto& [name, type] = EntryOpt.value();
    if (type != ResourceType::INTEGRATION)
    {
        throw std::runtime_error(
            fmt::format("Resource with UUID '{}' is a '{}' not an Integration", uuid, resourceTypeToString(type)));
    }

    // Load integration from disk
    const auto path = getResourcePaths(name, ResourceType::INTEGRATION);
    auto json = fileutils::readYMLFileAsJson(path);
    return dataType::Integration::fromJson(json, /*requireUUID:*/ true);
}

const std::vector<json::Json> CMStoreNS::getDefaultOutputs() const
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

/**************************************** KVDB ******************************************/

dataType::KVDB CMStoreNS::getKVDBByName(const std::string& name) const
{
    std::shared_lock lock(m_mutex);
    // Check if name exists
    auto optUUID = m_cache.getUUIDByNameType(name, ResourceType::KVDB);
    if (!optUUID.has_value())
    {
        throw std::runtime_error(fmt::format("KVDB with name '{}' does not exist", name));
    }
    const auto& uuid = optUUID.value();

    // Load KVDB from disk
    auto resourcePath = getResourcePaths(name, ResourceType::KVDB);
    auto json = fileutils::readYMLFileAsJson(resourcePath);
    return dataType::KVDB::fromJson(json, /*requireUUID:*/ true);
}

dataType::KVDB CMStoreNS::getKVDBByUUID(const std::string& uuid) const
{
    std::shared_lock lock(m_mutex);
    // Check if UUID exists
    auto optNameType = m_cache.getNameTypeByUUID(uuid);
    if (!optNameType.has_value())
    {
        throw std::runtime_error(fmt::format("KVDB with UUID '{}' does not exist", uuid));
    }
    const auto& [name, type] = optNameType.value();

    // Verify type
    if (type != ResourceType::KVDB)
    {
        throw std::runtime_error(
            fmt::format("Resource with UUID '{}' is a '{}' not a KVDB", uuid, resourceTypeToString(type)));
    }

    // Load KVDB from disk
    auto resourcePath = getResourcePaths(name, ResourceType::KVDB);
    auto json = fileutils::readYMLFileAsJson(resourcePath);
    return dataType::KVDB::fromJson(json, /*requireUUID:*/ true);
}

/**************************************** ASSETS ****************************************/

json::Json CMStoreNS::getAssetByName(const base::Name& name) const
{
    // Search asset as decoder, roule, filter, output or integration
    const auto rType = getResourceTypeFromAssetName(name);
    if (rType == ResourceType::UNDEFINED)
    {
        throw std::runtime_error("Asset type could not be determined from name: " + name.fullName());
    }

    // Check if asset exists
    std::shared_lock lock(m_mutex);
    const auto nameStr = name.fullName();
    if (!m_cache.existsNameType(nameStr, rType))
    {
        throw std::runtime_error(
            fmt::format("Asset with name '{}' and type '{}' does not exist", nameStr, resourceTypeToString(rType)));
    }

    // Load asset from disk
    auto resourcePath = getResourcePaths(nameStr, rType);

    return fileutils::readYMLFileAsJson(resourcePath);
}

json::Json CMStoreNS::getAssetByUUID(const std::string& uuid) const
{
    std::shared_lock lock(m_mutex);
    // Check if UUID exists
    auto optNameType = m_cache.getNameTypeByUUID(uuid);
    if (!optNameType.has_value())
    {
        throw std::runtime_error(fmt::format("Asset with UUID '{}' does not exist", uuid));
    }
    const auto& [name, type] = optNameType.value();

    // Load asset from disk
    auto resourcePath = getResourcePaths(name, type);
    return fileutils::readYMLFileAsJson(resourcePath);
}

} // namespace cm::store
