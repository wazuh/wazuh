#include "manager.hpp"

#include <filesystem>
#include <fstream>
#include <mutex>

#include <fmt/format.h>
#include <maxminddb.h>

#include <base/logging.hpp>
#include <base/utils/hash.hpp>
#include <store/istore.hpp>

#include "dbHandle.hpp"
#include "locator.hpp"

namespace geo
{
Manager::Manager(const std::shared_ptr<store::IStore>& store, const std::shared_ptr<IDownloader>& downloader)
    : m_store(store)
    , m_downloader(downloader)
{
    if (m_store == nullptr)
    {
        throw std::runtime_error("Maxmindb manager needs a non-null store");
    }

    if (m_downloader == nullptr)
    {
        throw std::runtime_error("Maxmindb manager needs a non-null downloader");
    }

    // Load dbs from the internal store (single document with nested structure)
    auto docResp = m_store->readDoc(base::Name(INTERNAL_NAME));
    if (base::isError(docResp))
    {
        LOG_DEBUG("Geo module do not have dbs in the store: {}", base::getError(docResp).message);
        return;
    }

    auto doc = base::getResponse(docResp);

    // Load city database if present
    auto cityPath = doc.getString("/city/path");
    auto cityHash = doc.getString("/city/hash");
    auto cityCreatedAt = doc.getInt64("/city/generated_at");
    if (cityPath.has_value() && cityHash.has_value() && cityCreatedAt.has_value())
    {
        auto addResp = addDbUnsafe(cityPath.value(), cityHash.value(), cityCreatedAt.value(), Type::CITY);
        if (base::isError(addResp))
        {
            LOG_ERROR("Geo cannot add city db '{}': {}", cityPath.value(), base::getError(addResp).message);
        }
    }
    else if (cityPath.has_value() || cityHash.has_value() || cityCreatedAt.has_value())
    {
        LOG_WARNING("Geo store has incomplete city database information, skipping");
    }

    // Load asn database if present
    auto asnPath = doc.getString("/asn/path");
    auto asnHash = doc.getString("/asn/hash");
    auto asnCreatedAt = doc.getInt64("/asn/generated_at");
    if (asnPath.has_value() && asnHash.has_value() && asnCreatedAt.has_value())
    {
        auto addResp = addDbUnsafe(asnPath.value(), asnHash.value(), asnCreatedAt.value(), Type::ASN);
        if (base::isError(addResp))
        {
            LOG_ERROR("Geo cannot add asn db '{}': {}", asnPath.value(), base::getError(addResp).message);
        }
    }
    else if (asnPath.has_value() || asnHash.has_value() || asnCreatedAt.has_value())
    {
        LOG_WARNING("Geo store has incomplete asn database information, skipping");
    }
}

base::OptError
Manager::upsertStoreEntry(const std::string& path, Type type, const std::string& hash, const int64_t createdAt)
{
    // Read existing document or create new one
    auto internalName = base::Name(INTERNAL_NAME);
    auto docResp = m_store->readDoc(internalName);

    store::Doc doc;
    if (!base::isError(docResp))
    {
        doc = std::move(base::getResponse(docResp));
    }

    // Update fields for the specific type
    auto typePrefix = fmt::format("/{}", typeName(type));
    doc.setString(path, typePrefix + "/path");
    doc.setString(hash, typePrefix + "/hash");
    doc.setInt64(createdAt, typePrefix + "/generated_at");

    auto storeResp = m_store->upsertDoc(internalName, doc);
    if (base::isError(storeResp))
    {
        return base::Error {
            fmt::format("Cannot update internal store for '{}': {}", path, base::getError(storeResp).message)};
    }

    return base::noError();
}

bool Manager::needsUpdate(const std::string& name, const std::string& remoteHash, Type type) const
{
    // Read the single document and check the specific type field
    auto internalResp = m_store->readDoc(base::Name(INTERNAL_NAME));

    if (base::isError(internalResp))
    {
        // If there's no stored document, we need to update
        return true;
    }

    auto doc = base::getResponse(internalResp);
    auto typePrefix = fmt::format("/{}", typeName(type));

    auto storedHash = doc.getString(typePrefix + "/hash");
    if (!storedHash.has_value())
    {
        return true;
    }

    // Check if file exists physically
    auto storedPath = doc.getString(typePrefix + "/path");
    if (storedPath.has_value())
    {
        if (!std::filesystem::exists(storedPath.value()))
        {
            // File was deleted, needs update
            return true;
        }
    }

    return storedHash.value() != remoteHash;
}

base::OptError
Manager::addDbUnsafe(const std::string& path, const std::string& hash, const int64_t createdAt, Type type)
{
    const auto name = std::filesystem::path(path).filename().string();

    // Check if the type has already a database
    if (m_dbTypes.find(type) != m_dbTypes.end())
    {
        return base::Error {fmt::format("Type '{}' already has the database '{}'", typeName(type), m_dbTypes.at(type))};
    }

    // Check if the database is already added
    if (m_dbs.find(name) != m_dbs.end())
    {
        return base::Error {fmt::format("Database with name '{}' already exists", name)};
    }

    // Create stable handle + immutable instance (MMDB_open is done inside DbInstance)
    auto handle = std::make_shared<DbHandle>();
    try
    {
        auto inst = std::make_shared<DbInstance>(path, hash, createdAt, type);
        handle->store(std::move(inst));
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Cannot add database '{}': {}", path, e.what())};
    }

    // Publish
    m_dbs.emplace(name, handle);
    m_dbTypes.emplace(type, name);

    return base::noError();
}

base::OptError Manager::writeDb(const std::string& path, const std::string& content)
{
    auto filePath = std::filesystem::path(path);

    // Create directories if they do not exist
    try
    {
        std::filesystem::create_directories(filePath.parent_path());
        // Set permissions to 770 (rwxrwx---)
        std::filesystem::permissions(filePath.parent_path(),
                                     std::filesystem::perms::owner_all | std::filesystem::perms::group_all,
                                     std::filesystem::perm_options::replace);
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Cannot create directories for '{}': {}", path, e.what())};
    }

    // Write the content to the file
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open())
    {
        return base::Error {fmt::format("Cannot open file '{}'", path)};
    }
    try
    {
        file.write(content.c_str(), content.size());
        file.close();
    }
    catch (const std::exception& e)
    {
        file.close();
        return base::Error {fmt::format("Cannot write to file '{}': {}", path, e.what())};
    }

    return base::noError();
}

base::OptError Manager::processDbEntry(const std::string& path,
                                       Type type,
                                       const std::string& gzUrl,
                                       const std::string& expectedMd5,
                                       const int64_t createdAt)
{
    const auto name = std::filesystem::path(path).filename().string();

    // Lock map only for validating and obtaining/creating handle
    std::unique_lock lock(m_rwMapMutex);

    if (m_dbTypes.find(type) != m_dbTypes.end() && m_dbTypes.at(type) != name)
    {
        return base::Error {fmt::format(
            "The name '{}' does not correspond to any database for type '{}'. "
            "If you want it to correspond, please delete the existing database and recreate it with this name.",
            name,
            typeName(type))};
    }

    // Check if database needs update by comparing stored hash with manifest MD5
    if (!needsUpdate(name, expectedMd5, type))
    {
        return base::noError();
    }

    // Get/create stable handle
    std::shared_ptr<DbHandle> handle;
    auto it = m_dbs.find(name);
    if (it != m_dbs.end())
    {
        handle = it->second;
    }
    else
    {
        handle = std::make_shared<DbHandle>();
        m_dbs.emplace(name, handle);
        m_dbTypes.emplace(type, name);
    }

    // Already have the handle; release the map lock so as not to block
    lock.unlock();

    // Download gz with retries and validate MD5
    std::string gzContent;
    base::OptError error = base::Error {fmt::format("Cannot download database from '{}'", gzUrl)};

    for (int i = 0; i < MAX_RETRIES; ++i)
    {
        auto downloadResp = m_downloader->downloadHTTPS(gzUrl);
        if (base::isError(downloadResp))
        {
            error = base::Error {
                fmt::format("Cannot download database from '{}': {}", gzUrl, base::getError(downloadResp).message)};
            continue;
        }

        gzContent = base::getResponse(downloadResp);

        // Validate MD5 of the gz file
        const auto computedMd5 = base::utils::hash::md5(gzContent);
        if (computedMd5 == expectedMd5)
        {
            error = base::noError();
            break;
        }

        error = base::Error {
            fmt::format("MD5 mismatch for database '{}'. Expected: {}, Got: {}", gzUrl, expectedMd5, computedMd5)};
    }

    if (base::isError(error))
    {
        return error;
    }

    // Extract .mmdb from gz to temporary path
    const auto tmpPath = path + ".tmp";
    auto extractResp = m_downloader->extractMmdbFromGz(gzContent, tmpPath);
    if (base::isError(extractResp))
    {
        // Clean up temporary file if extraction failed
        if (std::filesystem::exists(tmpPath))
        {
            std::filesystem::remove(tmpPath);
        }
        return base::getError(extractResp);
    }

    // Atomic rename to final path
    try
    {
        std::filesystem::rename(tmpPath, path);

        // Set permissions to 640 (rw-r-----)
        std::filesystem::permissions(path,
                                     std::filesystem::perms::owner_read | std::filesystem::perms::owner_write
                                         | std::filesystem::perms::group_read,
                                     std::filesystem::perm_options::replace);
    }
    catch (const std::exception& e)
    {
        std::filesystem::remove(tmpPath);
        return base::Error {fmt::format("Cannot replace db '{}': {}", path, e.what())};
    }

    // Open a new instance and perform an atomic swap (hot reload)
    std::shared_ptr<const DbInstance> newInst;
    try
    {
        newInst = std::make_shared<DbInstance>(path, expectedMd5, createdAt, type);
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Cannot open updated db '{}': {}", path, e.what())};
    }

    handle->store(std::move(newInst));

    // Persist manifest MD5 hash and generated_at in store
    auto res = upsertStoreEntry(path, type, expectedMd5, createdAt);
    if (base::isError(res))
    {
        return base::getError(res);
    }

    return base::noError();
}

void Manager::remoteUpsert(const std::string& manifestUrl, const std::string& cityPath, const std::string& asnPath)
{
    LOG_DEBUG("[Geo::Manager] Checking for geo database updates from manifest '{}'", manifestUrl);

    // Download and parse manifest
    auto manifestResp = m_downloader->downloadManifest(manifestUrl);
    if (base::isError(manifestResp))
    {
        LOG_WARNING(
            "[Geo::Manager] Cannot download manifest from '{}': {}", manifestUrl, base::getError(manifestResp).message);
        return;
    }

    const auto manifest = base::getResponse(manifestResp);
    LOG_DEBUG("[Geo::Manager] Manifest downloaded successfully");

    // Extract manifest fields
    auto createdAt = manifest.getInt64(GENERATED_AT_PATH);

    // Lambda to process database entries
    auto processDatabase = [&](Type type,
                               const std::string& path,
                               const std::optional<std::string>& url,
                               const std::optional<std::string>& md5,
                               const std::string& typeName)
    {
        if (!url.has_value() || !md5.has_value() || path.empty())
        {
            LOG_WARNING("[Geo::Manager] {} database not present in manifest or path not provided", typeName);
            return;
        }

        const auto dbName = std::filesystem::path(path).filename().string();

        // Check if database needs update
        if (!needsUpdate(dbName, md5.value(), type))
        {
            LOG_DEBUG("[Geo::Manager] No changes detected for {} database '{}'", typeName, dbName);
            return;
        }

        LOG_INFO("[Geo::Manager] Changes detected for {} database '{}', updating...", typeName, dbName);
        auto error = processDbEntry(path, type, url.value(), md5.value(), createdAt.value());
        if (base::isError(error))
        {
            LOG_ERROR("[Geo::Manager] Failed to process {} database '{}': {}",
                      typeName,
                      dbName,
                      base::getError(error).message);
        }
        else
        {
            LOG_INFO("[Geo::Manager] Successfully updated {} database '{}'", typeName, dbName);
        }
    };

    // Process city database if present
    processDatabase(Type::CITY, cityPath, manifest.getString("/city/url"), manifest.getString("/city/md5"), "CITY");

    // Process ASN database if present
    processDatabase(Type::ASN, asnPath, manifest.getString("/asn/url"), manifest.getString("/asn/md5"), "ASN");

    LOG_DEBUG("[Geo::Manager] Finished synchronization of geo databases");
}

base::RespOrError<std::shared_ptr<ILocator>> Manager::getLocator(Type type) const
{
    // Search the database with read lock
    std::shared_lock lock(m_rwMapMutex);

    // Check if the type has a database
    if (m_dbTypes.find(type) == m_dbTypes.end())
    {
        return base::Error {fmt::format("Type '{}' does not have a database", typeName(type))};
    }

    // Get the database handle and return the locator
    auto handle = m_dbs.at(m_dbTypes.at(type));
    auto locator = std::make_shared<Locator>(handle);

    return locator;
}

std::vector<DbInfo> Manager::listDbs() const
{
    std::shared_lock lock(m_rwMapMutex);

    std::vector<DbInfo> dbs;
    for (const auto& [name, handle] : m_dbs)
    {
        auto inst = handle->load();
        if (!inst)
        {
            continue;
        }

        dbs.emplace_back(DbInfo {name, inst->path(), inst->hash(), inst->createdAt(), inst->type()});
    }
    return dbs;
}

} // namespace geo
