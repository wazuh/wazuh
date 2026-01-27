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

    // Load dbs from the internal store
    auto dbsResp = m_store->readCol(INTERNAL_NAME);
    if (base::isError(dbsResp))
    {
        LOG_DEBUG("Geo module do not have dbs in the store: {}", base::getError(dbsResp).message);
        return;
    }

    auto dbs = base::getResponse(dbsResp);
    for (const auto& db : dbs)
    {
        auto dbResp = m_store->readDoc(db);
        if (base::isError(dbResp))
        {
            LOG_ERROR("Geo cannot read internal document '{}': {}", db, base::getError(dbResp).message);
            continue;
        }

        auto doc = base::getResponse(dbResp);
        auto path = doc.getString(PATH_PATH).value();
        auto type = typeFromName(doc.getString(TYPE_PATH).value());
        auto hash = doc.getString(HASH_PATH).value();
        auto createdAt = doc.getInt64(GENERATED_AT_PATH).value();

        auto addResp = addDbUnsafe(path, hash, createdAt, type);
        if (base::isError(addResp))
        {
            LOG_ERROR("Geo cannot add db '{}': {}", path, base::getError(addResp).message);
            m_store->deleteDoc(db);
            LOG_TRACE("Geo deleted internal document '{}'", db);
        }
    }
}

base::OptError
Manager::upsertStoreEntry(const std::string& path, Type type, const std::string& hash, const int64_t createdAt)
{
    // Create and upsert the internal document
    std::filesystem::path dbPath(path);
    auto internalName = base::Name(std::vector<std::string>({INTERNAL_NAME, dbPath.filename().string()}));
    auto doc = store::Doc();
    doc.setString(path, PATH_PATH);
    doc.setString(hash, HASH_PATH);
    doc.setString(typeName(type), TYPE_PATH);
    doc.setInt64(createdAt, GENERATED_AT_PATH);

    auto storeResp = m_store->upsertDoc(internalName, doc);
    if (base::isError(storeResp))
    {
        base::Error {fmt::format("Cannot update internal store for '{}': {}", path, base::getError(storeResp).message)};
    }

    return base::noError();
}

bool Manager::needsUpdate(const std::string& name, const std::string& remoteHash) const
{
    auto internalResp =
        m_store->readDoc(base::Name(fmt::format("{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, name)));

    if (base::isError(internalResp))
    {
        // If there's no stored hash, we need to update
        return true;
    }

    auto storedHash = base::getResponse(internalResp).getString(HASH_PATH);
    if (!storedHash.has_value())
    {
        return true;
    }

    // Check if file exists physically
    auto storedPath = base::getResponse(internalResp).getString(PATH_PATH);
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
    if (!needsUpdate(name, expectedMd5))
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
        if (std::filesystem::exists(path))
        {
            std::filesystem::remove(path);
        }
        std::filesystem::rename(tmpPath, path);

        // Set permissions to 640 (rw-r-----)
        std::filesystem::permissions(path,
                                    std::filesystem::perms::owner_read | std::filesystem::perms::owner_write |
                                    std::filesystem::perms::group_read,
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
        LOG_ERROR(
            "[Geo::Manager] Cannot download manifest from '{}': {}", manifestUrl, base::getError(manifestResp).message);
        return;
    }

    const auto manifest = base::getResponse(manifestResp);
    LOG_DEBUG("[Geo::Manager] Manifest downloaded successfully");

    // Extract manifest fields
    auto createdAt = manifest.getInt64(GENERATED_AT_PATH);

    // Process city database if present
    auto cityUrl = manifest.getString("/city/url");
    auto cityMd5 = manifest.getString("/city/md5");
    if (cityUrl.has_value() && cityMd5.has_value() && !cityPath.empty())
    {
        const auto cityName = std::filesystem::path(cityPath).filename().string();

        // Check if database needs update
        if (!needsUpdate(cityName, cityMd5.value()))
        {
            LOG_DEBUG("[Geo::Manager] No changes detected for CITY database '{}'", cityName);
        }
        else
        {
            LOG_INFO("[Geo::Manager] Changes detected for CITY database '{}', updating...", cityName);
            auto cityError = processDbEntry(cityPath, Type::CITY, cityUrl.value(), cityMd5.value(), createdAt.value());
            if (base::isError(cityError))
            {
                LOG_ERROR("[Geo::Manager] Failed to process CITY database '{}': {}",
                          cityName,
                          base::getError(cityError).message);
                // Continue with ASN even if city fails
            }
            else
            {
                LOG_INFO("[Geo::Manager] Successfully updated CITY database '{}'", cityName);
            }
        }
    }
    else
    {
        LOG_DEBUG("[Geo::Manager] CITY database not present in manifest or path not provided");
    }

    // Process ASN database if present
    auto asnUrl = manifest.getString("/asn/url");
    auto asnMd5 = manifest.getString("/asn/md5");
    if (asnUrl.has_value() && asnMd5.has_value() && !asnPath.empty())
    {
        const auto asnName = std::filesystem::path(asnPath).filename().string();

        // Check if database needs update
        if (!needsUpdate(asnName, asnMd5.value()))
        {
            LOG_DEBUG("[Geo::Manager] No changes detected for ASN database '{}'", asnName);
        }
        else
        {
            LOG_INFO("[Geo::Manager] Changes detected for ASN database '{}', updating...", asnName);
            auto asnError = processDbEntry(asnPath, Type::ASN, asnUrl.value(), asnMd5.value(), createdAt.value());
            if (base::isError(asnError))
            {
                LOG_ERROR("[Geo::Manager] Failed to process ASN database '{}': {}",
                          asnName,
                          base::getError(asnError).message);
                // Continue even if ASN fails
            }
            else
            {
                LOG_INFO("[Geo::Manager] Successfully updated ASN database '{}'", asnName);
            }
        }
    }
    else
    {
        LOG_DEBUG("[Geo::Manager] ASN database not present in manifest or path not provided");
    }

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
