#include "manager.hpp"

#include <filesystem>
#include <fstream>
#include <mutex>

#include <fmt/format.h>
#include <maxminddb.h>

#include <base/logging.hpp>
#include <store/istore.hpp>

#include "dbEntry.hpp"
#include "locator.hpp"

namespace geo
{
Manager::Manager(const std::shared_ptr<store::IStoreInternal>& store, const std::shared_ptr<IDownloader>& downloader)
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
    auto dbsResp = m_store->readInternalCol(INTERNAL_NAME);
    if (base::isError(dbsResp))
    {
        LOG_DEBUG("Geo module do not have dbs in the store: {}", base::getError(dbsResp).message);
        return;
    }

    auto dbs = base::getResponse(dbsResp);
    for (const auto& db : dbs)
    {
        auto dbResp = m_store->readInternalDoc(db);
        if (base::isError(dbResp))
        {
            LOG_ERROR("Geo cannot read internal document '{}': {}", db, base::getError(dbResp).message);
            continue;
        }

        auto doc = base::getResponse(dbResp);
        auto path = doc.getString(PATH_PATH).value();
        auto type = typeFromName(doc.getString(TYPE_PATH).value());

        auto addResp = addDbUnsafe(path, type, false);
        if (base::isError(addResp))
        {
            LOG_ERROR("Geo cannot add db '{}': {}", path, base::getError(addResp).message);
            m_store->deleteInternalDoc(db);
            LOG_TRACE("Geo deleted internal document '{}'", db);
        }
    }
}

base::OptError Manager::upsertStoreEntry(const std::string& path)
{
    std::filesystem::path dbPath(path);

    // Open file and compute hash
    auto file = std::ifstream(path, std::ios::binary);
    if (!file.is_open())
    {
        return base::Error {fmt::format("Cannot open file '{}'", path)};
    }

    // Get content of the file to compute the hash
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    auto hash = m_downloader->computeMD5(content);
    file.close();

    // Create and upsert the internal document
    auto internalName = base::Name({INTERNAL_NAME, dbPath.filename().string()});
    auto doc = store::Doc();
    doc.setString(path, PATH_PATH);
    doc.setString(hash, HASH_PATH);
    doc.setString(typeName(m_dbs.at(dbPath.filename().string())->type), TYPE_PATH);

    return m_store->upsertInternalDoc(internalName, doc);
}

base::OptError Manager::removeInternalEntry(const std::string& path)
{
    auto internalName = base::Name(
        fmt::format("{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, std::filesystem::path(path).filename().string()));

    return m_store->deleteInternalDoc(internalName);
}

base::OptError Manager::addDbUnsafe(const std::string& path, Type type, bool upsertStore)
{
    auto name = std::filesystem::path(path).filename().string();

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

    // Add the database
    auto entry = std::make_shared<DbEntry>(path, type);
    int status = MMDB_open(path.c_str(), MMDB_MODE_MMAP, entry->mmdb.get());
    if (MMDB_SUCCESS != status)
    {
        return base::Error {fmt::format("Cannot add database '{}': {}", path, MMDB_strerror(status))};
    }

    m_dbs.emplace(name, std::move(entry));
    m_dbTypes.emplace(type, name);

    if (upsertStore)
    {
        auto internalResp = upsertStoreEntry(path);
        if (base::isError(internalResp))
        {
            LOG_WARNING("Cannot update internal store for '{}': {}", path, base::getError(internalResp).message);
        }
    }

    return base::noError();
}

base::OptError Manager::removeDbUnsafe(const std::string& path)
{
    auto name = std::filesystem::path(path).filename().string();

    // Check if the database is already added
    if (m_dbs.find(name) == m_dbs.end())
    {
        return base::Error {fmt::format("Database '{}' not found", name)};
    }

    {
        // We need to hold the entry so the lock is not released after the entry is removed
        auto entry = m_dbs.at(name);

        // Lock the database entry internal mutex for write
        std::unique_lock<std::shared_mutex> lockEntry(entry->rwMutex);

        // Remove the database
        m_dbs.erase(name);

        // Unlock the entry mutex
        lockEntry.unlock();

        // Freed the entry
        entry.reset();
    }

    // Remove the type from the map if it was the one in use
    for (auto it = m_dbTypes.begin(); it != m_dbTypes.end(); ++it)
    {
        if (it->second == name)
        {
            m_dbTypes.erase(it);
            break;
        }
    }

    return removeInternalEntry(path);
}

base::OptError Manager::writeDb(const std::string& path, const std::string& content)
{
    auto filePath = std::filesystem::path(path);

    // Create directories if they do not exist
    try
    {
        std::filesystem::create_directories(filePath.parent_path());
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

base::OptError Manager::addDb(const std::string& path, Type type)
{
    // Hold write lock on the map
    std::unique_lock lock(m_rwMapMutex);

    auto resp = addDbUnsafe(path, type, true);
    return resp;
}

base::OptError Manager::removeDb(const std::string& path)
{
    // Hold write lock on the map
    std::unique_lock lock(m_rwMapMutex);

    auto resp = removeDbUnsafe(path);
    return resp;
}

base::OptError
Manager::remoteUpsertDb(const std::string& path, Type type, const std::string& dbUrl, const std::string& hashUrl)
{
    auto name = std::filesystem::path(path).filename().string();

    // Hold write lock on the map
    std::unique_lock lock(m_rwMapMutex);

    // If the type has a different database, fail
    if (m_dbTypes.find(type) != m_dbTypes.end() && m_dbTypes.at(type) != name)
    {
        return base::Error {fmt::format("Type '{}' already has the database '{}'", typeName(type), m_dbTypes.at(type))};
    }

    // Download the database hash
    auto hashResp = m_downloader->downloadMD5(hashUrl);
    if (base::isError(hashResp))
    {
        return base::Error {
            fmt::format("Cannot download hash from '{}': {}", hashUrl, base::getError(hashResp).message)};
    }
    auto hash = base::getResponse(hashResp);

    // Check if it is already updated
    auto entry = m_dbs.find(name);
    if (entry != m_dbs.end())
    {
        auto internalResp =
            m_store->readInternalDoc(base::Name(fmt::format("{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, name)));
        if (!base::isError(internalResp))
        {
            auto storedHash = base::getResponse(internalResp).getString(HASH_PATH).value();
            if (storedHash == hash)
            {
                return base::noError();
            }
        }
    }

    // Download the database while MAX_RETRIES if failed
    std::string content;
    base::OptError error;
    for (int i = 0; i < MAX_RETRIES; ++i)
    {
        auto dbResp = m_downloader->downloadHTTPS(dbUrl);
        if (base::isError(dbResp))
        {
            error = base::Error {
                fmt::format("Cannot download database from '{}': {}", dbUrl, base::getError(dbResp).message)};
            continue;
        }

        content = base::getResponse(dbResp);
        auto computedHash = m_downloader->computeMD5(content);
        if (computedHash == hash)
        {
            error = base::noError();
            break;
        }

        error = base::Error {fmt::format("Hash mismatch for database '{}'", dbUrl)};
    }

    if (base::isError(error))
    {
        return error;
    }

    // Write the database to the file
    // If the database is already added, hold the internal mutex for write
    if (entry != m_dbs.end())
    {
        std::unique_lock lockEntry(entry->second->rwMutex);
        auto writeResp = writeDb(path, content);
        if (base::isError(writeResp))
        {
            return base::getError(writeResp);
        }

        // Close the MMDB and reopen it
        MMDB_close(entry->second->mmdb.get());
        int status = MMDB_open(path.c_str(), MMDB_MODE_MMAP, entry->second->mmdb.get());
        if (MMDB_SUCCESS != status)
        {
            // Remove the database
            lockEntry.unlock();
            removeDbUnsafe(path);

            return base::Error {fmt::format("Cannot add database '{}': {}", path, MMDB_strerror(status))};
        }
    }
    else
    {
        auto writeResp = writeDb(path, content);
        if (base::isError(writeResp))
        {
            return base::getError(writeResp);
        }

        auto addResp = addDbUnsafe(path, type, false);
        if (base::isError(addResp))
        {
            return base::getError(addResp);
        }
    }

    // Update the internal store
    auto internalResp = upsertStoreEntry(path);
    if (base::isError(internalResp))
    {
        LOG_WARNING("Cannot update internal store for '{}': {}", path, base::getError(internalResp).message);
    }

    return base::noError();
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

    // Get the database entry and return the locator
    auto entry = m_dbs.at(m_dbTypes.at(type));
    auto locator = std::make_shared<Locator>(entry);

    return locator;
}

std::vector<DbInfo> Manager::listDbs() const
{
    std::shared_lock lock(m_rwMapMutex);
    std::vector<DbInfo> dbs;
    for (const auto& [name, entry] : m_dbs)
    {
        dbs.emplace_back(DbInfo {name, entry->path, entry->type});
    }
    return dbs;
}

} // namespace geo
