#include "manager.hpp"

#include <filesystem>
#include <fstream>
#include <mutex>

#include <fmt/format.h>
#include <maxminddb.h>

#include <base/logging.hpp>
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

        auto addResp = addDbUnsafe(path, type, false);
        if (base::isError(addResp))
        {
            LOG_ERROR("Geo cannot add db '{}': {}", path, base::getError(addResp).message);
            m_store->deleteDoc(db);
            LOG_TRACE("Geo deleted internal document '{}'", db);
        }
    }
}

base::OptError Manager::upsertStoreEntry(const std::string& path, Type type)
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
    auto internalName = base::Name(std::vector<std::string>({INTERNAL_NAME, dbPath.filename().string()}));
    auto doc = store::Doc();
    doc.setString(path, PATH_PATH);
    doc.setString(hash, HASH_PATH);
    doc.setString(typeName(type), TYPE_PATH);

    return m_store->upsertDoc(internalName, doc);
}

base::OptError Manager::removeInternalEntry(const std::string& path)
{
    auto internalName = base::Name(
        fmt::format("{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, std::filesystem::path(path).filename().string()));

    return m_store->deleteDoc(internalName);
}

base::OptError Manager::addDbUnsafe(const std::string& path, Type type, bool upsertStore)
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
        auto inst = std::make_shared<DbInstance>(path, type);
        handle->store(std::move(inst));
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Cannot add database '{}': {}", path, e.what())};
    }

    // Publish
    m_dbs.emplace(name, handle);
    m_dbTypes.emplace(type, name);

    if (upsertStore)
    {
        // IMPORTANT: no local hashing; store the REMOTE hash
        auto internalResp = upsertStoreEntry(path, type);
        if (base::isError(internalResp))
        {
            LOG_WARNING("Cannot update internal store for '{}': {}", path, base::getError(internalResp).message);
        }
    }

    return base::noError();
}

base::OptError Manager::removeDbUnsafe(const std::string& path)
{
    const auto name = std::filesystem::path(path).filename().string();

    if (m_dbs.find(name) == m_dbs.end())
    {
        return base::Error {fmt::format("Database '{}' not found", name)};
    }

    m_dbs.erase(name);

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

base::OptError Manager::remoteUpsertDb(const std::string& path,
                                      Type type,
                                      const std::string& dbUrl,
                                      const std::string& hashUrl)
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

    // Download remote hash (MD5) - unchanged
    auto hashResp = m_downloader->downloadMD5(hashUrl);
    if (base::isError(hashResp))
    {
        return base::Error {fmt::format("Cannot download hash from '{}': {}",
                                        hashUrl,
                                        base::getError(hashResp).message)};
    }
    const auto remoteHash = base::getResponse(hashResp);

    // early-exit si store dice que ya está actualizado (misma lógica que antes)
    {
        auto internalResp =
            m_store->readDoc(base::Name(fmt::format("{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, name)));
        if (!base::isError(internalResp))
        {
            const auto storedHash = base::getResponse(internalResp).getString(HASH_PATH).value_or("");
            if (!storedHash.empty() && storedHash == remoteHash)
            {
                return base::noError();
            }
        }
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

    // Download DB with retries and validate with local hash
    std::string content;
    base::OptError error = base::Error {fmt::format("Cannot download database from '{}'", dbUrl)};

    for (int i = 0; i < MAX_RETRIES; ++i)
    {
        auto dbResp = m_downloader->downloadHTTPS(dbUrl);
        if (base::isError(dbResp))
        {
            error = base::Error {fmt::format("Cannot download database from '{}': {}",
                                             dbUrl,
                                             base::getError(dbResp).message)};
            continue;
        }

        content = base::getResponse(dbResp);

        const auto computedHash = m_downloader->computeMD5(content);
        if (computedHash == remoteHash)
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

    // Atomic write to disk
    const auto tmpPath = path + ".tmp";
    auto writeResp = writeDb(tmpPath, content);
    if (base::isError(writeResp))
    {
        return base::getError(writeResp);
    }

    try
    {
        std::filesystem::rename(tmpPath, path);
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Cannot replace db '{}': {}", path, e.what())};
    }

    // Open a new instance and perform an atomic swap (real hot reload)
    std::shared_ptr<const DbInstance> newInst;
    try
    {
        newInst = std::make_shared<DbInstance>(path, type);
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Cannot open updated db '{}': {}", path, e.what())};
    }

    handle->store(std::move(newInst));

    // Persist remote hash in store
    auto internalUpsert = upsertStoreEntry(path, type);
    if (base::isError(internalUpsert))
    {
        LOG_WARNING("Cannot update internal store for '{}': {}", path, base::getError(internalUpsert).message);
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

        dbs.emplace_back(DbInfo {name, inst->path(), inst->type()});
    }
    return dbs;
}

} // namespace geo
