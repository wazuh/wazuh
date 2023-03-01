#include <kvdb/kvdbManager.hpp>

#include <algorithm>
#include <exception>
#include <filesystem>
#include <fstream>
#include <set>
#include <unordered_map>

#include <fmt/format.h>

#include <kvdb/kvdb.hpp>
#include <logging/logging.hpp>
#include <utils/baseMacros.hpp>
#include <utils/stringUtils.hpp>

namespace kvdb_manager
{

namespace
{

constexpr bool ERROR_IF_EXISTS {true};
constexpr bool NO_ERROR_IF_EXISTS {false};
constexpr bool CREATE_IF_MISSING {true};
constexpr bool DONT_CREATE_IF_MISSING {false};

} // namespace

KVDBManager::KVDBManager(const std::filesystem::path& dbStoragePath)
{
    // TODO should we read and load all the dbs inside the folder?
    // shouldn't be better to just load the configured ones at start instead?

    // TODO Remove this when Engine is integrated in Wazuh installation
    std::filesystem::create_directories(dbStoragePath);
    m_dbStoragePath = dbStoragePath;
}

KVDBHandle KVDBManager::loadDB(const std::string& name, bool createIfMissing)
{
    std::unique_lock lkW(m_mtx);
    const bool isLoaded = m_dbs.find(name) != m_dbs.end();

    if (isLoaded)
    {
        WAZUH_LOG_DEBUG("Engine KVDB manager: '{}' method: Database with name '{}' "
                        "already loaded.",
                        __func__,
                        name);
        return nullptr;
    }

    WAZUH_LOG_DEBUG("Engine KVDB manager: '{}' method: Loading database '{}' to the "
                    "available databases list.",
                    __func__,
                    name);
    auto kvdb = std::make_shared<KVDB>(name, m_dbStoragePath);
    auto result = kvdb->init(createIfMissing);
    if (KVDB::CreationStatus::OkInitialized == result
        || KVDB::CreationStatus::OkCreated == result)
    {
        m_dbs[name] = kvdb;
        return kvdb;
    }

    return nullptr;
}

void KVDBManager::unloadDB(const std::string& name)
{
    std::unique_lock lkW(m_mtx);
    const bool isLoaded = m_dbs.find(name) != m_dbs.end();

    if (isLoaded)
    {
        m_dbs.erase(name);
    }
}

KVDBHandle KVDBManager::getDB(const std::string& name)
{
    std::shared_lock lkReadDBs(m_mtx);

    const bool isLoaded = m_dbs.find(name) != m_dbs.end();

    if (isLoaded)
    {
        auto db = m_dbs[name];
        if (!db->isReady())
        {
            // In general it should never happen so we should consider just
            // removing this
            auto initResult = db->init(DONT_CREATE_IF_MISSING);
            if (initResult != KVDB::CreationStatus::OkCreated
                || initResult != KVDB::CreationStatus::OkInitialized)
            {
                WAZUH_LOG_ERROR("Engine KVDB manager: '{}' method: Error initializing "
                                "database '{}'.",
                                __func__,
                                db->getName());
                return nullptr;
            }
        }

        // return handle
        return db;
    }

    return nullptr;
}

std::vector<std::string> KVDBManager::listDBs(bool loaded)
{
    std::vector<std::string> list {};

    if (loaded)
    {
        std::shared_lock lkReadDBs(m_mtx);
        // Copy the keys to the list
        std::transform(m_dbs.begin(),
                       m_dbs.end(),
                       std::back_inserter(list),
                       [](const auto& kv) { return kv.first; });
    }
    else
    {
        // Check the folders in the storage path
        // Assuming that the folder name is the database name
        auto dir = std::filesystem::directory_iterator(m_dbStoragePath);
        for (const auto& entry : dir)
        {
            if (entry.is_directory())
            {
                list.push_back(entry.path().filename().string());
            }
        }
    }

    return list;
}

std::variant<KVDBHandle, base::Error> KVDBManager::getHandler(const std::string& name,
                                                              bool createIfMissing)
{
    auto kvdb = getDB(name);
    if (!kvdb)
    {
        loadDB(name, createIfMissing);
        kvdb = getDB(name);
        if (!kvdb)
        {
            return base::Error {fmt::format("Database '{}' not found or could not be loaded", name)};
        }
    }
    return kvdb;
}

std::optional<base::Error> KVDBManager::createFromJFile(const std::string& dbName,
                                                        const std::filesystem::path& path)
{
    std::vector<std::tuple<std::string, json::Json>> entries {};

    // Open file and read content
    if (!path.empty())
    {
        // Open file and read content
        std::string contents;
        // TODO: No check the size, the location, the type of file, the permissions it's a
        // security issue. The API should be changed to receive a stream instead of a path
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (in)
        {
            in.seekg(0, std::ios::end);
            contents.resize(in.tellg());
            in.seekg(0, std::ios::beg);
            in.read(&contents[0], contents.size());
            in.close();
        }
        else
        {
            return base::Error {fmt::format(
                "An error occurred while opening the file '{}'", path.c_str())};
        }

        json::Json jKv;
        try
        {
            jKv = json::Json {contents.c_str()};
        }
        catch (const std::exception& e)
        {
            return base::Error {fmt::format(
                "An error occurred while parsing the JSON file '{}'", path.c_str())};
        }

        if (!jKv.isObject())
        {
            return base::Error {
                fmt::format("An error occurred while parsing the JSON file '{}': "
                            "JSON is not an object",
                            path.c_str())};
        }

        entries = jKv.getObject().value();
    }

    // Check if the database exists
    if (exist(dbName))
    {
        return base::Error {fmt::format("Database '{}' already exists", dbName)};
    }

    // Create the database
    auto kvdb = getHandler(dbName, true);
    if (std::holds_alternative<base::Error>(kvdb))
    {
        return std::get<base::Error>(kvdb);
    }

    for (const auto& [key, value] : entries)
    {
        writeKey(dbName, key, value); // TODO check error
    }

    return std::nullopt;
}

std::variant<json::Json, base::Error> KVDBManager::jDumpDB(const std::string& name)
{
    auto handle = getHandler(name);
    if (std::holds_alternative<base::Error>(handle))
    {
        return std::get<base::Error>(handle);
    }
    auto& kvdb = std::get<KVDBHandle>(handle);

    return kvdb->jDump();
}

std::optional<base::Error> KVDBManager::writeRaw(const std::string& name,
                                                 const std::string& key,
                                                 const std::string& value)
{
    auto handle = getHandler(name);
    if (std::holds_alternative<base::Error>(handle))
    {
        return std::get<base::Error>(handle);
    }
    auto& kvdb = std::get<KVDBHandle>(handle);

    if (kvdb->write(key, value))
    {
        return std::nullopt;
    }
    return base::Error {
        fmt::format("Could not write key '{}' to database '{}'", key, name)};
}

std::optional<base::Error> KVDBManager::writeKey(const std::string& name,
                                                 const std::string& key,
                                                 const std::string& value)
{
    json::Json jValue;
    try
    {
        jValue = json::Json {value.c_str()};
    }
    catch (const std::exception& e)
    {
        jValue.setString(value);
    }

    return writeKey(name, key, jValue);
}

std::variant<std::string, base::Error> KVDBManager::getRawValue(const std::string& name,
                                                                const std::string& key)
{
    auto handle = getHandler(name);
    if (std::holds_alternative<base::Error>(handle))
    {
        return std::get<base::Error>(handle);
    }
    auto& kvdb = std::get<KVDBHandle>(handle);

    return kvdb->read(key);
}

std::variant<json::Json, base::Error> KVDBManager::getJValue(const std::string& name,
                                                             const std::string& key)
{
    const auto result = getRawValue(name, key);
    if (std::holds_alternative<base::Error>(result))
    {
        return std::get<base::Error>(result);
    }
    const auto& value = std::get<std::string>(result);
    json::Json jValue;
    try
    {
        jValue = json::Json {value.c_str()};
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format(
            "Could not parse value '{}' from database '{}' (corrupted value: '{}')",
            key,
            value.c_str(),
            name)};
    }

    return jValue;
}

std::optional<base::Error> KVDBManager::deleteKey(const std::string& name,
                                                  const std::string& key)
{
    bool result {false};
    auto handle = getHandler(name);
    if (std::holds_alternative<base::Error>(handle))
    {
        return std::get<base::Error>(handle);
    }
    auto& kvdb = std::get<KVDBHandle>(handle);

    return kvdb->deleteKey(key);
}

bool KVDBManager::exist(const std::string& name)
{
    std::shared_lock lkReadDBs(m_mtx);

    bool isLoaded = (m_dbs.find(name) != m_dbs.end());
    if (isLoaded)
    {
        return true;
    }

    auto dbHandle = std::make_shared<KVDB>(name, m_dbStoragePath);
    auto result = dbHandle->init(DONT_CREATE_IF_MISSING, NO_ERROR_IF_EXISTS);
    return (result != KVDB::CreationStatus::ErrorUnknown);
}

std::optional<base::Error> KVDBManager::deleteDB(const std::string& name)
{
    const auto MAX_USE_COUNT = 2; // 1 for the map and 1 for getHandler

    auto res = getHandler(name);
    if (std::holds_alternative<base::Error>(res))
    {
        return std::get<base::Error>(res);
    }

    // Check if the database is loaded
    auto& handler = std::get<KVDBHandle>(res);
    if (handler.use_count() > MAX_USE_COUNT)
    {
        return base::Error {fmt::format("Database '{}' is already in use '{}' times",
                                        name,
                                        handler.use_count() - MAX_USE_COUNT)};
    }

    // Delete the reference of the database list
    {
        std::unique_lock lkW(m_mtx);
        // Check again because it could have changed while waiting for the lock
        // Its more efficient to check again than to lock the mutex before checking the
        // first time
        if (handler.use_count() == MAX_USE_COUNT)
        {
            m_dbs.erase(name);
        }
        else
        {

            return base::Error {fmt::format("Database '{}' is already in use '{}' times",
                                            name,
                                            handler.use_count() - MAX_USE_COUNT)};
        }
    }
    // Mark for deletion
    handler->cleanupOnClose();

    return std::nullopt;
}

} // namespace kvdb_manager
