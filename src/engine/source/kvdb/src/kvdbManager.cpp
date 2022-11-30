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

KVDBManager::KVDBManager(const std::filesystem::path& DbFolder)
{
    // TODO should we read and load all the dbs inside the folder?
    // shouldn't be better to just load the configured ones at start instead?

    // TODO Remove this when Engine is integrated in Wazuh installation
    std::filesystem::create_directories(DbFolder);
    mDbFolder = DbFolder;

    auto legacyPath = mDbFolder;
    legacyPath.append("legacy");
    if (std::filesystem::exists(legacyPath))
    {
        for (const auto& cdbfile : std::filesystem::directory_iterator(legacyPath))
        {
            // Read it from the config file?
            if (cdbfile.is_regular_file())
            {
                if (createKVDBfromCDBFile(cdbfile.path(), true))
                {
                    // TODO Remove files once synced
                    // std::filesystem::remove(cdbfile.path())
                }
            }
        }
    }
}

KVDBHandle KVDBManager::addDb(const std::string& name, bool createIfMissing)
{
    std::unique_lock lk(mMtx);
    if (m_availableKVDBs.find(name) != m_availableKVDBs.end())
    {
        WAZUH_LOG_ERROR("Engine KVDB manager: \"{}\" method: Database with name \"{}\" "
                        "already exists.",
                        __func__,
                        name);
        return nullptr;
    }

    WAZUH_LOG_DEBUG("Engine KVDB manager: \"{}\" method: Adding database \"{}\" to the "
                    "available databases list.",
                    __func__,
                    name);
    auto kvdb = std::make_shared<KVDB>(name, mDbFolder);
    if (kvdb->init(createIfMissing) <= KVDB::CreationStatus::OkInitialized)
    {
        m_availableKVDBs[name] = kvdb;
        return kvdb;
    }

    return nullptr;
}

// TODO: tests for this method are missing
bool KVDBManager::createKVDBfromCDBFile(const std::filesystem::path& path,
                                        bool createIfMissing)
{
    std::ifstream CDBfile(path);
    if (!CDBfile.is_open())
    {
        WAZUH_LOG_ERROR(
            "Engine KVDB manager: \"{}\" method: CDB file \"{}\" could not be opened.",
            __func__,
            path.string());
        return false;
    }

    const std::string name {path.stem().string()};
    KVDBHandle kvdbHandle {addDb(name, createIfMissing)};
    if (!kvdbHandle)
    {
        WAZUH_LOG_ERROR("Engine KVDB manager: \"{}\" method: Failed to create database "
                        "\"{}\" from CDB file \"{}\".",
                        __func__,
                        name,
                        path.string());
        return false;
    }

    for (std::string line; getline(CDBfile, line);)
    {
        line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());
        auto kv = utils::string::split(line, ':');
        if (kv.empty() || kv.size() > 2)
        {
            WAZUH_LOG_ERROR(
                "Engine KVDB manager: \"{}\" method: CDB file \"{}\" could not be read.",
                __func__,
                path.string());
            return false;
        }

        kvdbHandle->write(kv[0], kv.size() == 2 ? kv[1] : "");
    }

    return true;
}

bool KVDBManager::deleteDB(const std::string& name, bool onlyLoaded)
{
    if (onlyLoaded)
    {
        std::unique_lock lk(mMtx);
        auto it = m_availableKVDBs.find(name);
        if (it == m_availableKVDBs.end())
        {
            WAZUH_LOG_ERROR("Engine KVDB manager: \"{}\" method: Database \"{}\" is not "
                            "present on the KVDB manager databases list.",
                            __func__,
                            name);
            return false;
        }

        it->second->cleanupOnClose();
        m_availableKVDBs.erase(it);
    }
    else
    {
        KVDBHandle dbHandle;
        if (!getKVDBFromFile(name, dbHandle))
        {
            WAZUH_LOG_ERROR("Engine KVDB manager: \"{}\" method: Database \"{}\" is not "
                            "present on the KVDB manager databases list.",
                            __func__,
                            name);
            return false;
        }

        dbHandle->cleanupOnClose();
    }

    return true;
}

KVDBHandle KVDBManager::getDB(const std::string& name)
{
    std::shared_lock lk(mMtx);
    auto it = m_availableKVDBs.find(name);
    if (it != m_availableKVDBs.end())
    {
        auto& db = it->second;
        if (!db->isReady())
        {
            // In general it should never happen so we should consider just
            // removing this
            if (db->init(false) > KVDB::CreationStatus::OkInitialized)
            {
                WAZUH_LOG_ERROR("Engine KVDB manager: \"{}\" method: Error initializing "
                                "database \"{}\".",
                                __func__,
                                db->getName());
                return nullptr;
            }
        }

        // return handle
        return it->second;
    }

    return nullptr;
}

std::vector<std::string> KVDBManager::getAvailableKVDBs(bool loaded)
{
    std::vector<std::string> list;

    if (loaded)
    {
        if (m_availableKVDBs.size() > 0)
        {
            for (const auto& var : m_availableKVDBs)
            {
                list.emplace_back(var.first);
            }
        }
    }

    else
    {
        for (const auto& file : std::filesystem::directory_iterator(mDbFolder))
        {
            std::string name {file.path().stem().string()};
            if (name != "legacy")
            {
                KVDBHandle dbHandle;
                if (getKVDBFromFile(name, dbHandle))
                {
                    list.emplace_back(name);
                }
            }
        }
    }

    return list;
}

std::string KVDBManager::CreateAndFillKVDBfromFile(const std::string& dbName,
                                                   const std::filesystem::path& path)
{
    auto dbHandle = std::make_shared<KVDB>(dbName, mDbFolder);

    // Initialize it only if it doesn't exist
    auto initResult = dbHandle->init(true, true);

    if (initResult == KVDB::CreationStatus::ErrorDatabaseAlreadyExists)
    {
        return {"A database with the same name already exists"};
    }
    else if (initResult == KVDB::CreationStatus::ErrorDatabaseBusy)
    {
        return {"Database is in use"};
    }
    else if (initResult != KVDB::CreationStatus::OkCreated)
    {
        return {"Database could not be created"};
    }

    if (!path.empty())
    {
        std::ifstream filePath(path);
        if (!filePath.is_open())
        {
            return fmt::format("File \"{}\" could not be opened", path.c_str());
        }

        for (std::string line; getline(filePath, line);)
        {
            line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());
            auto kv = utils::string::split(line, ':');
            if (kv.empty() || kv.size() > 2)
            {
                return fmt::format(
                    "An error occurred while trying to read the file \"{}\"",
                    path.c_str());
            }

            dbHandle->write(kv[0], kv.size() == 2 ? kv[1] : "");
        }
    }

    return "OK";
}

bool KVDBManager::getKVDBFromFile(const std::string& name, KVDBHandle& dbHandle)
{
    dbHandle = std::make_shared<KVDB>(name, mDbFolder);
    // Initialize it only if it already exists
    return dbHandle->init(false, false) <= KVDB::CreationStatus::OkInitialized;
}

size_t KVDBManager::dumpContent(const std::string& name, std::string& content)
{
    size_t result {0};
    KVDBHandle dbHandle;

    if (getKVDBFromFile(name, dbHandle))
    {
        result = dbHandle->dumpContent(content);
    }

    return result;
}

bool KVDBManager::writeKey(const std::string& name,
                           const std::string& key,
                           const std::string value)
{
    bool result {false};
    KVDBHandle dbHandle;

    if (getKVDBFromFile(name, dbHandle))
    {
        result = dbHandle->write(key, value);
    }

    return result;
}

std::optional<std::string> KVDBManager::getKeyValue(const std::string& name,
                                                    const std::string& key)
{
    std::optional<std::string> result = std::nullopt;
    KVDBHandle dbHandle;

    if (getKVDBFromFile(name, dbHandle))
    {
        if (dbHandle->hasKey(key))
        {
            result = dbHandle->read(key);
        }
    }

    return result;
}

bool KVDBManager::deleteKey(const std::string& name, const std::string& key)
{
    bool result = false;
    KVDBHandle dbHandle;

    if (getKVDBFromFile(name, dbHandle))
    {
        if (dbHandle->read(key).has_value())
        {
            result = dbHandle->deleteKey(key);
        }
    }

    return result;
}
