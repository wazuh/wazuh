#include <kvdb/kvdbManager.hpp>

#include <assert.h>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <unordered_map>

#include <fmt/format.h>
#include <logging/logging.hpp>
#include <utils/stringUtils.hpp>

#include <kvdb/kvdb.hpp>

// TODO Change Function Helpers tests initialization too.
KVDBManager *KVDBManager::mInstance = nullptr;
bool KVDBManager::init(const std::string &DbFolder)
{
    if (mInstance)
    {
        return false;
    }
    if (DbFolder.empty())
    {
        return false;
    }
    std::filesystem::create_directories(
        DbFolder); // TODO Remove this whe Engine is integrated in Wazuh
                   // installation
    mInstance = new KVDBManager(DbFolder);
    return true;
}

KVDBManager &KVDBManager::get()
{
    if (!mInstance)
    {
        throw std::logic_error("KVDBManager isn't initialized");
    }
    return *mInstance;
}

KVDBManager::KVDBManager(const std::string &DbFolder)
{
    mDbFolder = DbFolder;

    if (std::filesystem::exists(mDbFolder + "legacy"))
    {
        for (const auto &cdbfile :
             std::filesystem::directory_iterator(mDbFolder + "legacy"))
        {
            // Read it from the config file?
            if (cdbfile.is_regular_file())
            {
                if (createDBfromCDB(cdbfile.path(), false))
                {
                    // TODO Remove files once synced
                    // std::filesystem::remove(cdbfile.path())
                }
            }
        }
    }
}

KVDBManager::~KVDBManager()
{
    m_availableKVDBs.clear();
}

bool KVDBManager::createDB(const std::string &name, bool overwrite)
{
    rocksdb::Options createOptions;
    createOptions.IncreaseParallelism();
    createOptions.OptimizeLevelStyleCompaction();
    createOptions.create_if_missing = true;
    createOptions.error_if_exists = !overwrite;

    rocksdb::DB *db;
    rocksdb::Status s = rocksdb::DB::Open(createOptions, mDbFolder + name, &db);
    if (!s.ok())
    {
        WAZUH_LOG_ERROR("couldn't open db file, error: [{}]", s.ToString());
        return false;
    }
    s = db->Close(); // TODO: We can avoid this unnecessary close making a more
                     // complex KVDB constructor that creates DBs
                     // or if receives a CFHandler and a CFDescriptor vector.
    if (!s.ok())
    {
        WAZUH_LOG_ERROR("couldn't close db file, error: [{}]", s.ToString());
        return false;
    }

    return true;
}

bool KVDBManager::createDBfromCDB(const std::filesystem::path &path,
                                  bool overwrite)
{
    std::ifstream CDBfile(path);
    if (!CDBfile.is_open())
    {
        WAZUH_LOG_ERROR("Can't open CDB already open");
        return false;
    }

    if (!createDB(path.stem(), overwrite))
    {
        WAZUH_LOG_ERROR("Couldn't create DB [{}]", path.stem().c_str());
        return false;
    }
    auto kvdb = getDB(path.stem());
    if (!kvdb)
    {
        WAZUH_LOG_ERROR("Created DB [{}] is unavailable", path.stem().c_str());
        return false;
    }

    std::string line;
    while (getline(CDBfile, line))
    {
        line.erase(remove_if(line.begin(), line.end(), isspace), line.end());
        auto KV = utils::string::split(line, ':');
        if (!KV.empty() && !KV.at(0).empty() && !KV.at(0).empty())
        {
            WAZUH_LOG_ERROR("Error while reading CDBfile");
            return false;
        }
        kvdb->write(KV.at(0), KV.at(1));
    }

    popDB(path.stem());

    return true;
}

bool KVDBManager::deleteDB(const std::string &name)
{
    auto it = m_availableKVDBs.find(name);
    if (it == m_availableKVDBs.end())
    {
        WAZUH_LOG_ERROR("Database [{}] isn't handled by KVDB manager", name);
        return false;
    }
    it->second->markToDelete();
    m_availableKVDBs.erase(it);
    return true;
}

bool KVDBManager::popDB(const std::string &name)
{
    auto it = m_availableKVDBs.find(name);
    if (it == m_availableKVDBs.end())
    {
        WAZUH_LOG_ERROR("Database [{}] isn't handled by KVDB manager", name);
        return false;
    }
    m_availableKVDBs.erase(it);
    return true;
}

bool KVDBManager::addDB(const std::string &name, const std::string &folder)
{
    if (m_availableKVDBs.find(name) == m_availableKVDBs.end())
    {
        WAZUH_LOG_DEBUG("adding DB with name [{}] to available Databases",
                        name);
        std::shared_ptr<KVDB> kvdb = std::make_shared<KVDB>(name, folder);
        if (kvdb->isReady())
        {
            m_availableKVDBs[name] = std::move(kvdb);
            return true;
        }
        WAZUH_LOG_ERROR("DB created but not ready for use");
        return false;
    }
    return false;
}

std::shared_ptr<KVDB> KVDBManager::getDB(const std::string &name)
{
    auto it = m_availableKVDBs.find(name);
    if (it != m_availableKVDBs.end())
    {
        return it->second;
    }
    else
    {
        WAZUH_LOG_DEBUG("Database not available, creating it with name: [{}] ",
                        name);
        if (addDB(name, mDbFolder))
        {
            return getDB(name);
        }
    }

    WAZUH_LOG_ERROR("Database not available and couldn't create it");
    return nullptr;
}
