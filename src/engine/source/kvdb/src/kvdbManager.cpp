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
#include <utils/stringUtils.hpp>

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
        DbFolder); // TODO Remove this when Engine is integrated in Wazuh
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

std::shared_ptr<KVDB> KVDBManager::createDB(const std::string &name,
                                            bool overwrite)
{
    std::unique_lock lk(mMtx);
    // TODO revise logic if overwrite is true
    if (!overwrite && m_availableKVDBs.find(name) != m_availableKVDBs.end())
    {
        WAZUH_LOG_ERROR("DB with name [{}] already exists.", name);
        return nullptr;
    }

    WAZUH_LOG_DEBUG("adding DB with name [{}] to available Databases", name);
    auto kvdb = std::make_shared<KVDB>(name, mDbFolder, overwrite);
    kvdb->init();
    m_availableKVDBs[name] = kvdb;
    return kvdb;
}

bool KVDBManager::createDBfromCDB(const std::filesystem::path &path,
                                  bool overwrite)
{
    std::ifstream CDBfile(path);
    if (!CDBfile.is_open())
    {
        WAZUH_LOG_ERROR("Can't open CDB file [{}]", path.c_str());
        return false;
    }

    if (!createDB(path.stem(), overwrite))
    {
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
        line.erase(std::remove_if(line.begin(), line.end(), isspace),
                   line.end());
        auto KV = utils::string::split(line, ':');
        if (!KV.empty() && !KV.at(0).empty() && !KV.at(0).empty())
        {
            WAZUH_LOG_ERROR("Error while reading CDBfile [{}]", path.c_str());
            return false;
        }
        kvdb->write(KV.at(0), KV.at(1));
    }

    popDB(path.stem());

    return true;
}

bool KVDBManager::deleteDB(const std::string &name)
{
    std::unique_lock lk(mMtx);
    auto it = m_availableKVDBs.find(name);
    if (it == m_availableKVDBs.end())
    {
        WAZUH_LOG_ERROR("Database [{}] isn't handled by KVDB manager", name);
        return false;
    }
    m_availableKVDBs.erase(it);
    return true;
}

bool KVDBManager::popDB(const std::string &name)
{
    std::unique_lock lk(mMtx);
    auto it = m_availableKVDBs.find(name);
    if (it == m_availableKVDBs.end())
    {
        WAZUH_LOG_ERROR("Database [{}] isn't handled by KVDB manager", name);
        return false;
    }
    m_availableKVDBs.erase(it);
    return true;
}

std::shared_ptr<KVDB> KVDBManager::getDB(const std::string &name)
{
    std::shared_lock lk(mMtx);
    auto it = m_availableKVDBs.find(name);
    if (it != m_availableKVDBs.end())
    {
        auto &db = it->second;
        if (!db->isReady())
        {
            if (!db->init())
            {
                WAZUH_LOG_ERROR("Error initializing db [{}].", db->getName());
                return nullptr;
            }
        }

        return it->second;
    }

    return nullptr;
}
