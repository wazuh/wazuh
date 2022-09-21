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

bool KVDBManager::mInitialized;
std::filesystem::path KVDBManager::mDbFolder;
bool KVDBManager::init(const std::filesystem::path& path)
{
    WAZUH_ASSERT_MSG(!mInitialized,
                     "The manager should be initialized only once.");
    mInitialized = true;

    // TODO Remove this when Engine is integrated in Wazuh installation
    std::filesystem::create_directories(path);
    mDbFolder = path;

    return true;
}

KVDBManager& KVDBManager::get()
{
    WAZUH_ASSERT_MSG(mInitialized, "Trying to use an un-initialized manager");
    static KVDBManager instance;
    return instance;
}

KVDBManager::KVDBManager()
{
    // TODO should we read and load all the dbs inside the folder?
    // shouldn't be better to just load the configured ones at start instead?

    auto legacyPath = mDbFolder;
    legacyPath.append("legacy");
    if (std::filesystem::exists(legacyPath))
    {
        for (const auto& cdbfile :
             std::filesystem::directory_iterator(legacyPath))
        {
            // Read it from the config file?
            if (cdbfile.is_regular_file())
            {
                if (createDBfromCDB(cdbfile.path(), true))
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
        WAZUH_LOG_ERROR("DB with name [{}] already exists.", name);
        return nullptr;
    }

    WAZUH_LOG_DEBUG("adding DB with name [{}] to available Databases", name);
    auto kvdb = std::make_shared<KVDB>(name, mDbFolder);
    kvdb->init(createIfMissing);
    m_availableKVDBs[name] = kvdb;
    return kvdb;
}

bool KVDBManager::createDBfromCDB(const std::filesystem::path& path,
                                  bool createIfMissing)
{
    std::ifstream CDBfile(path);
    if (!CDBfile.is_open())
    {
        WAZUH_LOG_ERROR("Couln't open CDB file [{}]", path.c_str());
        return false;
    }

    auto db = addDb(path.stem(), createIfMissing);
    if (!db)
    {
        WAZUH_LOG_ERROR("Failed to create db [{}] from CDB file [{}].",
                        path.stem().string(),
                        path.string());
        return false;
    }

    for (std::string line; getline(CDBfile, line);)
    {
        line.erase(std::remove_if(line.begin(), line.end(), isspace),
                   line.end());
        auto kv = utils::string::split(line, ':');
        if (kv.empty() || kv.size() > 2)
        {
            WAZUH_LOG_ERROR("Error while reading CDBfile [{}]", path.c_str());
            return false;
        }

        db->write(kv[0], kv.size() == 2 ? kv[1] : "");
    }

    return true;
}

bool KVDBManager::deleteDB(const std::string& name)
{
    std::unique_lock lk(mMtx);
    auto it = m_availableKVDBs.find(name);
    if (it == m_availableKVDBs.end())
    {
        WAZUH_LOG_ERROR("Database [{}] isn't handled by KVDB manager", name);
        return false;
    }
    it->second->cleanupOnClose();
    m_availableKVDBs.erase(it);
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
            if (!db->init(false))
            {
                WAZUH_LOG_ERROR("Error initializing db [{}].", db->getName());
                return nullptr;
            }
        }

        return it->second;
    }

    return nullptr;
}
