#include <kvdb/kvdbManager.hpp>

#include <assert.h>
#include <fstream>
#include <iostream>
#include <set>
#include <unordered_map>

#include <fmt/format.h>
#include <logging/logging.hpp>
#include <utils/stringUtils.hpp>

#include <kvdb/kvdb.hpp>

static KVDB invalidDB = KVDB();

KVDBManager::KVDBManager()
{
    static const std::set<std::string> INTERNALFILES = {
        "legacy", "LOG", "LOG.old", "LOCK"};
    for (const auto &dbFile : std::filesystem::directory_iterator(FOLDER))
    {
        if (INTERNALFILES.find(dbFile.path().filename()) == INTERNALFILES.end())
        {
            if (addDB(dbFile.path().stem(), FOLDER))
            {
                if (m_availableKVDBs[dbFile.path().stem()]->getState() !=
                    KVDB::State::Open)
                {
                    WAZUH_LOG_ERROR("DB not opened");
                }
            }
            else
            {
                // log error coudn't addDB
                WAZUH_LOG_ERROR("couldn't add db, error: [{}]");
            }
        }
    }

    if (std::filesystem::exists(FOLDER + "legacy"))
    {
        for (const auto &cdbfile :
             std::filesystem::directory_iterator(FOLDER + "legacy"))
        { // Read it from the config file?
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

KVDB &KVDBManager::createDB(const std::string &name, bool overwrite)
{
    rocksdb::Options createOptions;
    createOptions.IncreaseParallelism();
    createOptions.OptimizeLevelStyleCompaction();
    createOptions.create_if_missing = true;
    createOptions.error_if_exists = !overwrite;

    rocksdb::DB *db;
    rocksdb::Status s = rocksdb::DB::Open(createOptions, FOLDER + name, &db);
    if (!s.ok())
    {
        WAZUH_LOG_ERROR("couldn't open db file, error: [{}]", s.ToString());
        return invalidDB;
    }
    s = db->Close(); // TODO: We can avoid this unnecessary close making a more
                     // complex KVDB constructor that creates DBs
                     // or if receives a CFHandler and a CFDescriptor vector.
    if (!s.ok())
    {
        WAZUH_LOG_ERROR("couldn't close db file, error: [{}]", s.ToString());
        return invalidDB;
    }

    if (addDB(name, FOLDER))
    {
        return getDB(name);
    }
    else
    {
        return invalidDB;
    }
}

bool KVDBManager::createDBfromCDB(const std::filesystem::path &path,
                                  bool overwrite)
{
    std::ifstream CDBfile(path);
    if (!CDBfile.is_open())
    {
        WAZUH_LOG_ERROR("Can't open CDB file");
        return false;
    }

    KVDB &kvdb = createDB(path.stem(), overwrite);
    if (kvdb.getName().empty())
    {
        WAZUH_LOG_ERROR("Couldn't create DB from CDB");
        return false;
    }
    if (kvdb.getState() != KVDB::State::Open)
    {
        WAZUH_LOG_ERROR("DB Creted from CDB is not open");
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
        kvdb.write(KV.at(0), KV.at(1));
    }

    CDBfile.close();

    return true;
}

bool KVDBManager::deleteDB(const std::string &name)
{
    auto it = m_availableKVDBs.find(name);
    if (it == m_availableKVDBs.end())
    {
        WAZUH_LOG_ERROR("Database [{}] isn´t handled by KVDB manager", name);
        return false;
    }
    bool ret = it->second->destroy();
    it->second.release();
    m_availableKVDBs.erase(it);
    return ret;
}

bool KVDBManager::addDB(const std::string &name,const std::string &folder)
{
    KVDB *kvdb;
    if (m_availableKVDBs.find(name) == m_availableKVDBs.end())
    {
        m_availableKVDBs[name] = std::make_unique<KVDB>(name, folder);
        return true;
    }
    return false;
}

KVDB &KVDBManager::getDB(const std::string &name)
{
    auto it = m_availableKVDBs.find(name);
    if (it != m_availableKVDBs.end())
    {
        return (*it->second);
    }
    return invalidDB;
}
