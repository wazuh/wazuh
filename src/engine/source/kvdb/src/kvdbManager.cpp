#include <kvdb/kvdbManager.hpp>

#include <assert.h>
#include <fstream>
#include <iostream>
#include <set>
#include <unordered_map>

#include <fmt/format.h>
#include <logging/logging.hpp>
#include <utils/stringUtils.hpp>

#include "kvdb.hpp"

KVDBManager::KVDBManager()
{
    static const std::set<std::string> INTERNALFILES = {
        "legacy", "LOG", "LOG.old", "LOCK"};
    for (const auto &dbFile : std::filesystem::directory_iterator(FOLDER))
    {
        if (INTERNALFILES.find(dbFile.path().filename()) == INTERNALFILES.end())
        {
            KVDB *DB = new KVDB(dbFile.path().stem(), FOLDER);
            if (DB && DB->getState() == KVDB::State::Open)
            {
                if (!addDB(DB))
                {
                    delete DB;
                    // TODO DEBUG Log
                }
            }
            else
            {
                delete DB;
                // TODO DEBUG Log
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
    for (DBMap::iterator it = available_kvdbs.begin();
         it != available_kvdbs.end();
         it++)
    {
        delete it->second;
    }
    available_kvdbs.clear();
}

bool KVDBManager::createDB(const std::string &name, bool replace)
{
    ROCKSDB::Options createOptions;
    createOptions.IncreaseParallelism();
    createOptions.OptimizeLevelStyleCompaction();
    createOptions.create_if_missing = true;
    createOptions.error_if_exists = !replace;

    ROCKSDB::DB *db;
    ROCKSDB::Status s = ROCKSDB::DB::Open(createOptions, FOLDER + name, &db);
    if (!s.ok())
    {
        // LOG(ERROR) << "[" << __func__ << "]" << " couldn't open db file,
        // error: " << s.ToString() << std::endl;
        return false;
    }
    s = db->Close(); // TODO: We can avoid this unnecessary close making a more
                     // complex KVDB constructor that creates DBs
                     // or if receives a CFHandler and a CFDescriptor vector.
    if (!s.ok())
    {
        // LOG(WARNING) << "[" << __func__ << "]" << " couldn't close db file,
        // error: " << s.ToString() << std::endl;
        return false;
    }

    KVDB *kvdb = new KVDB(name, FOLDER);
    if (!addDB(kvdb))
    {
        delete kvdb;
        return false;
    }

    return true;
}

bool KVDBManager::createDBfromCDB(const std::filesystem::path &path,
                                  bool replace)
{
    std::ifstream CDBfile(path);
    if (!CDBfile.is_open())
    {
        // TODO Log Error
        return false;
    }

    if (!createDB(path.stem(), replace))
    {
        // TODO Log Error
        CDBfile.close();
        return false;
    }
    KVDB &kvdb = getDB(path.stem());
    if (kvdb.getState() != KVDB::State::Open)
    {
        // TODO Log Error
        CDBfile.close();
        return false;
    }

    std::string line;
    while (getline(CDBfile, line))
    {
        line.erase(remove_if(line.begin(), line.end(), isspace), line.end());
        auto KV = utils::string::split(line, ':');
        kvdb.write(KV[0], KV[1]);
    }

    CDBfile.close();

    return true;
}

bool KVDBManager::DeleteDB(const std::string &name)
{
    bool ret = true;
    auto it = available_kvdbs.find(name);
    if (it != available_kvdbs.end())
    {
        ret = it->second->destroy();
        delete it->second;
        available_kvdbs.erase(it);
    }
    else
    {
        WAZUH_LOG_ERROR("Database [{}] isn´t handled by KVDB manager", name);
        ret = false;
    }

    return ret;
}

bool KVDBManager::addDB(KVDB *DB)
{
    if (available_kvdbs.find(DB->getName()) == available_kvdbs.end())
    {
        available_kvdbs[DB->getName()] = DB;
        return true;
    }
    else
    {
        return false;
    }
}

KVDB &KVDBManager::getDB(const std::string &Name)
{
    auto it = available_kvdbs.find(Name);
    if (it != available_kvdbs.end())
    {
        return (*it->second);
    }
    return invalidDB;
}
