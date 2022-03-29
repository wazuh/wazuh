#include <kvdb/kvdbManager.hpp>

#include <assert.h>
#include <iostream>
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <set>

#include <utils/stringUtils.hpp>
#include <fmt/format.h>
#include <logging/logging.hpp>

#include "kvdb.hpp"


KVDBManager::KVDBManager() {
    static const std::set<std::string> internalFiles = {"legacy", "LOG", "LOG.old", "LOCK"};
    for (const auto& dbFile : std::filesystem::directory_iterator(FOLDER)) {
        if (internalFiles.find(dbFile.path()) != internalFiles.end()) {
            KVDB* DB = new KVDB(dbFile.path().stem(), FOLDER);
            if (DB && DB->getState() == KVDB::State::Open) {
                addDB(DB);
            }
            else {
                delete DB;
                //TODO DEBUG Log
            }
        }
    }

    for (const auto& cdbfile : std::filesystem::directory_iterator(FOLDER + "legacy")) { //Read it from the config file?
        if (createDBfromCDB(cdbfile.path())) {
            //TODO Remove files once synced
            //std::filesystem::remove(cdbfile.path())
        }
    }
}

KVDBManager::~KVDBManager() {
    for (DBMap::iterator it = available_kvdbs.begin(); it != available_kvdbs.end(); it++) {
       delete it->second;
       available_kvdbs.erase(it);
    }
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
    addDB(kvdb);
    return true;
}

bool KVDBManager::createDBfromCDB(const std::filesystem::path& path, bool replace) {
    constexpr char folderSeparator = '/';
    constexpr char extensionSeparator = '.';

    std::string line;
    std::ifstream CDBfile (path);
    if (!CDBfile.is_open()) {
        // TODO Log Error
        return false;
    }

    if (!createDB(path.stem(), replace)) {
        // TODO Log Error
        CDBfile.close();
        return false;
    }
    auto kvdb = getDB(path.stem());
    if (kvdb.getState() != KVDB::State::Open) {
        // TODO Log Error
        CDBfile.close();
        return false;
    }

    while (getline(CDBfile, line))
    {
        line.erase(remove_if(line.begin(), line.end(), isspace), line.end());
        auto KV = utils::string::split(line, ':');
        kvdb.write(KV[0], KV[1]);
    }

    CDBfile.close();

    return true;
}

bool KVDBManager::DeleteDB(const std::string &name) {
    bool ret = true;
    auto it = available_kvdbs.find(name);
    if (it != available_kvdbs.end()) {
        ret = it->second->destroy();
        delete it->second;
        available_kvdbs.erase(it);
    }
    else {
        auto msg = fmt::format("Database [{}] isn´t handled by KVDB manager", name);
        WAZUH_LOG_ERROR(msg);
        ret = false;
    }

    return ret;
}

bool KVDBManager::addDB(KVDB *DB)
{
    available_kvdbs[DB->getName()] = DB;
    return true;
}

KVDB& KVDBManager::getDB(const std::string& Name) {
    auto it = available_kvdbs.find(Name);
    if (it != available_kvdbs.end()) {
        return (*it->second);
    }
    return invalidDB;
}
