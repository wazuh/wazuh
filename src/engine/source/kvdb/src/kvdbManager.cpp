#include <kvdb/kvdbManager.hpp>

#include <assert.h>
#include <iostream>
#include <unordered_map>

#include "kvdb.hpp"

KVDBManager::KVDBManager()
{
    // TODO Loop into FOLDER to load existent DBs
    KVDB *DB = createDB("TEST");
    if (DB)
    {
        addDB(DB);
    }
}

KVDB *KVDBManager::createDB(const std::string &name)
{

    ROCKSDB::Options createOptions;
    createOptions.IncreaseParallelism();
    createOptions.OptimizeLevelStyleCompaction();
    createOptions.create_if_missing = true;
    // createOptions.error_if_exists = true; // TODO Uncomment it. This is for
    // debugging purposes only

    ROCKSDB::DB *db;
    ROCKSDB::Status s = ROCKSDB::DB::Open(createOptions, FOLDER + name, &db);
    if (!s.ok())
    {
        // LOG(ERROR) << "[" << __func__ << "]" << " couldn't open db file,
        // error: " << s.ToString() << std::endl;
        return nullptr;
    }
    s = db->Close(); // TODO: We can avoid this unnecessary close making a more
                     // complex KVDB constructor that creates DBs
                     // or if receives a CFHandler and a CFDescriptor vector.
    if (!s.ok())
    {
        // LOG(WARNING) << "[" << __func__ << "]" << " couldn't close db file,
        // error: " << s.ToString() << std::endl;
        return nullptr;
    }
    KVDB *kvdb = new KVDB(name, FOLDER);
    return kvdb;
}

bool KVDBManager::addDB(KVDB *DB)
{
    available_kvdbs[DB->getName()] = DB;
    return true;
}

KVDB &KVDBManager::getDB(const std::string &Name)
{
    // TODO(*1): can this cause a SEgFault,
    // should we change from reference to pointer in order to be able to check
    // its precence?
    return *available_kvdbs[Name];
}
