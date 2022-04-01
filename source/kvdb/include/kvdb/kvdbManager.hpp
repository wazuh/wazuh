#ifndef _KVDBMANAGER_H
#define _KVDBMANAGER_H

#include <filesystem>
#include <string>
#include <vector>

#include "kvdb.hpp"

class KVDBManager
{
    KVDBManager(const std::string& DbFolder);
    ~KVDBManager();
    static KVDBManager* mInstance;
    std::string mDbFolder;
    using DBMap = std::unordered_map<std::string, KVDB *>;
    DBMap available_kvdbs;
    bool addDB(KVDB *DB);
    KVDB invalidDB = KVDB(); // TODO: Make this static?

public:
    static bool init(const std::string& DbFolder);
    static KVDBManager &get()
    {
        static KVDBManager instance;
        return instance;
    }
    KVDBManager(KVDBManager const &) = delete;
    KVDBManager() = delete;
    void operator=(KVDBManager const &) = delete;
    KVDB &createDB(const std::string &Name, bool overwrite = true);
    bool createDBfromCDB(const std::filesystem::path &path,
                         bool overwrite = true);
    bool deleteDB(const std::string &name);
    KVDB &getDB(const std::string &name);
};

#endif // _KVDBMANAGER_H
