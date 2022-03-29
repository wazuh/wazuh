#ifndef _KVDBMANAGER_H
#define _KVDBMANAGER_H

#include <string>
#include <vector>
#include <filesystem>

#include "kvdb.hpp"

class KVDBManager {
    KVDBManager();
    ~KVDBManager();
    const std::string FOLDER = "/var/ossec/queue/db/kvdb/";
    using DBMap = std::unordered_map<std::string, KVDB*>;
    DBMap available_kvdbs;
    bool addDB(KVDB* DB);
    KVDB invalidDB = KVDB(); // TODO: Make this static?

public:
    static KVDBManager& getInstance() { static KVDBManager instance; return instance; }
    KVDBManager(KVDBManager const&)     = delete;
    void operator=(KVDBManager const&)  = delete;
    bool createDB(const std::string& Name, bool replace = true);
    bool createDBfromCDB(const std::filesystem::path& path, bool replace = true);
    bool DeleteDB(const std::string &name);
    KVDB& getDB(const std::string& Name);
};

#endif // _KVDBMANAGER_H
