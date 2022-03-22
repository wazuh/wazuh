#ifndef _KVDBMANAGER_H
#define _KVDBMANAGER_H

#include <string>
#include <vector>

#include "kvdb.hpp"

class KVDBManager {
    KVDBManager();
    static constexpr char FOLDER[] = "/var/ossec/queue/db/kvdb/"; //Should be constexpr if it is a singleton?
    static constexpr char LEGACY_CDB_FOLDER[] = "queue/db/kvdb/"; // TODO Read it from the legacy config.
    std::unordered_map<std::string, KVDB*> available_kvdbs;
    void updateLegacyCDB();
    bool addDB(KVDB* DB);

public:
    static KVDBManager& getInstance() { static KVDBManager instance; return instance; }
    KVDBManager(KVDBManager const&)     = delete;
    void operator=(KVDBManager const&)  = delete;
    KVDB* createDB(const std::string& Name);
    KVDB& getDB(const std::string& Name);
};

#endif // _KVDBMANAGER_H
