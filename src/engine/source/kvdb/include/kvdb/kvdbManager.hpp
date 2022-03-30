#ifndef _KVDBMANAGER_H
#define _KVDBMANAGER_H

#include <filesystem>
#include <string>
#include <vector>

#include "kvdb.hpp"

class KVDBManager
{
    KVDBManager();
    ~KVDBManager();
    // TODO: this will be moved to an init method and folder path will be
    // modifiable
    const std::string FOLDER = "/var/ossec/queue/db/kvdb/";
    using DBMap = std::unordered_map<std::string, std::unique_ptr<KVDB>>;
    DBMap m_availableKVDBs;
    bool addDB(const std::string &name,const std::string &folder);

public:
    static KVDBManager &get()
    {
        static KVDBManager instance;
        return instance;
    }
    KVDBManager(KVDBManager const &) = delete;
    void operator=(KVDBManager const &) = delete;
    bool createDBfromCDB(const std::filesystem::path& path, bool replace = true);
    bool createDBfromCDB(const std::filesystem::path &path,
                         bool overwrite = true);
    bool deleteDB(const std::string &name);
    KVDB &getDB(const std::string &name);
};

#endif // _KVDBMANAGER_H
