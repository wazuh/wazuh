#ifndef _KVDBMANAGER_H
#define _KVDBMANAGER_H

#include <filesystem>
#include <string>
#include <vector>
#include <shared_mutex>
#include <unordered_map>

#include <utils/baseMacros.hpp>
#include <kvdb/kvdb.hpp>

using KVDBHandle = std::shared_ptr<KVDB>;

class KVDBManager
{
    WAZUH_DISABLE_COPY_ASSIGN(KVDBManager);

    KVDBManager(const std::string &DbFolder);
    ~KVDBManager();
    static KVDBManager *mInstance;
    std::string mDbFolder;
    std::unordered_map<std::string, KVDBHandle> m_availableKVDBs;
    std::shared_mutex mMtx;

public:
    static bool init(const std::string &DbFolder);
    static KVDBManager &get();
    KVDBHandle addDb(const std::string &Name, bool createIfMissing = true);
    bool createDBfromCDB(const std::filesystem::path &path,
                         bool overwrite = true);
    bool deleteDB(const std::string &name);
    KVDBHandle getDB(const std::string &name);
};

#endif // _KVDBMANAGER_H
