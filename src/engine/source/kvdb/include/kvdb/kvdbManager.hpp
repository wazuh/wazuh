#ifndef _KVDBMANAGER_H
#define _KVDBMANAGER_H

#include <filesystem>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <kvdb/kvdb.hpp>
#include <utils/baseMacros.hpp>

using KVDBHandle = std::shared_ptr<KVDB>;

class KVDBManager
{
    WAZUH_DISABLE_COPY_ASSIGN(KVDBManager);

    std::filesystem::path mDbFolder;
    std::unordered_map<std::string, KVDBHandle> m_availableKVDBs;
    std::shared_mutex mMtx;

public:
    KVDBManager(const std::filesystem::path& DbFolder);
    ~KVDBManager() = default;
    KVDBHandle addDb(const std::string& Name, bool createIfMissing = true);
    bool createDBfromCDB(const std::filesystem::path& path, bool createIfMissing = true);
    bool deleteDB(const std::string& name);
    KVDBHandle getDB(const std::string& name);
    void clear()
    {
        if (m_availableKVDBs.size() > 0)
        {
            m_availableKVDBs.clear();
        }
    }
};

#endif // _KVDBMANAGER_H
