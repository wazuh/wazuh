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

    static std::filesystem::path mDbFolder;
    std::unordered_map<std::string, std::pair<KVDBHandle, bool>> m_availableKVDBs;
    std::shared_mutex mMtx;

public:
    KVDBManager(const std::filesystem::path& DbFolder);
    ~KVDBManager() = default;
    KVDBHandle addDb(const std::string& Name,
                     bool createIfMissing = true,
                     bool lockForDelete = true);
    bool createKVDBfromFile(const std::filesystem::path& path,
                            bool createIfMissing = true,
                            const std::string dbName = "");
    bool deleteDB(const std::string& name, bool onlyFromMem = true);
    KVDBHandle getDB(const std::string& name, bool lockForDelete = true);
    std::vector<std::string> getAvailableKVDBs(bool onlyLoaded = true);
    bool CreateAndFillKVDBfromFile(const std::string& dbName,
                                   const std::filesystem::path& path = "");
    void clear()
    {
        if (m_availableKVDBs.size() > 0)
        {
            m_availableKVDBs.clear();
        }
    }
};

#endif // _KVDBMANAGER_H
