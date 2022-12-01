#ifndef _KVDBMANAGER_H
#define _KVDBMANAGER_H

#include <filesystem>
#include <optional>
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

    std::filesystem::path m_dbStoragePath;
    std::unordered_map<std::string, KVDBHandle> m_availableKVDBs;
    std::shared_mutex m_mtx;

    /**
     * @brief Loads in KVDBHanlde the pointer to access KVDB functions
     *
     * @param name of the KVDB to be loaded
     * @param dbHandle used to access KVDB functions
     * @return true if it could be found and loaded
     * @return false otherwise
     */
    bool getKVDBFromPath(const std::string& name, KVDBHandle& dbHandle);

    /**
     * @brief Checks wether a path contains a KVDB
     *
     * @param name of the KVDB to be checked
     * @return true if there's a KVDB on that path
     * @return false otherwise
     */
    bool isKVDBOnPath(const std::string& name);

public:
    KVDBManager(const std::filesystem::path& dbStoragePath);
    ~KVDBManager() = default;

    /**
     * @brief adds KVDB to the available list
     *
     * @param Name of the KVDB to be added
     * @param createIfMissing if true, creates the database when it does not exist
     * @return KVDBHandle to access KVDB functions
     */
    KVDBHandle loadDb(const std::string& Name, bool createIfMissing = true);

    /**
     * @brief Creates a KVDB named as the CDB file from filepath and fills it with
     * it's content.
     *
     * @param path where to look for the file to fill the KVDB
     * @return true if it could be created
     * @return false otherwise
     */
    bool createKVDBfromCDBFile(const std::filesystem::path& path);

    /**
     * @brief Deletes a KVDB from loaded list or from filesystem.
     *
     * @param name of the KVDB to be deleted
     * @param onlyFromMem true when th KVDB is loaded false if not
     * @return true if it could be deleted
     * @return false otherwise
     */
    bool deleteDB(const std::string& name, bool onlyFromMem = true);

    /**
     * @brief Obtains a KVDB from loaded list.
     *
     * @param name of the KVDB to be returned
     * @return KVDBHandle where to access KVDB functionality.
     */
    KVDBHandle getDB(const std::string& name);

    /**
     * @brief Get the Available KVDB object
     *
     * @param onlyLoaded if it only looks for it in the available list
     * @return std::vector<std::string> of the KVDBs.
     */
    std::vector<std::string> listKVDBs(bool onlyLoaded = true);

    /**
     * @brief Create a And Fill KVDB from File object
     *
     * @param dbName name of the KVDB where to look for the key
     * @param path where to look for the file.
     * @return true if it could be completed succesfully
     * @return false otherwise.
     */
    std::string CreateAndFillKVDBfromFile(const std::string& dbName,
                                   const std::filesystem::path& path = "");

    /**
     * @brief Dumps the full KVDB to a json format string.
     *
     * @param name of the KVDB to be dumped.
     * @param content string where to store the db.
     * @return size_t quantity of keys dumped to the content result.
     */
    size_t dumpContent(const std::string& name, std::string& content);

    /**
     * @brief Writes a key or a key value to the KVDB named name.
     *
     * @param name of the KVDB where to write the key
     * @param key to write.
     * @param value to fill corresponding to the key.
     * @return true if the proccess finished successfully.
     * @return false otherwise.
     */
    bool writeKey(const std::string& name,
                  const std::string& key,
                  const std::string value = "");

    /**
     * @brief Gets the Key Value object on the KVDB and returns its value, empty strins if
     * it's a key only KVDB.
     *
     * @param name of the KVDB where to look for the key.
     * @param key to use for the query.
     * @return std::optional<std::string> nullopt for not precense, value otherwise
     */
    std::optional<std::string> getKeyValue(const std::string& name,
                                           const std::string& key);

    /**
     * @brief Deletes key from KVDB
     *
     * @param name of the KVDB where to look for the key
     * @param key to be delete
     * @return true when it could deleted correctly
     * @return false otherwise
     */
    bool deleteKey(const std::string& name, const std::string& key);

    /**
     * @brief Clear the entire map of available KVDBs
     *
     */
    void clear()
    {
        if (m_availableKVDBs.size() > 0)
        {
            m_availableKVDBs.clear();
        }
    }
};

#endif // _KVDBMANAGER_H
