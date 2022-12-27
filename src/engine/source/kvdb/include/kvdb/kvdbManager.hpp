#ifndef _KVDBMANAGER_H
#define _KVDBMANAGER_H

#include <filesystem>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

#include <json/json.hpp>
#include <kvdb/kvdb.hpp>

namespace kvdb_manager
{

using KVDBHandle = std::shared_ptr<KVDB>;

constexpr int API_SUCCESS_CODE {0}; // TODO DELETE THIS - API
constexpr int API_ERROR_CODE {-1};  // TODO DELETE THIS - API

class KVDBManager
{
    WAZUH_DISABLE_COPY_ASSIGN(KVDBManager);

    std::filesystem::path m_dbStoragePath;
    std::unordered_map<std::string, KVDBHandle> m_dbs;
    std::shared_mutex m_mtx;

    /**
     * @brief Checks wether a path contains a KVDB
     *
     * @param name of the KVDB to be checked
     * @return true if there's a KVDB on that path
     * @return false otherwise
     */
    bool exist(const std::string& name);

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
    KVDBHandle loadDB(const std::string& Name,
                      bool createIfMissing = true); // TODO MOVE TO PRIVATE

    void unloadDB(const std::string& name);

    /**
     * @brief Obtains a KVDB from loaded list.
     *
     * @param name of the KVDB to be returned
     * @return KVDBHandle where to access KVDB functionality.
     */
    KVDBHandle getDB(const std::string& name); // TODO MOVE TO PRIVATE

    std::variant<KVDBHandle, base::Error> getHandler(const std::string& name,
                                                     bool createIfMissing = false);

    /**
     * @brief Get the Available KVDB object
     *
     * @param onlyLoaded if it only looks for it in the available list
     * @return std::vector<std::string> of the KVDBs.
     */
    std::vector<std::string> listDBs(bool onlyLoaded = true);

    /**
     * @brief Create a And Fill KVDB from File object
     *
     * @param dbName name of the KVDB where to look for the key
     * @param path where to look for the file.
     * @return true if it could be completed succesfully
     * @return false otherwise.
     */
    std::optional<base::Error> CreateFromJFile(const std::string& dbName,
                                        const std::filesystem::path& path = "");

    /**
     * @brief Dump the whole DB content to a json
     *
     * @param name Of the DB to be dumped
     * @param data Json object where the DB will be dumped
     * @return std::optional<std::string_view> error message or std::nullopt if no error
     */
    std::variant<json::Json, base::Error> jDumpDB(const std::string& name);

    /**
     * @brief Writes a key or a key value to the KVDB named name.
     *
     * @param name of the KVDB where to write the key
     * @param key to write.
     * @param value to fill corresponding to the key.
     * @return true if the proccess finished successfully.
     * @return false otherwise.
     */
    std::optional<base::Error> writeRaw(const std::string& name,
                                        const std::string& key,
                                        const std::string value = "null");

    inline std::optional<base::Error> writeKey(const std::string& name,
                                               const std::string& key,
                                               const std::string& value = "null");

    std::optional<base::Error>
    writeKey(const std::string& name, const std::string& key, const json::Json& value)
    {
        return writeRaw(name, key, value.str());
    };

    /**
     * @brief Gets the Key Value object on the KVDB and returns its value, empty strins if
     * it's a key only KVDB.
     *
     * @param name of the KVDB where to look for the key.
     * @param key to use for the query.
     * @return std::optional<std::string> nullopt for not precense, value otherwise
     */
    std::variant<std::string, base::Error> getRawValue(const std::string& name,
                                                       const std::string& key);

    std::variant<json::Json, base::Error> getJValue(const std::string& name,
                                                    const std::string& key);
    /**
     * @brief Deletes key from KVDB
     *
     * @param name of the KVDB where to look for the key
     * @param key to be delete
     * @return true when it could deleted correctly
     * @return false otherwise
     */
    std::optional<base::Error> deleteKey(const std::string& name, const std::string& key);

    /**
     * @brief Deletes DB and it's content from filesystem
     *
     * @param name of the DB to be deleted
     * @return nullopt if it could be deleted without problem
     * @return string error message otherwise
     */
    std::optional<std::string> deleteDB(const std::string& name);

    /**
     * @brief Clear the entire map of available KVDBs
     *
     */
    void clear()
    {
        if (m_dbs.size() > 0)
        {
            m_dbs.clear();
        }
    }
};

} // namespace kvdb_manager

#endif // _KVDBMANAGER_H
