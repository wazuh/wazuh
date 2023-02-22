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

class KVDBManager
{
    WAZUH_DISABLE_COPY_ASSIGN(KVDBManager);

    std::filesystem::path m_dbStoragePath;
    std::unordered_map<std::string, KVDBHandle> m_dbs;
    std::shared_mutex m_mtx;

    /**
     * @brief Checks if the KVDB exists in the available list or in the filesystem.
     *
     * @param name of the KVDB to be checked
     * @return true if it exists and can be loaded o false otherwise.
     */
    bool exist(const std::string& name);

    /**
     * @brief  Loads a KVDB from the filesystem to the loaded list.
     *
     * @param Name of the KVDB to be added
     * @param createIfMissing if true, creates the database when it does not exist
     * @return KVDBHandle where to access KVDB functionality.
     */
    KVDBHandle loadDB(const std::string& Name, bool createIfMissing = true);

    /**
     * @brief Get the KVDB from the available list.
     *
     * If it is not in the available list, it won't load it.
     * @param name of the KVDB to be retrieved
     * @return KVDBHandle where to access KVDB functionality or nullptr if it does not
     * loaded.
     */
    KVDBHandle getDB(const std::string& name);

public:
    KVDBManager(const std::filesystem::path& dbStoragePath);
    ~KVDBManager() = default;

    /**
     * @brief Unloads a KVDB from the loaded list.
     * @param name of the KVDB to be removed
     */
    void unloadDB(const std::string& name);

    /**
     * @brief Get the Handler of the KVDB or error if it does not exist.
     *
     * If it is not in the available list, it loads it.
     * @param name of the KVDB to be retrieved
     * @param createIfMissing if true, creates the database when it does not exist.
     * @return std::variant<KVDBHandle, base::Error>
     */
    std::variant<KVDBHandle, base::Error> getHandler(const std::string& name,
                                                     bool createIfMissing = false);

    /**
     * @brief Get the List of names of the KVDBs.
     *
     * @param onlyLoaded if true, returns only the loaded databases.
     * @return std::vector<std::string> list of databases.
     */
    std::vector<std::string> listDBs(bool onlyLoaded = true);

    /**
     * @brief Create a KVDB and loads it to the available list.
     *
     * Optionally, it can be created from a json file. The json file must be a valid
     * json object with the following structure:
     * {
     * "key1": "value1",
     * "key2": "value2",
     * ...
     * }
     * Where key1, key2, ... are the keys and value1, value2, ... are the values.
     * The values can be any valid json object.
     * @param dbName The name of the database to be created.
     * @param path The path to the json file to be used as a source.
     * @return std::optional<base::Error> error message or std::nullopt if no error
     */
    std::optional<base::Error> createFromJFile(const std::string& dbName,
                                               const std::filesystem::path& path = "");

    /**
     * @brief Dumps the KVDB named name to a json array or error if it does not dumped.
     *
     * @param name of the KVDB to be dumped
     * @return std::variant<json::Json, base::Error>  json array or error if it does not
     * dumped.
     */
    std::variant<json::Json, base::Error> jDumpDB(const std::string& name);

    /**
     * @brief Dumps the KVDB named name to a json array or error if it does not dumped.
     *
     * @param name of the KVDB to be dumped
     * @return std::variant<json::Json, base::Error>  json array or error if it does not
     * dumped.
     */
    std::variant<std::unordered_map<std::string, std::string>, base::Error> rDumpDB(const std::string& name);


    /**
     * @brief Writes a key or a key value to the KVDB named name.
     *
     * @param name of the KVDB where to write the key
     * @param key to write.
     * @param value to fill corresponding to the key. If it's empty, it will write a null
     * value.
     * @return std::optional<base::Error> error message or std::nullopt if no error
     *
     * @warning Never use this function directly. Use writeKey or writeRaw instead.
     * @TODO: Make this function private.
     */
    std::optional<base::Error> writeRaw(const std::string& name,
                                        const std::string& key,
                                        const std::string value = "null");

    /**
     * @brief Writes a key or a key value to the KVDB named name.
     *
     * @param name of the KVDB where to write the key
     * @param key to write.
     * @param value to fill corresponding to the key. If it's empty, it will write a null value.
     * @return std::optional<base::Error> error message or std::nullopt if no error
     */
    std::optional<base::Error>
    writeKey(const std::string& name, const std::string& key, const std::string& value = "null");

    /**
     * @brief Writes a key or a key value to the KVDB named name.
     *
     * @param name of the KVDB where to write the key
     * @param key to write.
     * @param value to fill corresponding to the key. If it's empty, it will write a null
     * value.
     * @return std::optional<base::Error> error message or std::nullopt if no error
     */
    std::optional<base::Error>
    writeKey(const std::string& name, const std::string& key, const json::Json& value)
    {
        return writeRaw(name, key, value.str());
    };

    /**
     * @brief Get the Raw Value of the key from the KVDB named name or error if could not
     * get it.
     *
     * @param name of the KVDB where to look for the key.
     * @param key to use for the query.
     * @return std::optional<std::string> nullopt for not precense, value otherwise
     */
    std::variant<std::string, base::Error> getRawValue(const std::string& name,
                                                       const std::string& key);

    /**
     * @brief Get the Value of the key from the KVDB named name or error if could not get
     * it.
     *
     * @param name of the KVDB where to look for the key.
     * @param key to use for the query.
     * @return std::variant<json::Json, base::Error>
     */
    std::variant<json::Json, base::Error> getJValue(const std::string& name,
                                                    const std::string& key);
    /**
     * @brief Deletes key from KVDB named name
     *
     * @param name of the KVDB where to look for the key
     * @param key to be delete
     * @return nullopt if the key no longer exists. (It could be deleted or it was not
     * there)
     */
    std::optional<base::Error> deleteKey(const std::string& name, const std::string& key);

    /**
     * @brief Deletes DB and it's content from filesystem
     *
     * @param name of the DB to be deleted
     * @return nullopt if it could be deleted without problem
     * @return error if it could not be deleted
     */
    std::optional<base::Error> deleteDB(const std::string& name);

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
