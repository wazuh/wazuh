/**
 * @file file.cpp
 * @brief Definition of FIM database for files library.
 * @date 2021-09-9
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */
#include "json.hpp"
#include "db.hpp"
#include "fimDBHelper.hpp"
#include "dbFileItem.hpp"
#ifdef __cplusplus
extern "C" {
#endif

const auto fileColumnList = R"({"column_list":"[path, mode, last_event, scanned, options, checksum, dev, inode, size,
                                                perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1,
                                                hash_sha256, mtime]"})"_json;

/**
 * @brief Get path list using the sqlite LIKE operator using @pattern. (stored in @file).
 * @param pattern Pattern that will be used for the LIKE operation.
 *
 * @return a vector with every paths on success, a empty vector otherwise.
 */
std::vector<std::string> fim_db_get_path_from_pattern(const char *pattern);

/**
 * @brief Get all the paths asociated to an inode
 *
 * @param inode Inode.
 * @param dev Device.
 *
 * @return a vector with paths asociated to the inode.
 */
std::vector<std::string> fim_db_get_paths_from_inode(unsigned long int inode, unsigned long int dev);


int fim_db_delete_range(const char* pattern,
                        pthread_mutex_t* mutex,
                        event_data_t* evt_data,
                        const directory_t* configuration)
{
    auto paths = fim_db_get_path_from_pattern(pattern);
    if (paths.empty())
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, "No entry found with that pattern");
        return FIMDB_ERR;
    }
    for (auto& path : paths)
    {
        char* entry = const_cast<char*>(path.c_str());
        directory_t *validated_configuration = fim_configuration_directory(entry);
        if (validated_configuration == configuration) {
            fim_delete_file_event(entry, mutex, evt_data, NULL, NULL);
        }
    }

    return FIMDB_OK;
}

int fim_db_process_missing_entry(const char* pattern,
                                 pthread_mutex_t* mutex,
                                 event_data_t* evt_data)
{
    auto paths = fim_db_get_path_from_pattern(pattern);
    if (paths.empty())
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, "No entry found with that pattern");
        return FIMDB_ERR;
    }
    for (auto& path : paths)
    {
        char* entry = const_cast<char*>(path.c_str());
        fim_delete_file_event(entry, mutex, evt_data, NULL, NULL);
    }

    return FIMDB_OK;
}

int fim_db_remove_wildcard_entry(const char* pattern,
                                 pthread_mutex_t* mutex,
                                 event_data_t* evt_data,
                                 directory_t* configuration)
{
    auto paths = fim_db_get_path_from_pattern(pattern);
    if (paths.empty())
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, "No entry found with that pattern");
        return FIMDB_ERR;
    }
    for (auto& path : paths)
    {
        char* entry = const_cast<char*>(path.c_str());
        fim_generate_delete_event(entry, mutex, evt_data, configuration, NULL);
    }

    return FIMDB_OK;
}
// LCOV_EXCL_STOP

fim_entry* fim_db_get_path(const char* file_path)
{
    nlohmann::json entry_from_path;
    auto filter = std::string("WHERE path=") + std::string(file_path);
    auto query = FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, fileColumnList, filter, FILE_PRIMARY_KEY);
    try
    {
        FIMDBHelper::getDBItem<FIMDB>(entry_from_path, query);
    }
    catch (DbSync::dbsync_error& err)
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, err.what());
        return nullptr;
    }
    std::unique_ptr<FileItem> file(new FileItem(entry_from_path));

    return file->toFimEntry();
}

std::vector<std::string> fim_db_get_paths_from_inode(unsigned long int inode, unsigned long int dev)
{
    std::vector<std::string> paths;
    nlohmann::json resultQuery;

    try
    {
        auto filter = std::string("WHERE inode=") + std::to_string(inode) + std::string(" AND dev=") + std::to_string(dev);
        auto query = FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, FILE_PRIMARY_KEY, filter, FILE_PRIMARY_KEY);
        FIMDBHelper::getDBItem<FIMDB>(resultQuery, query);
    }
    catch (DbSync::dbsync_error& err)
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, err.what());
        return paths;
    }
    for (auto& item : resultQuery["path"].items())
    {
        paths.push_back(item.value());
    }

    return paths;
}

int fim_db_remove_path(const char* path)
{
    try
    {
        auto removeFile = std::string("WHERE path=") + std::string(path);
        FIMDBHelper::removeFromDB<FIMDB>(FIMBD_FILE_TABLE_NAME, removeFile);
    }
    catch (DbSync::dbsync_error& err)
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, err.what());
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_get_count_file_inode()
{
    int count = 0;

    try
    {
        nlohmann::json inodeQuery;
        inodeQuery["column_list"] = "count(DISTINCT (inode || ',' || dev)) AS count";
        auto countQuery = FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, inodeQuery, "", "");
        FIMDBHelper::getCount<FIMDB>(FIMBD_FILE_TABLE_NAME, count, countQuery);
    }
    catch (DbSync::dbsync_error& err)
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, err.what());
    }

    return count;
}

int fim_db_get_count_file_entry()
{
    int count = 0;

    try
    {
        FIMDBHelper::getCount<FIMDB>(FIMBD_FILE_TABLE_NAME, count);
    }
    catch (DbSync::dbsync_error& err)
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, err.what());
    }

    return count;
}

std::vector<std::string> fim_db_get_path_from_pattern(const char* pattern)
{
    std::vector<std::string> paths;
    nlohmann::json resultQuery;
    try
    {
        auto filter = std::string("WHERE path LIKE") + std::string(pattern);
        auto queryFromPattern = FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, FILE_PRIMARY_KEY, filter, FILE_PRIMARY_KEY);
        FIMDBHelper::getDBItem<FIMDB>(resultQuery, queryFromPattern);
    }
    catch (DbSync::dbsync_error& err)
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, err.what());
        return paths;
    }
    for (auto& item : resultQuery["path"].items())
    {
        paths.push_back(item.value());
    }

    return paths;
}

int fim_db_file_update(const fim_entry* data, bool* updated)
{
    std::unique_ptr<FileItem> file(new FileItem(const_cast<fim_entry*>(data)));
    try
    {
        FIMDBHelper::updateItem<FIMDB>(*file->toJSON(), *updated);
    }
    catch (DbSync::dbsync_error& err)
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, err.what());
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

void create_windows_who_data_events(unsigned long int inode, unsigned long int dev, whodata_evt* w_evt)
{
    auto paths = fim_db_get_paths_from_inode(inode, dev);
    if (paths.empty())
    {
        FIMDBHelper::logErr<FIMDB>(LOG_ERROR, "No paths found with these inode and dev");
        return;
    }
    for (auto& path : paths)
    {
        char* entry = const_cast<char*>(path.c_str());
        w_rwlock_rdlock(&syscheck.directories_lock);
        fim_process_missing_entry(entry, FIM_WHODATA, w_evt);
        w_rwlock_unlock(&syscheck.directories_lock);
    }
}

#ifdef __cplusplus
}
#endif
