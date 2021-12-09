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

int fim_db_process_missing_entry(pthread_mutex_t* mutex,
                                 int storage,
                                 event_data_t* evt_data)
{
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_delete_file_event, storage, evt_data, NULL,
                                    NULL);
}

int fim_db_remove_wildcard_entry(pthread_mutex_t* mutex,
                                 int storage,
                                 event_data_t* evt_data,
                                 directory_t* configuration)
{
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_generate_delete_event, storage, evt_data,
                                    configuration, NULL);
}
// LCOV_EXCL_STOP

fim_entry* fim_db_decode_full_row(sqlite3_stmt* stmt)
{

    fim_entry* entry = NULL;

    os_calloc(1, sizeof(fim_entry), entry);
    entry->type = FIM_TYPE_FILE;
    os_strdup((char*)sqlite3_column_text(stmt, 0), entry->file_entry.path);

    os_calloc(1, sizeof(fim_file_data), entry->file_entry.data);
    entry->file_entry.data->mode = (fim_event_mode)sqlite3_column_int(stmt, 1);
    entry->file_entry.data->last_event = (time_t)sqlite3_column_int(stmt, 2);
    entry->file_entry.data->scanned = (time_t)sqlite3_column_int(stmt, 3);
    entry->file_entry.data->options = (time_t)sqlite3_column_int(stmt, 4);
    strncpy(entry->file_entry.data->checksum, (char*)sqlite3_column_text(stmt, 5), sizeof(os_sha1) - 1);
    entry->file_entry.data->dev = (unsigned long int)sqlite3_column_int(stmt, 6);
    entry->file_entry.data->inode = (unsigned long int)sqlite3_column_int64(stmt, 7);
    entry->file_entry.data->size = (unsigned int)sqlite3_column_int(stmt, 8);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 9), entry->file_entry.data->perm);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 10), entry->file_entry.data->attributes);
#ifdef WIN32
    entry->file_entry.data->perm_json = cJSON_Parse(entry->file_entry.data->perm);
#endif
    sqlite_strdup((char *)sqlite3_column_text(stmt, 11), entry->file_entry.data->uid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 12), entry->file_entry.data->gid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 13), entry->file_entry.data->user_name);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 14), entry->file_entry.data->group_name);
    strncpy(entry->file_entry.data->hash_md5, (char *)sqlite3_column_text(stmt, 15), sizeof(os_md5) - 1);
    strncpy(entry->file_entry.data->hash_sha1, (char *)sqlite3_column_text(stmt, 16), sizeof(os_sha1) - 1);
    strncpy(entry->file_entry.data->hash_sha256, (char *)sqlite3_column_text(stmt, 17), sizeof(os_sha256) - 1);
    entry->file_entry.data->mtime = (unsigned int)sqlite3_column_int(stmt, 18);

    return entry;
}

/* No needed bind FIMDB_STMT_GET_LAST_ROWID, FIMDB_STMT_GET_NOT_SCANNED,
   FIMDB_STMT_SET_ALL_UNSCANNED, FIMDB_STMT_DELETE_UNSCANNED */

/* FIMDB_STMT_REPLACE_ENTRY */
void fim_db_bind_replace_entry(fdb_t* fim_sql, const char* file_path, const fim_file_data* entry)
{
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 1, file_path, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 2, entry->mode);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 3, entry->last_event);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 4, entry->scanned);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 5, entry->options);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 6, entry->checksum, -1, NULL);
#ifndef WIN32
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 7, entry->dev);
    sqlite3_bind_int64(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 8, entry->inode);
#else
    sqlite3_bind_null(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 7);
    sqlite3_bind_null(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 8);
#endif
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 9, entry->size);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 10, entry->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 11, entry->attributes, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 12, entry->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 13, entry->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 14, entry->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 15, entry->group_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 16, entry->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 17, entry->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 18, entry->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_ENTRY], 19, entry->mtime);
}

/* FIMDB_STMT_GET_PATH
 * FIMDB_STMT_DELETE_PATH
 * FIMDB_STMT_SET_SCANNED
 * FIMDB_STMT_GET_PATH_FROM_PATTERN */
void fim_db_bind_path(fdb_t* fim_sql, int index, const char* path)
{
    char** paths = NULL;
    auto filter = std::string("WHERE inode=") + std::to_string(inode) + std::string(" AND dev=") + std::to_string(dev);
    auto query = FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, FILE_PRIMARY_KEY, filter, FILE_PRIMARY_KEY);
    nlohmann::json resultQuery;
    FIMDBHelper::getDBItem<FIMDB>(resultQuery, query);

    return paths;
}

int fim_db_remove_path(const char* path)
{
    int res = 0;
    auto removeFile = std::string("WHERE path=") + std::string(path);
    FIMDBHelper::removeFromDB<FIMDB>(FIMBD_FILE_TABLE_NAME, removeFile);

    return res;
}

int fim_db_get_count_file_inode()
{
    int count = 0;
    nlohmann::json inodeQuery;
    inodeQuery["column_list"] = "count(DISTINCT (inode || ',' || dev)) AS count";
    auto countQuery = FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, inodeQuery, "", "");
    FIMDBHelper::getCount<FIMDB>(FIMBD_FILE_TABLE_NAME, count, countQuery);

    return count;
}

int fim_db_get_count_file_entry(fdb_t* fim_sql)
{
    int count = 0;
    nlohmann::json query;
    FIMDBHelper::getCount<FIMDB>(FIMBD_FILE_TABLE_NAME, count, query);

    return count;
}

std::vector<std::string>  fim_db_get_path_from_pattern(const char* pattern)
{
    std::vector<std::string> paths;
    auto filter = std::string("WHERE path LIKE") + std::string(pattern);
    auto queryFromPattern = FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, FILE_PRIMARY_KEY, filter, FILE_PRIMARY_KEY);
    nlohmann::json resultQuery;
    try
    {
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
#ifdef __cplusplus
}
#endif
