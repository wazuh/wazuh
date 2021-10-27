/**
 * @file fim_db_files.c
 * @brief Definition of FIM database for files library.
 * @date 2020-09-9
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "db.hpp"

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when unit testing */
#define static

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression, const char* const file, const int line);
#undef assert
#define assert(expression) mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

extern const char* SQL_STMT[];

/**
 * @brief Check if database if full
 *
 * @param fim_sql FIM database structure.
 * @param file_path Path reference to insert in db.
 * @param entry Entry data to be inserted.
 */
static int fim_db_insert_entry(fdb_t* fim_sql, const char* file_path, const fim_file_data* entry);

/**
 * @brief Set file entry scanned.
 *
 * @param fim_sql FIM database struct.
 * @param path File path.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
static int fim_db_set_scanned(fdb_t* fim_sql, const char* path);

int fim_db_get_not_scanned(fdb_t* fim_sql, fim_tmp_file** file, int storage)
{

    int ret = 0;
    /* TODO: Add c++ code to get all files unscanned from DB. If we use DBSync transactions
       for that this function should be deleted (using get_deleted_rows())
    */
    return ret;
}

// LCOV_EXCL_START
int fim_db_delete_not_scanned(fdb_t* fim_sql, fim_tmp_file* file, pthread_mutex_t* mutex, int storage)
{
    /* TODO: Add c++ code to delete files unscanned from DB
    */
    return FIMDB_OK;
}

int fim_db_delete_range(fdb_t* fim_sql,
                        fim_tmp_file* file,
                        pthread_mutex_t* mutex,
                        int storage,
                        event_data_t* evt_data,
                        directory_t* configuration)
{
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_db_remove_validated_path, storage,
                                    evt_data, configuration, NULL);
}

int fim_db_process_missing_entry(fdb_t* fim_sql,
                                 fim_tmp_file* file,
                                 pthread_mutex_t* mutex,
                                 int storage,
                                 event_data_t* evt_data)
{
    return fim_db_process_read_file(fim_sql, file, FIM_TYPE_FILE, mutex, fim_delete_file_event, storage, evt_data, NULL,
                                    NULL);
}

int fim_db_remove_wildcard_entry(fdb_t* fim_sql,
                                 fim_tmp_file* file,
                                 pthread_mutex_t* mutex,
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
    assert(index == FIMDB_STMT_GET_PATHS_INODE);

    sqlite3_bind_int64(fim_sql->stmt[index], 1, inode);
    sqlite3_bind_int(fim_sql->stmt[index], 2, dev);
}

fim_entry* _fim_db_get_path(fdb_t* fim_sql, const char* file_path)
{
    fim_entry* entry = NULL;

    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_PATH);
    fim_db_bind_path(fim_sql, FIMDB_STMT_GET_PATH, file_path);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_PATH]) == SQLITE_ROW)
    {
        entry = fim_db_decode_full_row(fim_sql->stmt[FIMDB_STMT_GET_PATH]);
    }

    return entry;
}

fim_entry* fim_db_get_path(fdb_t* fim_sql, const char* file_path)
{
    fim_entry* entry = NULL;

    /* TODO: Add c++ code to manage this function 
    */

    return entry;
}

char** fim_db_get_paths_from_inode(fdb_t* fim_sql, unsigned long int inode, unsigned long int dev)
{
    char** paths = NULL;

    /* TODO: Add c++ code to manage this function 
    */
    
    return paths;
}

int fim_db_insert_entry(fdb_t* fim_sql, const char* file_path, const fim_file_data* entry)
{
     /* TODO: Add c++ code to insert a file from a fim_file_data to DB 
    */

    return FIMDB_OK;
}

int fim_db_remove_path(fdb_t* fim_sql, const char* path)
{
    int state = FIMDB_ERR;

    /* TODO: Add c++ code to delete a file from DB 
    */
    return state;
}

int fim_db_set_all_unscanned(fdb_t* fim_sql)
{
    int retval;
    /* TODO: Add c++ code to implement set all unscanned in DB 
    */
    return retval;
}

int fim_db_set_scanned(fdb_t* fim_sql, const char* path)
{
    /* TODO: Add c++ code to implement set scanned in DB 
    */

    return FIMDB_OK;
}

void fim_db_remove_validated_path(fdb_t* fim_sql,
                                  fim_entry* entry,
                                  pthread_mutex_t* mutex,
                                  void* evt_data,
                                  void* configuration,
                                  __attribute__((unused)) void* _unused_patameter)
{
    int res = 0;
    /* TODO: Add c++ code to implement fim_db_get_count 
    */
    return res;
}

int fim_db_get_count_file_entry(fdb_t* fim_sql)
{
    int res = 0;
    /* TODO: Add c++ code to implement fim_db_get_count 
    */
    return res;
}

int fim_db_get_path_from_pattern(fdb_t* fim_sql, const char* pattern, fim_tmp_file** file, int storage)
{
    int ret = 0;
    /* TODO: Add c++ code to get some files from a pattern in DB 
    */
    return ret;
}

int fim_db_file_update(fdb_t* fim_sql, const char* path, const fim_file_data* data, fim_entry** saved)
{
    int retval;
    /* TODO: Add c++ code to update a file in DB 
    */
    return retval;
}
#ifdef __cplusplus
}
#endif
