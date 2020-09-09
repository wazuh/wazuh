/**
 * @file fim_db_registries.c
 * @brief Definition of FIM database for registries library.
 * @date 2020-09-9
 *
 * @copyright Copyright (c) 2020 Wazuh, Inc.
 */

#include "fim_db_registries.h"

extern const char *SQL_STMT[];

/**
 * @brief Binds name and key_id to a statement
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param name Registry name.
 * @param key_id Key id of the registry.
*/
static void fim_db_bind_registry_data_name_key_id(fdb_t *fim_sql, int index, char *name, int key_id);


/**
 * @brief Binds path into registry statement
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param path Path to registry.
*/
static void fim_db_bind_delete_registry_data_path(fdb_t *fim_sql, int index, char *path);


/**
 * @brief Binds start and top paths into select range statements
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param start First entry of the range.
 * @param top Last entry of the range.
*/
static void fim_db_bind_registry_path_range(fdb_t *fim_sql, int index, char *start, char *top);

/**
 * @brief Bind registry data into an insert registry data statement
 *
 * @param fim_sql FIM database structure.
 * @param data Structure that contains the fields of the inserted data.
 * @param key_id Identifier of the key.
 */
static void fim_db_bind_insert_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, unsigned int key_id);

/**
 * @brief Bind registry data into an insert registry key statement
 *
 * @param fim_sql FIM database structure.
 * @param registry_key Structure that contains the fields of the inserted key.
 * @param rowid Row identifier.
 */
static void fim_db_bind_insert_registry_key(fdb_t *fim_sql, fim_registry_key *registry_key, unsigned int rowid);

/**
 * @brief Bind registry data into a update registry data statement
 *
 * @param fim_sql FIM database structure.
 * @param data Registy data structure with that will be updated.
 * @param key_id Identifier of the registry key.
 */
static void fim_db_bind_update_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, unsigned int key_id);

/**
 * @brief Bind registry key into a update registry data statement
 *
 * @param fim_sql FIM database structure.
 * @param registry_key Structure that will be updated.
 */
static void fim_db_bind_update_registry_key(fdb_t *fim_sql, fim_registry_key *registry_key);

/**
 * @brief Bind rowid into get registry key statement.
 *
 * @param fim_sql FIM database structure.
 * @param rowid Row id of the registry key.
 */
static void fim_db_bind_get_registry_key_rowid(fdb_t *fim_sql, unsigned int rowid);

fim_entry *fim_db_decode_full_reg_row(sqlite3_stmt *stmt) {
    fim_entry *entry = NULL;

    os_calloc(1, sizeof(fim_entry), entry);
    os_calloc(1, sizeof(fim_registry_key), entry->registry_entry.key);
    os_calloc(1, sizeof(fim_registry_value_data), entry->registry_entry.value);

    entry->type = FIM_TYPE_REGISTRY;
    // Registry key
    os_strdup((char *)sqlite3_column_text(stmt, 0), entry->registry_entry.key->path);
    // skip data_id
    sqlite_strdup((char *)sqlite3_column_text(stmt, 2), entry->registry_entry.key->perm);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 3), entry->registry_entry.key->uid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 4), entry->registry_entry.key->gid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 5), entry->registry_entry.key->user_name);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 6), entry->registry_entry.key->group_name);
    entry->registry_entry.key->scanned = (unsigned int)sqlite3_column_int(stmt, 7);
    strncpy(entry->registry_entry.key->checksum, (char *)sqlite3_column_text(stmt, 8), sizeof(os_sha1) - 1);
    // Registry data
    entry->registry_entry.value->id = (unsigned int)sqlite3_column_int(stmt, 9);
    os_strdup((char *)sqlite3_column_text(stmt, 9), entry->registry_entry.value->name);
    entry->registry_entry.value->type = (unsigned int)sqlite3_column_int(stmt, 10);
    entry->registry_entry.value->scanned = (unsigned int)sqlite3_column_int(stmt, 11);
    strncpy(entry->registry_entry.value->checksum, (char *)sqlite3_column_text(stmt, 12), sizeof(os_sha1) - 1);
    entry->registry_entry.value->last_event = (time_t)sqlite3_column_int(stmt, 13);
    strncpy(entry->registry_entry.value->hash_md5, (char *)sqlite3_column_text(stmt, 15), sizeof(os_md5) - 1);
    strncpy(entry->registry_entry.value->hash_sha1, (char *)sqlite3_column_text(stmt, 16), sizeof(os_sha1) - 1);
    strncpy(entry->registry_entry.value->hash_sha256, (char *)sqlite3_column_text(stmt, 17), sizeof(os_sha256) - 1);
    return entry;
}

// Registry callbacks

void fim_db_callback_save_reg_data_name(__attribute__((unused))fdb_t * fim_sql, fim_entry *entry, int storage, void *arg) {
    if (entry->type == FIM_TYPE_REGISTRY) {
        return ;
    }

    char *base = wstr_escape_json(entry->registry_entry.value->name);
    if (base == NULL) {
        merror("Error escaping '%s'", entry->registry_entry.value->name);
        return;
    }

    if (storage == FIM_DB_DISK) { // disk storage enabled
        if ((size_t)fprintf(((fim_tmp_file *) arg)->fd, "%s\n", base) != (strlen(base) + sizeof(char))) {
            merror("%s - %s", entry->registry_entry.value->name, strerror(errno));
            goto end;
        }

        fflush(((fim_tmp_file *) arg)->fd);

    } else {
        W_Vector_insert(((fim_tmp_file *) arg)->list, base);
    }

    ((fim_tmp_file *) arg)->elements++;

end:
    os_free(base);

}

// Registry functions
int fim_db_set_all_registry_data_unscanned(fdb_t *fim_sql) {

    int retval = fim_db_exec_simple_wquery(fim_sql, SQL_STMT[FIMDB_STMT_SET_ALL_REG_DATA_UNSCANNED]);
    fim_db_check_transaction(fim_sql);
    return retval;
}

int fim_db_set_all_registry_key_unscanned(fdb_t *fim_sql) {

    int retval = fim_db_exec_simple_wquery(fim_sql, SQL_STMT[FIMDB_STMT_SET_ALL_REG_KEY_UNSCANNED]);
    fim_db_check_transaction(fim_sql);
    return retval;
}

int fim_db_set_registry_key_scanned(fdb_t *fim_sql, char *path) {
    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_SET_REG_KEY_SCANNED);
    fim_db_bind_delete_registry_data_path(fim_sql, FIMDB_STMT_SET_REG_KEY_SCANNED, path);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_SET_REG_KEY_SCANNED]) != SQLITE_DONE) {
        merror("Step error setting scanned key path '%s': %s", path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

int fim_db_set_registry_data_scanned(fdb_t *fim_sql, char *name, unsigned int key_rowid) {
    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_SET_REG_DATA_SCANNED);
    fim_db_bind_registry_data_name_key_id(fim_sql, FIMDB_STMT_SET_REG_DATA_SCANNED, name, key_rowid);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_SET_REG_DATA_SCANNED]) != SQLITE_DONE) {
        merror("Step error setting scanned data name '%s': %s", name, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

int fim_db_get_registry_keys_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage){
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    int ret = fim_db_process_get_query(fim_sql, FIM_TYPE_REGISTRY, FIMDB_STMT_GET_REG_KEY_NOT_SCANNED,
                                       fim_db_callback_save_path, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

int fim_db_get_registry_data_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    int ret = fim_db_process_get_query(fim_sql, FIM_TYPE_REGISTRY, FIMDB_STMT_GET_REG_DATA_NOT_SCANNED,
                                       fim_db_callback_save_reg_data_name, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

int fim_db_delete_registry_keys_not_scanned(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {

}

int fim_db_delete_registry_data_not_scanned(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage) {}

int fim_db_get_registry_keys_range(fdb_t *fim_sql, char *start, char *top, fim_tmp_file **file, int storage) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_PATH_RANGE);
    fim_db_bind_range(fim_sql, FIMDB_STMT_GET_REG_PATH_RANGE, start, top);

    int ret = fim_db_process_get_query(fim_sql, FIM_TYPE_REGISTRY, FIMDB_STMT_GET_REG_PATH_RANGE,
                                       fim_db_callback_save_reg_data_name, storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

int fim_db_get_count_registry_key(fdb_t *fim_sql) {
    int res = fim_db_get_count(fim_sql, FIMDB_STMT_GET_COUNT_REG_KEY);

    if(res == FIMDB_ERR) {
        merror("Step error getting count registry key: %s", sqlite3_errmsg(fim_sql->db));
    }
    return res;
}

int fim_db_get_count_registry_data(fdb_t *fim_sql) {
    int res = fim_db_get_count(fim_sql, FIMDB_STMT_GET_COUNT_REG_DATA);

    if(res == FIMDB_ERR) {
        merror("Step error getting count registry data: %s", sqlite3_errmsg(fim_sql->db));
    }
    return res;
}

int fim_db_insert_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, int key_rowid) {
    int res = 0;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_REPLACE_REG_DATA);
    fim_db_bind_insert_registry_data(fim_sql, data, key_rowid);

    if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA]), res != SQLITE_DONE) {
        merror("Step error replacing registry data '%d': %s", key_rowid, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_insert_registry_key(fdb_t *fim_sql, fim_registry_key *entry) {
    int res = 0;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_REPLACE_REG_KEY);
    fim_db_bind_insert_registry_key(fim_sql, entry);

    if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY]), res != SQLITE_DONE) {
        merror("Step error replacing registry key '%s': %s", entry->path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_insert_registry(fdb_t *fim_sql, int key_rowid, fim_entry *new) {
    int res_data = 0;
    int res_key = 0;

    res_data = fim_db_insert_registry_data(fim_sql, new->registry_entry.value, key_rowid);
    res_key = fim_db_insert_registry_key(fim_sql, new->registry_entry.key);

    return res_data || res_key;
}

// Registry sql queries bindings
static void fim_db_bind_registry_data_name_key_id(fdb_t *fim_sql, int index, char *name, int key_id) {
    if (index == FIMDB_STMT_SET_REG_DATA_UNSCANNED ||
        index == FIMDB_STMT_DELETE_REG_DATA ||
        index == FIMDB_STMT_SET_REG_KEY_SCANNED ||
        index == FIMDB_STMT_GET_REG_DATA) {
        sqlite3_bind_text(fim_sql->stmt[index], 1, name, -1, NULL);
        sqlite3_bind_int(fim_sql->stmt[index], 2, key_id);
    }
}

static void fim_db_bind_delete_registry_data_path(fdb_t *fim_sql, int index, char *path) {
    if (index == FIMDB_STMT_GET_REG_KEY ||
        index == FIMDB_STMT_SET_REG_KEY_UNSCANNED ||
        index == FIMDB_STMT_GET_REG_ROWID ||
        index == FIMDB_STMT_DELETE_REG_KEY_PATH ||
        index == FIMDB_STMT_DELETE_REG_DATA_PATH ||
        index == FIMDB_STMT_SET_REG_DATA_SCANNED) {

        sqlite3_bind_text(fim_sql->stmt[index], 1, path, -1, NULL);
    }
}

static void fim_db_bind_registry_path_range(fdb_t *fim_sql, int index, char *start, char *top) {
    if (index == FIMDB_STMT_GET_REG_COUNT_RANGE ||
        index == FIMDB_STMT_GET_REG_PATH_RANGE) {
        sqlite3_bind_text(fim_sql->stmt[index], 1, start, -1, NULL);
        sqlite3_bind_text(fim_sql->stmt[index], 2, top, -1, NULL);
    }
}

static void fim_db_bind_insert_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, unsigned int key_id) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 1, key_id);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 2, data->name, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 3, data->type);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 4, data->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 5, data->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 6, data->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 7, data->scanned);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 8, data->checksum, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 9, data->last_event);
}

static void fim_db_bind_insert_registry_key(fdb_t *fim_sql, fim_registry_key *registry_key, unsigned int rowid) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 1, registry_key->path, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 2, registry_key->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 3, registry_key->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 4, registry_key->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 5, registry_key->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 6, registry_key->group_name, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 7, registry_key->scanned);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 8, registry_key->checksum, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 9, registry_key->arch);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 10, rowid);
}

static void fim_db_bind_update_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, unsigned int key_id) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 1, data->type);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 2, data->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 3, data->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 4, data->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 5, data->scanned);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 6, data->checksum, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 7, data->last_event);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 8, key_id);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_DATA], 9, data->name, -1, NULL);
}

static void fim_db_bind_update_registry_key(fdb_t *fim_sql, fim_registry_key *registry_key) {
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 1, registry_key->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 2, registry_key->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 3, registry_key->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 4, registry_key->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 5, registry_key->group_name, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 6, registry_key->scanned);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 7, registry_key->checksum, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_UPDATE_REG_KEY], 8, registry_key->path, -1, NULL);
}

static void fim_db_bind_get_registry_key_rowid(fdb_t *fim_sql, unsigned int rowid) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY_ROWID], 1, rowid);
}
