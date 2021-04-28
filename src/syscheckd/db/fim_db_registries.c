/**
 * @file fim_db_registries.c
 * @brief Definition of FIM database for registries library.
 * @date 2020-09-9
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifdef WIN32
#include "fim_db_registries.h"

extern const char *SQL_STMT[];

const char *registry_arch[] = {
    [ARCH_32BIT] = "[x32]",
    [ARCH_64BIT] = "[x64]"
};

/**
 * @brief Binds name and key_id to a statement
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param name Registry name.
 * @param key_id Key id of the registry.
*/
static void fim_db_bind_registry_data_name_key_id(fdb_t *fim_sql, int index, const char *name, int key_id);


/**
 * @brief Binds path into registry statement
 *
 * @param fim_sql FIM database structure.
 * @param index Index of the particular statement.
 * @param path Path to registry.
 * @param arch architecture of the registry
*/
static void fim_db_bind_registry_path(fdb_t *fim_sql, unsigned int index, const char *path, unsigned int arch);

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
 * @param id Registry key identifier.
 */
static void fim_db_bind_insert_registry_key(fdb_t *fim_sql, fim_registry_key *registry_key, unsigned int id);

/**
 * @brief Bind id into get registry key statement.
 *
 * @param fim_sql FIM database structure.
 * @param id ID of the registry key.
 */
static void fim_db_bind_get_registry_key_id(fdb_t *fim_sql, unsigned int id);

/**
 * @brief Bind id into get registry value statement.
 *
 * @param fim_sql FIM database structure.
 * @param key_id ID of the registry key.
 */
static void fim_db_bind_get_registry_data_key_id(fdb_t *fim_sql, unsigned int key_id);

// Registry sql queries bindings
static void fim_db_bind_registry_data_name_key_id(fdb_t *fim_sql, int index, const char *name, int key_id) {
    if (index == FIMDB_STMT_SET_REG_DATA_UNSCANNED ||
        index == FIMDB_STMT_DELETE_REG_DATA ||
        index == FIMDB_STMT_SET_REG_DATA_SCANNED ||
        index == FIMDB_STMT_GET_REG_DATA) {

        sqlite3_bind_text(fim_sql->stmt[index], 1, name, -1, NULL);
        sqlite3_bind_int(fim_sql->stmt[index], 2, key_id);
    }
}

static void fim_db_bind_registry_path(fdb_t *fim_sql, unsigned int index, const char *path, unsigned int arch) {
    if (index == FIMDB_STMT_GET_REG_KEY ||
        index == FIMDB_STMT_SET_REG_KEY_UNSCANNED ||
        index == FIMDB_STMT_GET_REG_ROWID ||
        index == FIMDB_STMT_DELETE_REG_KEY_PATH ||
        index == FIMDB_STMT_DELETE_REG_DATA_PATH ||
        index == FIMDB_STMT_SET_REG_KEY_SCANNED) {

        sqlite3_bind_text(fim_sql->stmt[index], 1, path, -1, NULL);
        sqlite3_bind_text(fim_sql->stmt[index], 2, registry_arch[arch], -1, NULL);
    }
}

static void fim_db_bind_insert_registry_data(fdb_t *fim_sql, fim_registry_value_data *data, unsigned int key_id) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 1, key_id);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 2, data->name, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 3, data->type);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 4, data->size);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 5, data->hash_md5, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 6, data->hash_sha1, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 7, data->hash_sha256, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 8, data->scanned);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 9, data->last_event);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA], 10, data->checksum, -1, NULL);
}

static void fim_db_bind_insert_registry_key(fdb_t *fim_sql, fim_registry_key *registry_key, unsigned int id) {
    if (id == 0) {
        sqlite3_bind_null(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 1);
    } else {
        sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 1, id);
    }
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 2, registry_key->path, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 3, registry_key->perm, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 4, registry_key->uid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 5, registry_key->gid, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 6, registry_key->user_name, -1, NULL);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 7, registry_key->group_name, -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 8, registry_key->mtime);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 9, registry_arch[registry_key->arch], -1, NULL);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 10, registry_key->scanned);
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 11, registry_key->last_event);
    sqlite3_bind_text(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY], 12, registry_key->checksum, -1, NULL);
}

static void fim_db_bind_get_registry_key_id(fdb_t *fim_sql, unsigned int id) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY_ROWID], 1, id);
}

static void fim_db_bind_get_registry_data_key_id(fdb_t *fim_sql, unsigned int key_id) {
    sqlite3_bind_int(fim_sql->stmt[FIMDB_STMT_GET_REG_DATA_ROWID], 1, key_id);
}

int fim_db_remove_registry_key(fdb_t *fim_sql, fim_entry *entry) {

    if (entry->type != FIM_TYPE_REGISTRY) {
        return FIMDB_ERR;
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_REG_DATA_PATH);
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_REG_KEY_PATH);
    fim_db_bind_registry_path(fim_sql, FIMDB_STMT_DELETE_REG_DATA_PATH, entry->registry_entry.key->path,
                              entry->registry_entry.key->arch);
    fim_db_bind_registry_path(fim_sql, FIMDB_STMT_DELETE_REG_KEY_PATH, entry->registry_entry.key->path,
                              entry->registry_entry.key->arch);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_REG_DATA_PATH]) != SQLITE_DONE) {
        merror("Step error deleting data value from key '%s': %s", entry->registry_entry.key->path,
               sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_REG_KEY_PATH]) != SQLITE_DONE) {
        merror("Step error deleting key path '%s': %s", entry->registry_entry.key->path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

int fim_db_remove_registry_value_data(fdb_t *fim_sql, fim_registry_value_data *entry) {
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_DELETE_REG_DATA);
    fim_db_bind_registry_data_name_key_id(fim_sql, FIMDB_STMT_DELETE_REG_DATA, entry->name, entry->id);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_DELETE_REG_DATA]) != SQLITE_DONE) {
        merror("Step error deleting entry name '%s': %s", entry->name, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

fim_registry_key *fim_db_decode_registry_key(sqlite3_stmt *stmt) {
    fim_registry_key *entry;
    os_calloc(1, sizeof(fim_registry_key), entry);

    entry->id = (unsigned int)sqlite3_column_int(stmt, 0);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 1), entry->path);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 2), entry->perm);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 3), entry->uid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 4), entry->gid);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 5), entry->user_name);
    sqlite_strdup((char *)sqlite3_column_text(stmt, 6), entry->group_name);
    entry->mtime = (unsigned int)sqlite3_column_int(stmt, 7);
    entry->arch = strcmp((char *)sqlite3_column_text(stmt, 8), "[x64]") == 0 ? ARCH_64BIT : ARCH_32BIT;
    entry->scanned = (unsigned int)sqlite3_column_int(stmt, 9);
    entry->last_event = sqlite3_column_int(stmt, 10);
    strncpy(entry->checksum, (char *)sqlite3_column_text(stmt, 11), sizeof(os_sha1) - 1);

    return entry;
}

fim_registry_value_data *_fim_db_decode_registry_value(sqlite3_stmt *stmt, int offset) {
    fim_registry_value_data *entry;
    os_calloc(1, sizeof(fim_registry_value_data), entry);

    entry->id = (unsigned int)sqlite3_column_int(stmt, offset + 0);
    sqlite_strdup((char *)sqlite3_column_text(stmt, offset + 1), entry->name);
    entry->type = (unsigned int)sqlite3_column_int(stmt, offset + 2);
    entry->size = (unsigned int)sqlite3_column_int(stmt, offset + 3);
    strncpy(entry->hash_md5, (char *)sqlite3_column_text(stmt, offset + 4), sizeof(os_md5) - 1);
    strncpy(entry->hash_sha1, (char *)sqlite3_column_text(stmt, offset + 5), sizeof(os_sha1) - 1);
    strncpy(entry->hash_sha256, (char *)sqlite3_column_text(stmt, offset + 6), sizeof(os_sha256) - 1);
    entry->scanned = (unsigned int)sqlite3_column_int(stmt, offset + 7);
    entry->last_event = (unsigned int)sqlite3_column_int(stmt, offset + 8);
    strncpy(entry->checksum, (char *)sqlite3_column_text(stmt, offset + 9), sizeof(os_sha1) - 1);

    return entry;
}

fim_registry_value_data * fim_db_decode_registry_value(sqlite3_stmt *stmt) {
    return _fim_db_decode_registry_value(stmt, 0);
}

fim_entry *fim_db_decode_registry(int index, sqlite3_stmt *stmt) {
    fim_entry *entry = NULL;

    os_calloc(1, sizeof(fim_entry), entry);

    entry->type = FIM_TYPE_REGISTRY;
    entry->registry_entry.key = NULL;
    entry->registry_entry.value = NULL;

    // Registry key
    if (index == FIMDB_STMT_GET_REG_KEY_NOT_SCANNED ||
        index == FIMDB_STMT_GET_REG_KEY_ROWID ||
        index == FIMDB_STMT_GET_REG_KEY) {

        entry->registry_entry.key = fim_db_decode_registry_key(stmt);
    }

    if (index == FIMDB_STMT_GET_REG_DATA || index == FIMDB_STMT_GET_REG_DATA_NOT_SCANNED) {
        entry->registry_entry.value = fim_db_decode_registry_value(stmt);
    }

    return entry;
}

// Registry callbacks

void fim_db_callback_save_reg_data_name(__attribute__((unused))fdb_t * fim_sql, fim_entry *entry, int storage,
                                        void *arg) {
    int length;
    if (entry->type != FIM_TYPE_REGISTRY || entry->registry_entry.value == NULL) {
        return ;
    }

    char *base = wstr_escape_json(entry->registry_entry.value->name);
    char *buffer = NULL;

    if (base == NULL) {
        merror("Error escaping '%s'", entry->registry_entry.value->name);
        goto end;
    }

    length = snprintf(NULL, 0, "%d %s", entry->registry_entry.value->id, base) + 1;

    os_malloc(length, buffer);

    snprintf(buffer, length, "%d %s", entry->registry_entry.value->id, base);

    if (storage == FIM_DB_DISK) { // disk storage enabled
        if (fprintf(((fim_tmp_file *) arg)->fd, "%032ld%s\n", (unsigned long)(length), buffer) < 0) {
            merror("Can't save entry: %s %s", entry->registry_entry.value->name, strerror(errno));
            goto end;
        }

        fflush(((fim_tmp_file *) arg)->fd);

    } else {
        W_Vector_insert(((fim_tmp_file *) arg)->list, buffer);
    }

    ((fim_tmp_file *) arg)->elements++;

end:
    os_free(base);
    os_free(buffer);
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

int fim_db_set_registry_key_scanned(fdb_t *fim_sql, const char *path, unsigned int arch) {
    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_SET_REG_KEY_SCANNED);
    fim_db_bind_registry_path(fim_sql, FIMDB_STMT_SET_REG_KEY_SCANNED, path, arch);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_SET_REG_KEY_SCANNED]) != SQLITE_DONE) {
        merror("Step error setting scanned key path '%s': %s", path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

int fim_db_set_registry_data_scanned(fdb_t *fim_sql, const char *name, unsigned int key_id) {
    // Clean and bind statements
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_SET_REG_DATA_SCANNED);
    fim_db_bind_registry_data_name_key_id(fim_sql, FIMDB_STMT_SET_REG_DATA_SCANNED, name, key_id);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_SET_REG_DATA_SCANNED]) != SQLITE_DONE) {
        merror("Step error setting scanned data name '%s': %s", name, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    fim_db_check_transaction(fim_sql);

    return FIMDB_OK;
}

int fim_db_get_registry_key_rowid(fdb_t *fim_sql, const char *path, unsigned int arch, unsigned int *rowid) {
    int res;
    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_ROWID);
    fim_db_bind_registry_path(fim_sql, FIMDB_STMT_GET_REG_ROWID, path, arch);

    res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_REG_ROWID]);

    if (res == SQLITE_ROW) {
        *rowid = sqlite3_column_int(fim_sql->stmt[FIMDB_STMT_GET_REG_ROWID], 0);
    }
    else if (res == SQLITE_DONE) {
        mdebug2("Key %s not found in DB", path);
        *rowid = 0;
    }
    else {
        merror("Step error getting registry rowid %s: %s", path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_get_registry_keys_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage) {
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

fim_registry_value_data *fim_db_get_registry_data(fdb_t *fim_sql, unsigned int key_id, const char *name) {
    fim_registry_value_data *value = NULL;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_DATA);
    fim_db_bind_registry_data_name_key_id(fim_sql, FIMDB_STMT_GET_REG_DATA, name, key_id);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_REG_DATA]) == SQLITE_ROW) {
        value = fim_db_decode_registry_value(fim_sql->stmt[FIMDB_STMT_GET_REG_DATA]);
    }

    return value;
}

fim_registry_key *fim_db_get_registry_key(fdb_t *fim_sql, const char *path, unsigned int arch) {
    fim_registry_key *reg_key = NULL;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_KEY);
    fim_db_bind_registry_path(fim_sql, FIMDB_STMT_GET_REG_KEY, path, arch);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY]) == SQLITE_ROW) {
        reg_key = fim_db_decode_registry_key(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY]);
    }

    return reg_key;
}

fim_registry_key *fim_db_get_registry_key_using_id(fdb_t *fim_sql, unsigned int id) {
    fim_registry_key *reg_key = NULL;

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_KEY_ROWID);
    fim_db_bind_get_registry_key_id(fim_sql, id);

    if (sqlite3_step(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY_ROWID]) == SQLITE_ROW) {
        reg_key = fim_db_decode_registry_key(fim_sql->stmt[FIMDB_STMT_GET_REG_KEY_ROWID]);
    }

    return reg_key;
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

int fim_db_insert_registry_data(fdb_t *fim_sql,
                                fim_registry_value_data *data,
                                unsigned int key_id,
                                unsigned int replace_entry) {
    int res = 0;

    // Check there is room in the DB in case of insertion.
    if (syscheck.file_limit_enabled && replace_entry == 0) {
        int count = fim_db_get_count_entries(syscheck.database);

        if (count == FIMDB_ERR) {
            mdebug1("Failed to get count of entries while inserting '%s'", data->name);
            return FIMDB_ERR;
        }

        if (count >= syscheck.file_limit) {
            mdebug1("Couldn't insert '%s' value entry into DB. The DB is full, please check your configuration.",
                    data->name);
            return FIMDB_FULL;
        }
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_REPLACE_REG_DATA);
    fim_db_bind_insert_registry_data(fim_sql, data, key_id);

    if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_DATA]), res != SQLITE_DONE) {
        merror("Step error replacing registry data '%d': %s", key_id, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_insert_registry_key(fdb_t *fim_sql, fim_registry_key *entry, unsigned int rowid) {
    int res = 0;

    // Check there is room in the DB in case of insertion.
    if (syscheck.file_limit_enabled && rowid == 0) {
        int count = fim_db_get_count_entries(syscheck.database);

        if (count == FIMDB_ERR) {
            mdebug1("Failed to get count of entries while inserting '%s %s'", registry_arch[entry->arch], entry->path);
            return FIMDB_ERR;
        }

        if (count >= syscheck.file_limit) {
            mdebug1("Couldn't insert '%s %s' entry into DB. The DB is full, please check your configuration.",
                    registry_arch[entry->arch], entry->path);
            return FIMDB_FULL;
        }
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_REPLACE_REG_KEY);
    fim_db_bind_insert_registry_key(fim_sql, entry, rowid);

    if (res = sqlite3_step(fim_sql->stmt[FIMDB_STMT_REPLACE_REG_KEY]), res != SQLITE_DONE) {
        merror("Step error replacing registry key '%s': %s", entry->path, sqlite3_errmsg(fim_sql->db));
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_insert_registry(fdb_t *fim_sql, fim_entry *new) {
    int res_data = 0;
    int res_key = 0;
    unsigned int replace_entry = new->registry_entry.key->id == 0 ? 0 : 1;

    res_key = fim_db_insert_registry_key(fim_sql, new->registry_entry.key, new->registry_entry.key->id);
    fim_db_get_registry_key_rowid(fim_sql, new->registry_entry.key->path, new->registry_entry.key->arch,
                                  &new->registry_entry.key->id);
    res_data = fim_db_insert_registry_data(fim_sql, new->registry_entry.value, new->registry_entry.key->id,
                                           replace_entry);

    fim_db_check_transaction(fim_sql);

    return res_data || res_key;
}

int fim_db_get_values_from_registry_key(fdb_t * fim_sql, fim_tmp_file **file, int storage, unsigned long int key_id) {
    if ((*file = fim_db_create_temp_file(storage)) == NULL) {
        return FIMDB_ERR;
    }

    fim_db_clean_stmt(fim_sql, FIMDB_STMT_GET_REG_DATA_ROWID);
    fim_db_bind_get_registry_data_key_id(fim_sql, key_id);

    int ret = fim_db_multiple_row_query(fim_sql, FIMDB_STMT_GET_REG_DATA_ROWID,
                                        FIM_DB_DECODE_TYPE(fim_db_decode_string), free,
                                        FIM_DB_CALLBACK_TYPE(fim_db_callback_save_string), storage, (void*) *file);

    if (*file && (*file)->elements == 0) {
        fim_db_clean_file(file, storage);
    }

    return ret;
}

int fim_db_process_read_registry_data_file(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex,
                                           void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
                                           int storage, void * alert, void * mode, void * w_evt) {

    char *read_line = NULL;
    int id;
    int i;
    char *split;

    for (i = 0; i < file->elements; i++) {
        // Read line has to be: 234(row id of the key) some_reg(name of the registry). Get the rowid and the name
        if(fim_db_read_line_from_file(file, storage, i, &read_line) != 0) {
            fim_db_clean_file(&file, storage);
            return FIMDB_ERR;
        }

        id = strtoul(read_line, &split, 10);
        // Skip if the fields couldn't be extracted.
        if (split == NULL || *split != ' ') {
            mwarn("Temporary path file '%s' is corrupt: wrong line format", file->path);
            os_free(read_line);
            continue;
        }

        fim_entry *entry;
        os_calloc(1, sizeof(fim_entry), entry);
        entry->type = FIM_TYPE_REGISTRY;

        w_mutex_lock(mutex);
        entry->registry_entry.key = fim_db_get_registry_key_using_id(fim_sql, id);
        entry->registry_entry.value = fim_db_get_registry_data(fim_sql, id, (split + 1));
        w_mutex_unlock(mutex);

        if (entry->registry_entry.key != NULL && entry->registry_entry.value != NULL) {
            callback(fim_sql, entry, mutex, alert, mode, w_evt);
        }

        free_entry(entry);
        os_free(read_line);
    }

    fim_db_clean_file(&file, storage);

    return FIMDB_OK;
}

#endif
