/**
 * @file fim_db_registries.h
 * @brief Definition of FIM database for registries library.
 * @date 2020-09-9
 *
 * @copyright Copyright (c) 2020 Wazuh, Inc.
 */

#ifndef FIM_DB_REGISTRIES_H
#define FIM_DB_REGISTRIES_H

#ifdef WIN32

#include "fim_db.h"

/**
 * @brief Read registry data that are stored in a temporal storage.
 *
 * @param fim_sql FIM database structure.
 * @param file Structure of the file which contains all the key ids and value names.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param callback Function to call within a step.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param alert False don't send alert, True send delete alert.
 * @param mode FIM mode for callback function.
 * @param w_evt Whodata information for callback function.
 *
 */
int fim_db_process_read_registry_data_file(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex,
                                           void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
                                           int storage, void * alert, void * mode, void * w_evt);

// Registry callbacks

/**
 * @brief Write an entry path into the storage pointed by @args.
 *
 * @param fim_sql FIM database struct.
 * @param entry Registry value data to be saved.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param arg Storage which contains all the paths.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
void fim_db_callback_save_reg_data_name(fdb_t *fim_sql, fim_entry *entry, int storage, void *arg);

// Registry functions.

/**
 * @brief Get checksum of all registry key.
 *
 * @param fim_sql FIM database struct.
 * @param arg CTX object.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_key_checksum(fdb_t *fim_sql, void * arg);

/**
 * @brief Get checksum of all registry data.
 *
 * @param fim_sql FIM database struct.
 * @param arg CTX object.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_data_checksum(fdb_t *fim_sql, void * arg);

/**
 * @brief Get the rowid of a key path.
 * @param fim_sql FIM database struct
 * @param path Path of the key to look for
 * @param rowid Variable where the rowid will be stored
 * @param arch Architecture of the registry
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_key_rowid(fdb_t *fim_sql, const char *path, unsigned int arch, unsigned int *rowid);

/**
 * @brief Get registry data using its key_id and name.
 *
 * @param fim_sql FIM database struct.
 * @param key_id ID of the registry.
 * @param name Name of the registry value.
 *
 * @return FIM registry data struct on success, NULL on error.
 */
fim_registry_value_data *fim_db_get_registry_data(fdb_t *fim_sql, unsigned int key_id, const char *name);

/**
 * @brief Get all the key paths
 *
 * @param fim_sql FIM databse struct.
 * @param key_id key_id of the registry data table.
 *
 * @return char** An array of the paths asociated to the key_id.
 */
char **fim_db_get_all_registry_key(fdb_t *fim_sql, unsigned long int key_id);

/**
 * @brief Insert or update registry data.
 *
 * @param fim_sql FIM database struct.
 * @param data Registry data to be inserted.
 * @param key_id Registry key ID.
 * @param replace_entry 0 if a new registry_data entry is being inserted.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_registry_data(fdb_t *fim_sql,
                                fim_registry_value_data *data,
                                unsigned int key_id,
                                unsigned int replace_entry);

/**
 * @brief Insert or update registry key.
 *
 * @param fim_sql FIM database struct.
 * @param entry Registry key to be inserted.
 * @param rowid Row id of the registry.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_registry_key(fdb_t *fim_sql, fim_registry_key *entry, unsigned int rowid);

/**
 * @brief Insert a registry entry in the needed tables.
 *
 * @param fim_sql FIM database struct.
 * @param new FIM entry data.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_registry(fdb_t *fim_sql, fim_entry *new);

/**
 * @brief Calculate checksum of registry keys between @start and @top.
 *
 * Said range will be split into two and the resulting checksums will
 * be sent as sync messages.
 *
 * @param fim_sql FIM database struct
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param id Sync session counter (timetamp).
 * @param n Number of entries between start and stop.
 * @param mutex FIM database's mutex for thread synchronization.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_registry_key_checksum_range(fdb_t *fim_sql, const char *start, const char *top,
                                       long id, int n, pthread_mutex_t *mutex);

/**
 * @brief Count the number of entries between range @start and @top.
 *
 * @param fim_sql FIM database struct
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param counter Pointer which will hold the final count.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_key_count_range(fdb_t *fim_sql, char *start, char *top, int *counter);

/**
 * @brief Count the number of registry data entries between range @start and @top.
 *
 * @param fim_sql FIM database struct
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param counter Pointer which will hold the final count.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */

int fim_db_get_registry_data_count_range(fdb_t *fim_sql, const char *start, const char *top, int *counter);

/**
 * @brief Get the last/first row from registry_key table.
 *
 * @param fim_sql FIM database struct
 * @param mode FIM_FIRST_ROW or FIM_LAST_ROW.
 * @param path pointer of pointer where the path will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_row_registry_key(fdb_t *fim_sql, int mode, char **path);

/**
 * @brief Get the last/first row from registry_data table.
 *
 * @param fim_sql FIM database struct
 * @param mode FIM_FIRST_ROW or FIM_LAST_ROW.
 * @param path pointer of pointer where the path will be stored.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_row_registry_data(fdb_t *fim_sql, int mode, char **path);

/**
 * @brief Set all entries from registry_key table to unscanned.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_registry_key_unscanned(fdb_t *fim_sql);

/**
 * @brief Set all entries from registry_data table to unscanned.
 *
 * @param fim_sql FIM database struct.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_all_registry_data_unscanned(fdb_t *fim_sql);

/**
 * @brief Set a registry key as scanned.
 *
 * @param fim_sql FIM database struct.
 * @param path Registry key path.
 * @param arch Architecture of the registry
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_registry_key_scanned(fdb_t *fim_sql, const char *path, unsigned int arch);

/**
 * @brief Set a registry data as scanned.
 *
 * @param fim_sql FIM database struct.
 * @param name Value name.
 * @param key_id key_id of the registry data table.
 * @param file_path File path.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_set_registry_data_scanned(fdb_t *fim_sql, const char *name, unsigned int key_id);

/**
 * @brief Get all the unscanned registries keys by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_keys_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage);

/**
 * @brief Get all the unscanned registries values by saving them in a temporal storage.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_registry_data_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage);

/**
 * @brief Get count of all entries in registry data table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in registry data table.
 */
int fim_db_get_count_registry_data(fdb_t *fim_sql);

/**
 * @brief Get count of all entries in registry key table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in registry data table.
 */
int fim_db_get_count_registry_key(fdb_t *fim_sql);

/**
 * @brief Get registry keys between @start and @top. (stored in @file).
 *
 * @param fim_sql FIM database struct.
 * @param start First entry of the range.
 * @param top Last entry of the range.
 * @param file  Structure of the storage which contains all the paths.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 *
 */
int fim_db_get_registry_value_range(fdb_t *fim_sql, const char *start, const char *top, fim_tmp_file **file,
                                    int storage);

/**
 * @brief Removes a range of registry keys from the database.
 * The key paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_registry_key_range(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage);

/**
 * @brief Removes a range of registry data from the database.
 * The key paths are alphabetically ordered.
 * The range is given by start and top parameters.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_delete_registry_value_range(fdb_t * fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage);
/**
 * @brief Remove a range of registry keys from database if they have a
 * specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mode FIM mode (scheduled, realtime or whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_registry_key_entry(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage,
                                              fim_event_mode mode, whodata_evt * w_evt);

/**
 * @brief Remove a range of registry data from database if they have a
 * specific monitoring mode.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param mutex FIM database's mutex for thread synchronization.
 * @param storage 1 Store database in memory, disk otherwise.
 * @param mode FIM mode (scheduled, realtime or whodata)
 * @param w_evt Whodata information
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_process_missing_registry_data_entry(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex, int storage,
                                               fim_event_mode mode, whodata_evt * w_evt);


/**
 * @brief Get count of all entries in registry key and registry data table.
 *
 * @param fim_sql FIM database struct.
 *
 * @return Number of entries in registry key table.
 */
int fim_db_get_count_registry_key_data(fdb_t *fim_sql);

/**
 * @brief Delete registry using registry entry.
 *
 * @param fim_sql FIM database struct.
 * @param entry Registry entry.
 */
int fim_db_remove_registry_key(fdb_t *fim_sql, fim_entry *entry);

/**
 * @brief Delete registry data using fim_registry_value_data entry.
 *
 * @param fim_sql FIM database struct.
 * @param entry fim_registry_value_data entry.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_remove_registry_value_data(fdb_t *fim_sql, fim_registry_value_data *entry);

/**
 * @brief Get a registry using it's id.
 *
 * @param fim_sql FIM database struct.
 * @param id Id of the registry key
 *
 * @return fim_registry_key structure.
 */
fim_registry_key *fim_db_get_registry_key_using_id(fdb_t *fim_sql, unsigned int id);

/**
 * @brief Get all registry values from given id.
 *
 * Given an id, save in a fim_tmp_file all its values.
 *
 * @param fim_sql FIM database struct.
 * @param file Structure of the file which contains all the paths.
 * @param storage Type of storage (memory or disk).
 * @param key_id Key id of the values.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_get_values_from_registry_key(fdb_t * fim_sql, fim_tmp_file **file, int storage, unsigned long int key_id);

/**
 * @brief Decodes a row from the database to be saved in a fim_registry_key structure.
 *
 * @param stmt The statement to be decoded.
 *
 * @return fim_registry_key* The filled structure.
 */
fim_registry_key *fim_db_decode_registry_key(sqlite3_stmt *stmt);

/**
 * @brief Decodes a row from the database to be saved in a fim_registry_value_data structure.
 *
 * @param stmt The statement to be decoded.
 *
 * @return fim_registry_value_data* The filled structure.
 */
fim_registry_value_data * fim_db_decode_registry_value(sqlite3_stmt *stmt);

/**
 * @brief Decodes a row from the registry database to be saved in a registry key structure.
 *
 * @param stmt The statement to be decoded.
 * @param index Index of the statement.
 *
 * @return fim_entry* The filled structure.
 */
fim_entry *fim_db_decode_registry(int index, sqlite3_stmt *stmt);

#endif /* WIN32 */
#endif /* FIM_DB_REGISTRIES_H */
