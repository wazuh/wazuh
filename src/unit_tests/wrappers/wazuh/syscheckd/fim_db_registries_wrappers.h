#ifndef FIM_DB_REGISTRIES_WRAPPERS_H
#define FIM_DB_REGISTRIES_WRAPPERS_H

#ifdef WIN32
#include "syscheckd/db/fim_db_registries.h"

int __wrap_fim_db_remove_registry_value_data(fdb_t *fim_sql, fim_registry_value_data *entry);

int __wrap_fim_db_get_values_from_registry_key(fdb_t * fim_sql, fim_tmp_file **file, int storage, unsigned long int key_id);

int __wrap_fim_db_process_read_registry_data_file(fdb_t *fim_sql, fim_tmp_file *file, pthread_mutex_t *mutex,
                                           void (*callback)(fdb_t *, fim_entry *, pthread_mutex_t *, void *, void *, void *),
                                           int storage, void * alert, void * mode, void * w_evt);

int __wrap_fim_db_remove_registry_key(fdb_t *fim_sql, fim_entry *entry);

int __wrap_fim_db_get_registry_keys_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage);

int __wrap_fim_db_get_registry_data_not_scanned(fdb_t * fim_sql, fim_tmp_file **file, int storage);

fim_registry_value_data *__wrap_fim_db_get_registry_data(fdb_t *fim_sql, unsigned int key_id, const char *name);

int __wrap_fim_db_insert_registry_data(fdb_t *fim_sql,
                                fim_registry_value_data *data,
                                unsigned int key_id,
                                unsigned int replace_entry);

int __wrap_fim_db_set_registry_data_scanned(fdb_t *fim_sql, const char *name, unsigned int key_id);

int __wrap_fim_db_get_registry_key_rowid(fdb_t *fim_sql, const char *path, unsigned int arch, unsigned int *rowid);

fim_registry_key *__wrap_fim_db_get_registry_key(fdb_t *fim_sql, const char *path, unsigned int arch);

int __wrap_fim_db_insert_registry_key(fdb_t *fim_sql, fim_registry_key *entry, unsigned int rowid);

int __wrap_fim_db_set_registry_key_scanned(fdb_t *fim_sql, const char *path, unsigned int arch);

int __wrap_fim_db_set_all_registry_data_unscanned(fdb_t *fim_sql);

int __wrap_fim_db_set_all_registry_key_unscanned(fdb_t *fim_sql);

void expect_fim_db_get_values_from_registry_key_call(fdb_t *fim_sql,
                                                     fim_tmp_file *file,
                                                     int storage,
                                                     int ret);
void expect_fim_db_remove_registry_key_call(fdb_t *fim_sql,
                                                 fim_entry *entry,
                                                 int ret);

void expect_fim_db_remove_registry_value_data_call(fdb_t *fim_sql,
                                                   fim_registry_value_data *entry,
                                                   int ret);

#endif // WIN32
#endif // FIM_DB_REGISTRIES_WRAPPERS_H
