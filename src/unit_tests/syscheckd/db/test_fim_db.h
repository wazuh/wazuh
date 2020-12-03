#ifndef __TEST_FIM_DB_H
#define __TEST_FIM_DB_H

#include "test_fim.h"

/**********************************************************************************************************************\
 * Common wrappers used in tests
\**********************************************************************************************************************/

#include "wrappers/externals/sqlite/sqlite3_wrappers.h"

/**********************************************************************************************************************\
 * Auxiliar structs used in tests
\**********************************************************************************************************************/
typedef struct _test_fim_db_insert_data {
    fdb_t *fim_sql;
    fim_entry *entry;
    fim_tmp_file *tmp_file;
    fim_file_data *saved;
} test_fim_db_insert_data;

typedef struct _test_fim_db_ctx_s {
    test_fim_db_insert_data *test_data;
    EVP_MD_CTX *ctx;
} test_fim_db_ctx_t;

/**********************************************************************************************************************\
 * Auxiliar expect functions
\**********************************************************************************************************************/
/* fim_db.c */
void expect_fim_db_check_transaction();
void expect_fim_db_decode_full_row();
void expect_fim_db_decode_full_row_from_entry(const fim_entry *entry);
void expect_fim_db_exec_simple_wquery();
void expect_fim_db_clean_stmt();
void expect_fim_db_get_count_entries(int retval);
void expect_fim_db_force_commit();
void expect_fim_db_read_line_from_file_fail();
void expect_fim_db_read_line_from_file_disk_success(int index, FILE *fd, const char *line, const char *line_length);
void expect_fim_db_get_path_success(const char *path, const fim_entry *entry);

/* fim_db_files.c */
void expect_fim_db_bind_insert_data(int text_count);
void expect_fim_db_bind_update_data(int text_count);
void expect_fim_db_bind_replace_path(int text_count);
void expect_fim_db_bind_delete_data_id(int row);
void expect_fim_db_bind_get_inode();
void expect_fim_db_insert_path_success();
void expect_fim_db_insert_data_success(int row_id);
void expect_fim_db_bind_path(const char *path);
void expect_fim_db_get_paths_from_inode(char **paths);

/* fim_db_registries.c */
void expect_fim_db_get_registry_key_fail(const fim_registry_key *key);
void expect_fim_db_get_registry_key(const fim_registry_key *key);
void expect_fim_db_get_registry_data_fail(const char *name, int key_id);
void expect_fim_db_get_registry_data(const char *name, int key_id, const fim_registry_value_data *data);

/**********************************************************************************************************************\
 * Setup and teardown functions
\**********************************************************************************************************************/
int setup_fim_db_group(void **state);
int teardown_fim_db_group(void **state);
int test_fim_db_setup(void **state);
int test_fim_db_teardown(void **state);
int test_fim_tmp_file_setup_disk(void **state);
int test_fim_tmp_file_teardown_disk(void **state);
int teardown_fim_entry(void **state);

extern const fim_file_data DEFAULT_FILE_DATA;
extern const fim_registry_key DEFAULT_REGISTRY_KEY;
extern const fim_registry_value_data DEFAULT_REGISTRY_VALUE;

#endif // __TEST_FIM_DB_H
