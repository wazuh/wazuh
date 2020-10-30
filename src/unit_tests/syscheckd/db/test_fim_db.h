#ifndef __TEST_FIM_DB_H
#define __TEST_FIM_DB_H

#include "syscheck.h"
#include "syscheck-config.h"

/**********************************************************************************************************************\
 * Common wrappers used in tests
\**********************************************************************************************************************/

#include "wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "wrappers/wazuh/shared/debug_op_wrappers.h"

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
void expect_fim_db_exec_simple_wquery();
void expect_fim_db_clean_stmt();
void expect_fim_db_get_count_entries(int retval);
void expect_fim_db_force_commit();

/* fim_db_files.c */
void expect_fim_db_bind_insert_data(int text_count);
void expect_fim_db_bind_update_data(int text_count);
void expect_fim_db_bind_replace_path(int text_count);
void expect_fim_db_bind_delete_data_id(int row);
void expect_fim_db_bind_get_inode();
void expect_fim_db_insert_path_success();
void expect_fim_db_insert_data_success(int row_id);
void expect_fim_db_bind_path(const char *path);

/**********************************************************************************************************************\
 * Setup and teardown functions
\**********************************************************************************************************************/
int setup_group(void **state);
int teardown_group(void **state);
int test_fim_db_setup(void **state);
int test_fim_db_teardown(void **state);
int test_fim_tmp_file_setup_disk(void **state);
int test_fim_tmp_file_teardown_disk(void **state);

#endif // __TEST_FIM_DB_H
