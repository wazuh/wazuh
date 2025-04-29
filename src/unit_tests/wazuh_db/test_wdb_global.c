
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "../wazuh_db/wdb.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/time_op_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/posix/time_wrappers.h"
#include "../wrappers/wazuh/shared/cluster_op_wrappers.h"
#include "wazuhdb_op.h"

#define GROUPS_SIZE 10
#define AGENTS_SIZE 10

extern void __real_cJSON_Delete(cJSON *item);
extern int test_mode;

/* setup/teardown */
typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("global",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    *state = init_data;
    wdb_init_conf();
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    wdb_free_conf();
    return 0;
}

/* wrappers configurations for fail/success */

/**
 * @brief Configure a successful call to __wrap_wdb_exec_stmt_sized
 *
 * @param j_array The cJSON* array to mock
 * @param column_mode The expected column mode, STMT_MULTI_COLUMN or STMT_SINGLE_COLUMN
 */
void wrap_wdb_exec_stmt_sized_success_call(cJSON* j_array, int column_mode) {
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    expect_value(__wrap_wdb_exec_stmt_sized, column_mode, column_mode);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, j_array);
}

/**
 * @brief Configure a failed call to __wrap_wdb_exec_stmt_sized
 *
 * @param column_mode The expected column mode, STMT_MULTI_COLUMN or STMT_SINGLE_COLUMN
 */
void wrap_wdb_exec_stmt_sized_failed_call(int column_mode) {
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    expect_value(__wrap_wdb_exec_stmt_sized, column_mode, column_mode);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ERROR);
    will_return(__wrap_wdb_exec_stmt_sized, NULL);
}

/**
 * @brief Configure a call to __wrap_wdb_exec_stmt_sized where the result is bigger than WDB_MAX_RESPONSE_SIZE
 *
 * @param j_array The cJSON* array to mock
 * @param column_mode The expected column mode, STMT_MULTI_COLUMN or STMT_SINGLE_COLUMN
 */
void wrap_wdb_exec_stmt_sized_socket_full_call(cJSON* j_array, int column_mode) {
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    expect_value(__wrap_wdb_exec_stmt_sized, column_mode, column_mode);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ROW);
    will_return(__wrap_wdb_exec_stmt_sized, j_array);
}

/**
 * @brief Configure all the wrappers to simulate a successful call to wdb_global_get_agent_max_group_priority() method
 * @param agent_id The id of the agent to get the max priority of its groups
 * @param j_priority_resp The response of the priority query
 */
void create_wdb_global_get_agent_max_group_priority_success_call(int agent_id, cJSON* j_priority_resp) {
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_PRIORITY_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, j_priority_resp);
    expect_function_call(__wrap_cJSON_Delete);
}

/**
 * @brief Configure all the wrappers to simulate a successful call to create_wdb_global_validate_groups_success_call() method
 *
 * @param agent_id The agent ID the new groups will be assigned to.
 * @param j_groups_number Existent groups number of agent_id.
 * @param j_groups Groups to be assigned to agent_id
 */
void create_wdb_global_validate_groups_success_call(int agent_id, cJSON *j_groups_number) {
    /* wdb_global_groups_number_get */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, j_groups_number);
    expect_function_call(__wrap_cJSON_Delete);
}

/**
 * @brief Configure all the wrappers to simulate a successful call to wdb_global_delete_agent_belong() method
 * @param agent_id The id of the agent whose groups are being deleted
 */
void create_wdb_global_delete_agent_belong_success_call(int agent_id) {
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
}

/**
 * @brief Configure all the wrappers to simulate a successful call to _wdb_global_unassign_agent_group() method
 * @param agent_id The id of the agent being removed from the belongs table
 * @param group_id The id of the group being removed from the the belongs table
 * @param group_name The name of the group being searched for remove
 * @param find_group_resp The response of the find group query
 */
void create_wdb_global_unassign_agent_group_success_call(int agent_id, int group_id, char* group_name, cJSON* find_group_resp) {
    // wdb_global_find_group
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, find_group_resp);
    expect_function_call(__wrap_cJSON_Delete);
    // wdb_global_delete_tuple_belong
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, group_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
}

/**
 * @brief Configure all the wrappers to simulate a successful call to wdb_global_calculate_agent_group_csv() method
 * @param agent_id The id of the agent to calculate its groups csv
 */
void create_wdb_global_calculate_agent_group_csv_success_call(int agent_id) {
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
}

/**
 * @brief Configure all the wrappers to simulate a successful call to wdb_global_set_agent_group_context() method
 * @param agent_id The id of the agent to set its group context
 * @param csv The groups csv to be written in the groups column
 * @param hash The hash to be written in the group_hash column
 * @param sync_status The sync status to be written in the group_sync_status column
 */
void create_wdb_global_set_agent_group_context_success_call(int agent_id, char* csv, char* hash, char* sync_status) {
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_CTX_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    if (csv) {
        expect_string(__wrap_sqlite3_bind_text, buffer, csv);
    }
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    if (hash) {
        expect_string(__wrap_sqlite3_bind_text, buffer, hash);
    }
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
}

/* Tests wdb_global_get_agent_labels */

void test_wdb_global_get_agent_labels_transaction_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    output = wdb_global_get_agent_labels(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_labels_cache_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    output = wdb_global_get_agent_labels(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_labels_bind_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    output = wdb_global_get_agent_labels(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_labels_exec_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_wdb_exec_stmt, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    output = wdb_global_get_agent_labels(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_labels_success(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);

    output = wdb_global_get_agent_labels(data->wdb, 1);
    assert_ptr_equal(output, (cJSON*)1);
}

/* Tests wdb_global_del_agent_labels */

void test_wdb_global_del_agent_labels_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_del_agent_labels(data->wdb, 1);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_del_agent_labels_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_del_agent_labels(data->wdb, 1);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_del_agent_labels_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_del_agent_labels(data->wdb, 1);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_del_agent_labels_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_del_agent_labels(data->wdb, 1);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_del_agent_labels_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_del_agent_labels(data->wdb, 1);
    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_set_agent_label */

void test_wdb_global_set_agent_label_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_value");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_value");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_agent_label_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_value");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_set_agent_label(data->wdb, 1, key, value);
    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_set_sync_status */

void test_wdb_global_set_sync_status_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_validate_sync_status */

void test_wdb_global_validate_sync_status_no_old_status(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "synced";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    expect_string(__wrap__merror, formatted_msg, "Failed to get old sync_status for agent '1'");

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_synced_to_synced(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "synced";
    char *old_status = "synced";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_to_synced(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "synced";
    char *old_status = "syncreq";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_status_to_synced(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "synced";
    char *old_status = "syncreq_status";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_keepalive_to_synced(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "synced";
    char *old_status = "syncreq_keepalive";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_synced_to_syncreq(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq";
    char *old_status = "synced";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_to_syncreq(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq";
    char *old_status = "syncreq";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_status_to_syncreq(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq";
    char *old_status = "syncreq_status";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_keepalive_to_syncreq(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq";
    char *old_status = "syncreq_keepalive";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_synced_to_syncreq_status(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq_status";
    char *old_status = "synced";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_to_syncreq_status(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq_status";
    char *old_status = "syncreq";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, old_status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_status_to_syncreq_status(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq_status";
    char *old_status = "syncreq_status";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_keepalive_to_syncreq_status(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq_status";
    char *old_status = "syncreq_keepalive";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_synced_to_syncreq_keepalive(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq_keepalive";
    char *old_status = "synced";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_to_syncreq_keepalive(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq_keepalive";
    char *old_status = "syncreq";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, old_status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_status_to_syncreq_keepalive(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq_keepalive";
    char *old_status = "syncreq_status";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, old_status);

    os_free(new_status);
}

void test_wdb_global_validate_sync_status_syncreq_keepalive_to_syncreq_keepalive(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = "syncreq_keepalive";
    char *old_status = "syncreq_keepalive";
    char *new_status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, old_status);

    new_status = wdb_global_validate_sync_status(data->wdb, agent_id, status);
    assert_string_equal(new_status, status);

    os_free(new_status);
}

/* Tests wdb_global_get_sync_status */

void test_wdb_global_get_sync_status_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = NULL;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    status = wdb_global_get_sync_status(data->wdb, agent_id);
    assert_null(status);

    os_free(status);
}

void test_wdb_global_get_sync_status_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    status = wdb_global_get_sync_status(data->wdb, agent_id);
    assert_null(status);

    os_free(status);
}

void test_wdb_global_get_sync_status_bind1_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    status = wdb_global_get_sync_status(data->wdb, agent_id);
    assert_null(status);

    os_free(status);
}

void test_wdb_global_get_sync_status_step_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_step(): ERROR MESSAGE");

    status = wdb_global_get_sync_status(data->wdb, agent_id);
    assert_null(status);

    os_free(status);
}

void test_wdb_global_get_sync_status_success_no_status(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    status = wdb_global_get_sync_status(data->wdb, agent_id);
    assert_null(status);

    os_free(status);
}

void test_wdb_global_get_sync_status_success(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *status = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "synced");

    status = wdb_global_get_sync_status(data->wdb, agent_id);
    assert_string_equal(status, "synced");

    os_free(status);
}

/* Tests wdb_global_sync_agent_info_get */

void test_wdb_global_sync_agent_info_get_transaction_fail(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "Cannot begin transaction");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_sync_agent_info_get_cache_fail(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "Cannot cache statement");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_sync_agent_info_get_bind_fail(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "Cannot bind sql statement");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_sync_agent_info_get_no_agents(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return_count(__wrap_wdb_stmt_cache, 1, 3);
    expect_value_count(__wrap_sqlite3_bind_int, index, 1, 3);
    expect_value_count(__wrap_sqlite3_bind_int, value, last_agent_id, 3);
    will_return_count(__wrap_sqlite3_bind_int, SQLITE_OK, 3);
    will_return_count(__wrap_wdb_exec_stmt, NULL, 3);
    expect_function_call_any(__wrap_cJSON_Delete);

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "[]");
    os_free(output);
    assert_int_equal(result, WDBC_OK);
}

void test_wdb_global_sync_agent_info_get_success(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;
    cJSON *json_output = NULL;
    cJSON *root = NULL;
    cJSON *json_agent = NULL;
    cJSON *json_labels = NULL;
    cJSON *json_label = NULL;
    int agent_id = 10;

    root = __real_cJSON_CreateArray();
    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    cJSON_AddStringToObject(json_agent,"test_field", "test_value");
    cJSON_AddItemToArray(root, json_agent);

    will_return_count(__wrap_wdb_begin2, 1, -1);
    will_return_count(__wrap_wdb_stmt_cache, 1, -1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_get_agent_labels()
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_global_set_sync_status()
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Mocking one valid agent
    will_return(__wrap_wdb_exec_stmt, root);
    expect_function_call_any(__wrap_cJSON_Delete);

    // Required for wdb_get_agent_labels()
    json_labels = __real_cJSON_CreateArray();
    json_label = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_label, "id", agent_id);
    cJSON_AddStringToObject(json_label,"key", "test_key");
    cJSON_AddStringToObject(json_label,"value", "test_value");
    cJSON_AddItemToArray(json_labels, json_label);
    will_return(__wrap_wdb_exec_stmt, json_labels);

    // Required for wdb_global_set_sync_status()
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    // No more agents
    will_return(__wrap_wdb_exec_stmt, NULL);

    // Status and keep alive queries
    expect_value_count(__wrap_sqlite3_bind_int, index, 1, 2);
    expect_value_count(__wrap_sqlite3_bind_int, value, last_agent_id, 2);
    will_return_count(__wrap_sqlite3_bind_int, SQLITE_OK, 2);
    will_return_count(__wrap_wdb_exec_stmt, NULL, 2);

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "[{\"id\":10,\"test_field\":\"test_value\",\"labels\":[{\"id\":10,\"key\":\"test_key\",\"value\":\"test_value\"}]}]");
    os_free(output);
    __real_cJSON_Delete(json_output);
    __real_cJSON_Delete(root);
    assert_int_equal(result, WDBC_OK);
}

void test_wdb_global_sync_agent_info_get_sync_fail(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;
    cJSON *root = NULL;
    cJSON *json_agent = NULL;
    cJSON *json_labels = NULL;
    int agent_id = 10;

    root = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(root, json_agent = cJSON_CreateObject());
    cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(agent_id));

    will_return_count(__wrap_wdb_begin2, 1, -1);
    will_return_count(__wrap_wdb_stmt_cache, 1, -1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_get_agent_labels()
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_global_set_sync_status()
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Mocking one valid agent
    will_return(__wrap_wdb_exec_stmt, root);
    expect_function_call_any(__wrap_cJSON_Delete);

    // Required for wdb_get_agent_labels()
    json_labels = __real_cJSON_CreateArray();
    will_return(__wrap_wdb_exec_stmt, json_labels);

    // Required for wdb_global_set_sync_status()
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Cannot set sync_status for agent 10");

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "Cannot set sync_status for agent 10");
    os_free(output);
    __real_cJSON_Delete(root);
    __real_cJSON_Delete(json_labels);
    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_sync_agent_info_get_full(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;
    cJSON *root = NULL;
    cJSON *json_agent = NULL;
    cJSON *json_labels = NULL;
    cJSON *json_label = NULL;
    int agent_id = 10;

    root = __real_cJSON_CreateArray();
    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    // Creating a cJSON array bigger than WDB_MAX_RESPONSE_SIZE
    for(int i = 0; i < 2500; i++){
        cJSON_AddStringToObject(json_agent,"test_field", "test_value");
    }
    cJSON_AddItemToArray(root, json_agent);

    will_return_count(__wrap_wdb_begin2, 1, -1);
    will_return_count(__wrap_wdb_stmt_cache, 1, -1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_get_agent_labels()
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Mocking one valid agent
    will_return(__wrap_wdb_exec_stmt, root);
    expect_function_call_any(__wrap_cJSON_Delete);

    // Required for wdb_get_agent_labels()
    json_labels = __real_cJSON_CreateArray();
    json_label = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_label, "id", 1);
    cJSON_AddStringToObject(json_label,"key", "test_key");
    cJSON_AddStringToObject(json_label,"value", "test_value");
    cJSON_AddItemToArray(json_labels, json_label);
    will_return(__wrap_wdb_exec_stmt, json_labels);

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);

    assert_string_equal(output, "[]");
    os_free(output);
    __real_cJSON_Delete(root);
    assert_int_equal(result, WDBC_DUE);
}

void test_wdb_global_sync_agent_info_get_size_limit(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;
    cJSON *json_output = NULL;
    cJSON *root = NULL;
    cJSON *json_agent = NULL;
    int agent_id = 10000;

    root = __real_cJSON_CreateArray();
    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    // Creating a cJSON array of WDB_MAX_RESPONSE_SIZE
    for(int i = 0; i < 8126; i++){
        cJSON_AddStringToObject(json_agent,"a", "b");
    }
    cJSON_AddItemToArray(root, json_agent);

    will_return_count(__wrap_wdb_begin2, 1, -1);
    will_return_count(__wrap_wdb_stmt_cache, 1, -1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_get_agent_labels()
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_global_set_sync_status()
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Mocking one valid agent
    will_return(__wrap_wdb_exec_stmt, root);
    expect_function_call_any(__wrap_cJSON_Delete);

    // Required for wdb_get_agent_labels()
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "SQL MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): SQL MESSAGE");

    // Required for wdb_global_set_sync_status()
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    // No more agents
    will_return(__wrap_wdb_exec_stmt, NULL);

    // Status and keep alive queries
    expect_value_count(__wrap_sqlite3_bind_int, index, 1, 2);
    expect_value_count(__wrap_sqlite3_bind_int, value, last_agent_id, 2);
    will_return_count(__wrap_sqlite3_bind_int, SQLITE_OK, 2);
    will_return_count(__wrap_wdb_exec_stmt, NULL, 2);

    result = wdb_global_sync_agent_info_get(data->wdb, &last_agent_id, &output);
    assert_int_equal(result, WDBC_OK);

    os_free(output);
    __real_cJSON_Delete(json_output);
    __real_cJSON_Delete(root);
}

/* Tests wdb_global_get_groups_integrity */

void test_wdb_global_get_groups_integrity_statement_fail(void **state)
{
    cJSON* j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    j_result = wdb_global_get_groups_integrity(data->wdb, NULL);

    assert_null(j_result);
}

void test_wdb_global_get_groups_integrity_syncreq(void **state)
{
    cJSON* j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    will_return(__wrap_wdb_step, SQLITE_ROW);

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    j_result = wdb_global_get_groups_integrity(data->wdb, NULL);

    char *result = cJSON_PrintUnformatted(j_result);
    assert_string_equal(result, "[\"syncreq\"]");
    os_free(result);
    __real_cJSON_Delete(j_result);
}

void test_wdb_global_get_groups_integrity_hash_mismatch(void **state)
{
    cJSON* j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    os_sha1 digest = "";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    expect_string(__wrap_wdb_get_global_group_hash, hexdigest, digest);
    will_return(__wrap_wdb_get_global_group_hash, OS_INVALID);

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    j_result = wdb_global_get_groups_integrity(data->wdb, digest);

    char *result = cJSON_PrintUnformatted(j_result);
    assert_string_equal(result, "[\"hash_mismatch\"]");
    os_free(result);
    __real_cJSON_Delete(j_result);
}

void test_wdb_global_get_groups_integrity_synced(void **state)
{
    cJSON* j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    os_sha1 digest = "";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    expect_string(__wrap_wdb_get_global_group_hash, hexdigest, digest);
    will_return(__wrap_wdb_get_global_group_hash, OS_SUCCESS);

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    j_result = wdb_global_get_groups_integrity(data->wdb, digest);

    char *result = cJSON_PrintUnformatted(j_result);
    assert_string_equal(result, "[\"synced\"]");
    os_free(result);
    __real_cJSON_Delete(j_result);
}

void test_wdb_global_get_groups_integrity_error(void **state)
{
    cJSON* j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(global) SQLite: ERROR MESSAGE");

    j_result = wdb_global_get_groups_integrity(data->wdb, NULL);

    assert_null(j_result);
}

/* Tests wdb_global_get_agent_max_group_priority */

void test_wdb_global_get_agent_max_group_priority_statement_fail(void **state)
{
    int result = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_PRIORITY_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    result = wdb_global_get_agent_max_group_priority(data->wdb, agent_id);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_get_agent_max_group_priority_bind_fail(void **state)
{
    int result = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_PRIORITY_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_get_agent_max_group_priority(data->wdb, agent_id);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_get_agent_max_group_priority_step_fail(void **state)
{
    int result = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_PRIORITY_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_get_agent_max_group_priority(data->wdb, agent_id);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_get_agent_max_group_priority_success(void **state)
{
    int result = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    cJSON *j_result = cJSON_Parse("[{\"MAX(priority)\":5}]");

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_PRIORITY_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, j_result);
    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_get_agent_max_group_priority(data->wdb, agent_id);

    assert_int_equal(result, 5);
    __real_cJSON_Delete(j_result);
}

/* Tests wdb_global_sync_agent_groups_get */

void test_wdb_global_sync_agent_groups_get_no_condition_get_hash_true(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = WDB_GROUP_NO_CONDITION;
    int last_agent_id = 0;
    bool set_synced = false;
    bool get_hash = true;
    cJSON *j_output = NULL;

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    expect_string(__wrap_wdb_get_global_group_hash, hexdigest, "");
    will_return(__wrap_wdb_get_global_group_hash, OS_SUCCESS);

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, 10, &j_output);

    char *output = cJSON_PrintUnformatted(j_output);
    assert_string_equal(output, "[{\"data\":[],\"hash\":null}]");
    os_free(output);
    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_output);
}

void test_wdb_global_sync_agent_groups_get_transaction_fail(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = WDB_GROUP_SYNC_STATUS;
    int last_agent_id = 0;
    bool set_synced = true;
    bool get_hash = true;
    int agent_registration_delta = 10;
    cJSON *j_output = NULL;

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    will_return(__wrap_wdb_begin2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, agent_registration_delta, &j_output);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_output);
}

void test_wdb_global_sync_agent_groups_get_cache_fail(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = WDB_GROUP_SYNC_STATUS;
    int last_agent_id = 0;
    bool set_synced = true;
    bool get_hash = true;
    int agent_registration_delta = 10;
    cJSON *j_output = NULL;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_time, 100);
    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, agent_registration_delta, &j_output);

    char *output = cJSON_PrintUnformatted(j_output);
    assert_string_equal(output, "[{\"data\":[]}]");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_output);
}

void test_wdb_global_sync_agent_groups_get_bind_fail(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = WDB_GROUP_ALL;
    int last_agent_id = 0;
    bool set_synced = true;
    bool get_hash = true;
    int agent_registration_delta = 10;
    cJSON *j_output = NULL;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_time, 100);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, agent_registration_delta, &j_output);

    char *output = cJSON_PrintUnformatted(j_output);
    assert_string_equal(output, "[{\"data\":[]}]");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_output);
}

void test_wdb_global_sync_agent_groups_get_bind2_fail(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = WDB_GROUP_ALL;
    int last_agent_id = 0;
    bool set_synced = true;
    bool get_hash = true;
    int agent_registration_delta = 10;
    cJSON *j_output = NULL;
    int wrapped_time = 100;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_time, wrapped_time);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, wrapped_time - agent_registration_delta);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, agent_registration_delta, &j_output);

    char *output = cJSON_PrintUnformatted(j_output);
    assert_string_equal(output, "[{\"data\":[]}]");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_output);
}

void test_wdb_global_sync_agent_groups_get_no_agents_get_hash_false(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = 0;
    int last_agent_id = 0;
    bool set_synced = false;
    bool get_hash = false;
    int agent_registration_delta = 10;
    int wrapped_time = 100;
    cJSON *j_output = NULL;
    cJSON *j_exec_response = __real_cJSON_CreateArray();
    cJSON *j_object = cJSON_CreateObject();

    cJSON_AddNumberToObject(j_object, "id", 1);
    cJSON_AddItemToArray(j_exec_response, j_object);

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_time, wrapped_time);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, wrapped_time - agent_registration_delta);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, j_exec_response);
    expect_function_call(__wrap_cJSON_Delete);

    /* wdb_global_select_group_belong */
    cJSON *j_groups = NULL;
    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id+1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    /* wdb_exec_stmt_sized */
    wrap_wdb_exec_stmt_sized_success_call(j_groups, STMT_SINGLE_COLUMN);
    expect_function_call(__wrap_cJSON_Delete);
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    /* Next agent */
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id+1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, wrapped_time - agent_registration_delta);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, NULL);
    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, agent_registration_delta, &j_output);

    char *output = cJSON_PrintUnformatted(j_output);
    assert_string_equal(output, "[{\"data\":[{\"id\":1,\"groups\":[]}]}]");
    os_free(output);
    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_exec_response);
    __real_cJSON_Delete(j_output);
    __real_cJSON_Delete(j_groups);
}

void test_wdb_global_sync_agent_groups_get_exec_fail_get_hash_true_success(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = WDB_GROUP_ALL;
    int last_agent_id = 0;
    bool set_synced = true;
    bool get_hash = true;
    int agent_registration_delta = 10;
    cJSON *j_output = NULL;
    int wrapped_time = 100;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_time, wrapped_time);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, wrapped_time - agent_registration_delta);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, NULL);
    expect_string(__wrap_wdb_get_global_group_hash, hexdigest, "");
    will_return(__wrap_wdb_get_global_group_hash, OS_SUCCESS);
    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, agent_registration_delta, &j_output);

    char *output = cJSON_PrintUnformatted(j_output);
    assert_string_equal(output, "[{\"data\":[],\"hash\":null}]");
    os_free(output);
    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_output);
}

void test_wdb_global_sync_agent_groups_get_exec_fail_get_hash_true_fail(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = WDB_GROUP_ALL;
    int last_agent_id = 0;
    bool set_synced = true;
    bool get_hash = true;
    int agent_registration_delta = 10;
    cJSON *j_output = NULL;
    int wrapped_time = 100;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_time, wrapped_time);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, wrapped_time - agent_registration_delta);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, NULL);
    expect_string(__wrap_wdb_get_global_group_hash, hexdigest, "");
    will_return(__wrap_wdb_get_global_group_hash, OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Cannot obtain the global group hash");
    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, agent_registration_delta, &j_output);

    char *output = cJSON_PrintUnformatted(j_output);
    assert_string_equal(output, "[{\"data\":[]}]");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_output);
}

void test_wdb_global_sync_agent_groups_get_set_synced_error(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = WDB_GROUP_ALL;
    int last_agent_id = 0;
    bool set_synced = true;
    bool get_hash = true;
    int agent_registration_delta = 10;
    int wrapped_time = 100;
    cJSON *j_output = NULL;
    cJSON *j_exec_response = __real_cJSON_CreateArray();
    cJSON *j_object = cJSON_CreateObject();

    cJSON_AddNumberToObject(j_object, "id", 1);
    cJSON_AddItemToArray(j_exec_response, j_object);

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_time, wrapped_time);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, wrapped_time - agent_registration_delta);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, j_exec_response);
    expect_function_call(__wrap_cJSON_Delete);

    /* wdb_global_select_group_belong */
    cJSON *root = cJSON_Parse("[\"default\",\"new_group\"]");
    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id+1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    /* wdb_exec_stmt_sized */
    wrap_wdb_exec_stmt_sized_success_call(root, STMT_SINGLE_COLUMN);

    /* wdb_global_set_agent_groups_sync_status */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNC_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_string(__wrap__merror, formatted_msg, "Cannot set group_sync_status for agent 1");

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, agent_registration_delta, &j_output);

    char *output = cJSON_PrintUnformatted(j_output);
    assert_string_equal(output, "[{\"data\":[{\"id\":1,\"groups\":[\"default\",\"new_group\"]}]}]");
    os_free(output);
    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_exec_response);
    __real_cJSON_Delete(j_output);
}

void test_wdb_global_sync_agent_groups_get_due_buffer_full(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = 0;
    int last_agent_id = 0;
    bool set_synced = false;
    bool get_hash = true;
    int agent_registration_delta = 10;
    int wrapped_time = 100;
    cJSON *j_output = NULL;
    cJSON *j_exec_response = __real_cJSON_CreateArray();
    cJSON *j_object = cJSON_CreateObject();

    cJSON_AddNumberToObject(j_object, "id", 1);
    cJSON_AddItemToArray(j_exec_response, j_object);

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    will_return(__wrap_time, 100);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, wrapped_time - agent_registration_delta);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, j_exec_response);
    expect_function_call(__wrap_cJSON_Delete);

    /* wdb_global_select_group_belong */
    cJSON *j_groups = __real_cJSON_CreateArray();
    /* Creating a JSON object with 5000 groups of name "test_group"
    to exceed the WDB_MAX_RESPONSE_SIZE just for testing purposes.
    In a real scenario an agent won't belong to more than MAX_GROUPS_PER_MULTIGROUP (128),
    the group names will be unique and not longer than MAX_GROUP_NAME (255).
    */
    for (int i = 0; i < 5000; ++i) {
        cJSON_AddItemToArray(j_groups, cJSON_CreateString("test_group"));
    }
    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id+1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    /* wdb_exec_stmt_sized */
    wrap_wdb_exec_stmt_sized_success_call(j_groups, STMT_SINGLE_COLUMN);

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, agent_registration_delta, &j_output);

    assert_int_equal(result, WDBC_DUE);
    __real_cJSON_Delete(j_exec_response);
    __real_cJSON_Delete(j_output);
}

/* Tests wdb_global_add_global_group_hash_to_response */

void test_wdb_global_sync_agent_groups_get_invalid_condition(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_groups_sync_condition_t condition = WDB_GROUP_INVALID_CONDITION;
    int last_agent_id = 0;
    bool set_synced = true;
    bool get_hash = true;
    int agent_registration_delta = 10;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid groups sync condition");

    result = wdb_global_sync_agent_groups_get(data->wdb, condition, last_agent_id, set_synced, get_hash, agent_registration_delta, NULL);

    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_add_global_group_hash_to_resposne_response_null(void **state) {
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid JSON object.");

    result = wdb_global_add_global_group_hash_to_response(data->wdb, NULL, 1);

    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_add_global_group_hash_to_resposne_get_hash_return_null(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *j_response = cJSON_CreateObject();

    expect_string(__wrap_wdb_get_global_group_hash, hexdigest, "");
    will_return(__wrap_wdb_get_global_group_hash, OS_SUCCESS);

    result = wdb_global_add_global_group_hash_to_response(data->wdb, &j_response, 1);

    char *output = cJSON_PrintUnformatted(j_response);
    assert_string_equal(output, "{\"hash\":null}");
    os_free(output);
    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_response);
}

void test_wdb_global_add_global_group_hash_to_resposne_response_due(void **state) {
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *j_response = cJSON_CreateObject();

    result = wdb_global_add_global_group_hash_to_response(data->wdb, &j_response, WDB_MAX_RESPONSE_SIZE-1);

    assert_int_equal(result, WDBC_DUE);
    __real_cJSON_Delete(j_response);
}

void test_wdb_global_add_global_group_hash_to_resposne_get_hash_error(void **state)
{
    wdbc_result result = WDBC_OK;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *j_response = cJSON_CreateObject();

    expect_string(__wrap_wdb_get_global_group_hash, hexdigest, "");
    will_return(__wrap_wdb_get_global_group_hash, OS_INVALID);

    expect_string(__wrap__merror, formatted_msg, "Cannot obtain the global group hash");

    result = wdb_global_add_global_group_hash_to_response(data->wdb, &j_response, 1);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_response);
}

/* Tests wdb_global_sync_agent_info_set */

void test_wdb_global_sync_agent_info_set_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_count(__wrap_sqlite3_bind_parameter_index, zName, -1);
    will_return_count(__wrap_sqlite3_bind_parameter_index, 1, -1);

    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", 1);
    cJSON_AddStringToObject(json_agent, "name", "test_name");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_name");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);

    __real_cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;
    int agent_id = 10;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_count(__wrap_sqlite3_bind_parameter_index, zName, -1);
    will_return_count(__wrap_sqlite3_bind_parameter_index, 1, -1);

    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    cJSON_AddStringToObject(json_agent, "name", "test_name");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_name");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);
    __real_cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;
    int agent_id = 10;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_count(__wrap_sqlite3_bind_parameter_index, zName, -1);
    will_return_count(__wrap_sqlite3_bind_parameter_index, 1, -1);

    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    cJSON_AddStringToObject(json_agent, "name", "test_name");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_name");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);
    __real_cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;
    int agent_id = 10;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_count(__wrap_sqlite3_bind_parameter_index, zName, -1);
    will_return_count(__wrap_sqlite3_bind_parameter_index, 1, -1);

    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    cJSON_AddStringToObject(json_agent, "name", "test_name");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_name");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);
    __real_cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;
    int agent_id = 10;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_count(__wrap_sqlite3_bind_parameter_index, zName, -1);
    will_return_count(__wrap_sqlite3_bind_parameter_index, 1, -1);

    json_agent = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_agent, "id", agent_id);
    cJSON_AddStringToObject(json_agent, "name", "test_name");

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_name");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_sync_agent_info_set(data->wdb, json_agent);
    __real_cJSON_Delete(json_agent);
    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_insert_agent */

void test_wdb_global_insert_agent_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = NULL;
    char *ip = NULL;
    char *register_ip = NULL;
    char *internal_key = NULL;
    char *group = NULL;
    int date_add = 0;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = NULL;
    char *ip = NULL;
    char *register_ip = NULL;
    char *internal_key = NULL;
    char *group = NULL;
    int date_add = 0;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind4_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind5_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, internal_key);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind6_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, internal_key);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, date_add);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_bind7_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, internal_key);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, date_add);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, group);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, internal_key);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, date_add);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, group);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "test_ip";
    char *register_ip = "0.0.0.0";
    char *internal_key = "test_key";
    char *group = "test_group";
    int date_add = 100;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, register_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, internal_key);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, date_add);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, group);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_insert_agent(data->wdb, 1, name, ip, register_ip, internal_key, group, date_add);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_update_agent_name */

void test_wdb_global_update_agent_name_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = NULL;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_name_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = NULL;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_name_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_name_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_name_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_name_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_update_agent_name(data->wdb, 1, name);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_update_agent_version */

void test_wdb_global_update_agent_version_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = NULL;
    const char *os_version = NULL;
    const char *os_major = NULL;
    const char *os_minor = NULL;
    const char *os_codename = NULL;
    const char *os_platform = NULL;
    const char *os_build = NULL;
    const char *os_uname = NULL;
    const char *os_arch = NULL;
    const char *version = NULL;
    const char *config_sum = NULL;
    const char *merged_sum = NULL;
    const char *manager_host = NULL;
    const char *node_name = NULL;
    const char *agent_ip = NULL;
    const char *connection_status = NULL;
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = NULL;
    const char *os_version = NULL;
    const char *os_major = NULL;
    const char *os_minor = NULL;
    const char *os_codename = NULL;
    const char *os_platform = NULL;
    const char *os_build = NULL;
    const char *os_uname = NULL;
    const char *os_arch = NULL;
    const char *version = NULL;
    const char *config_sum = NULL;
    const char *merged_sum = NULL;
    const char *manager_host = NULL;
    const char *node_name = NULL;
    const char *agent_ip = NULL;
    const char *connection_status = NULL;
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind4_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind5_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind6_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind7_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind8_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind9_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind10_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind11_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind12_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind13_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind14_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind15_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind16_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind17_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind18_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_value(__wrap_sqlite3_bind_text, buffer, group_config_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_bind19_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_value(__wrap_sqlite3_bind_text, buffer, group_config_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 19);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_value(__wrap_sqlite3_bind_text, buffer, group_config_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 19);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_version_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    const char *os_name = "test_name";
    const char *os_version = "test_version";
    const char *os_major = "test_major";
    const char *os_minor = "test_minor";
    const char *os_codename = "test_codename";
    const char *os_platform = "test_platform";
    const char *os_build = "test_build";
    const char *os_uname = "test_uname";
    const char *os_arch = "test_arch";
    const char *version = "test_version";
    const char *config_sum = "test_config";
    const char *merged_sum = "test_merged";
    const char *manager_host = "test_manager";
    const char *node_name = "test_node";
    const char *agent_ip = "test_ip";
    const char *connection_status = "active";
    const char *sync_status = "synced";
    const char *group_config_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_major);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_minor);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_codename);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_platform);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_build);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_uname);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_arch);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_value(__wrap_sqlite3_bind_text, buffer, config_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_value(__wrap_sqlite3_bind_text, buffer, merged_sum);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, manager_host);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_value(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_value(__wrap_sqlite3_bind_text, buffer, agent_ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_value(__wrap_sqlite3_bind_text, buffer, group_config_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 19);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status,
                                            sync_status, group_config_status);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_update_agent_keepalive */

void test_wdb_global_update_agent_keepalive_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, status);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, status);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, status);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_keepalive_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, status);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_update_agent_keepalive(data->wdb, 1, connection_status, status);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_update_agent_connection_status */

void test_wdb_global_update_agent_connection_status_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status, 0);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status, 0);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status, 0);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");
    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status, 0);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");
    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status, 0);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_bind4_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");
    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status, 0);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_bind5_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");
    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status, 0);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status, 0);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_connection_status_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status, 0);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_update_agent_status_code */

void test_wdb_global_update_agent_status_code_transaction_fail(void **state) {
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int status_code = 0;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_status_code(data->wdb, 1, status_code, version, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_status_code_cache_fail(void **state) {
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int status_code = 0;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_status_code(data->wdb, 1, status_code, version, sync_status);

    assert_int_equal(result, OS_INVALID);
}


void test_wdb_global_update_agent_status_code_bind1_fail(void **state) {
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int status_code = 0;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, status_code);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_update_agent_status_code(data->wdb, 1, status_code, version, sync_status);

    assert_int_equal(result, OS_INVALID);
}


void test_wdb_global_update_agent_status_code_bind2_fail(void **state) {
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int status_code = 0;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, status_code);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_status_code(data->wdb, 1, status_code, version, sync_status);

    assert_int_equal(result, OS_INVALID);
}


void test_wdb_global_update_agent_status_code_bind3_fail(void **state) {
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int status_code = 0;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, status_code);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_status_code(data->wdb, 1, status_code, version, sync_status);

    assert_int_equal(result, OS_INVALID);
}


void test_wdb_global_update_agent_status_code_bind4_fail(void **state) {
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int status_code = 0;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, status_code);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_update_agent_status_code(data->wdb, 1, status_code, version, sync_status);

    assert_int_equal(result, OS_INVALID);
}


void test_wdb_global_update_agent_status_code_step_fail(void **state) {
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int status_code = 0;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, status_code);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_update_agent_status_code(data->wdb, 1, status_code, version, sync_status);

    assert_int_equal(result, OS_INVALID);
}


void test_wdb_global_update_agent_status_code_success(void **state) {
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int status_code = 0;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, status_code);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, version);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    // wdb_global_get_sync_status
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, sync_status);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_update_agent_status_code(data->wdb, 1, status_code, version, sync_status);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_delete_agent */

void test_wdb_global_delete_agent_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_select_agent_name */

void test_wdb_global_select_agent_name_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_name_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_name_bind_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_name_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_name_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_select_agent_group */

void test_wdb_global_select_agent_group_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_group_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_group_bind_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_group_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_group_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_select_groups */

void test_wdb_global_select_groups_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_groups(data->wdb);

    assert_null(result);
}

void test_wdb_global_select_groups_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_groups(data->wdb);

    assert_null(result);
}

void test_wdb_global_select_groups_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    /* wdb_exec_stmt_sized */
    wrap_wdb_exec_stmt_sized_failed_call(STMT_MULTI_COLUMN);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "Failed to get groups: ERROR MESSAGE.");

    result = wdb_global_select_groups(data->wdb);

    assert_null(result);
}

void test_wdb_global_select_groups_socket_full(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    /* wdb_exec_stmt_sized */
    wrap_wdb_exec_stmt_sized_socket_full_call(NULL, STMT_MULTI_COLUMN);
    expect_string(__wrap__mwarn, formatted_msg, "The groups exceed the socket maximum response size.");

    result = wdb_global_select_groups(data->wdb);

    assert_null(result);
}

void test_wdb_global_select_groups_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    /* wdb_exec_stmt_sized */
    wrap_wdb_exec_stmt_sized_success_call((cJSON*) 1, STMT_MULTI_COLUMN);

    result = wdb_global_select_groups(data->wdb);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_find_agent */

void test_wdb_global_find_agent_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_bind1_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_bind2_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_bind3_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_find_agent_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, ip);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_find_agent(data->wdb, name, ip);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_find_group */

void test_wdb_global_find_group_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_find_group(data->wdb, group_name);

    assert_null(result);
}

void test_wdb_global_find_group_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_find_group(data->wdb, group_name);

    assert_null(result);
}

void test_wdb_global_find_group_bind_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_find_group(data->wdb, group_name);

    assert_null(result);
}

void test_wdb_global_find_group_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_find_group(data->wdb, group_name);

    assert_null(result);
}

void test_wdb_global_find_group_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_find_group(data->wdb, group_name);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_insert_agent_group */

void test_wdb_global_insert_agent_group_invalid_group_name(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "group_name,with_comma";

    expect_string(__wrap__mwarn, formatted_msg, "Invalid group name. 'group_name,with_comma' "
                                                "contains invalid characters");
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot insert 'group_name,with_comma'");

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_group_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_group_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_group_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_group_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_group_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_select_group_belong */

void test_wdb_global_select_group_belong_transaction_fail(void **state)
{
    cJSON *j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    j_result = wdb_global_select_group_belong(data->wdb, 1);
    assert_null(j_result);
}

void test_wdb_global_select_group_belong_cache_fail(void **state)
{
    cJSON *j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    j_result = wdb_global_select_group_belong(data->wdb, 1);
    assert_null(j_result);
}

void test_wdb_global_select_group_belong_bind_fail(void **state)
{
    cJSON *j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    j_result = wdb_global_select_group_belong(data->wdb, 1);
    assert_null(j_result);
}

void test_wdb_global_select_group_belong_exec_fail(void **state)
{
    cJSON *j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    /* wdb_exec_stmt_sized */
    wrap_wdb_exec_stmt_sized_failed_call(STMT_SINGLE_COLUMN);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__mdebug1, formatted_msg, "Failed to get agent groups: ERROR MESSAGE.");

    j_result = wdb_global_select_group_belong(data->wdb, 1);
    assert_null(j_result);
}

void test_wdb_global_select_group_belong_socket_size_error(void **state)
{
    cJSON *j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    /* wdb_exec_stmt_sized */
    wrap_wdb_exec_stmt_sized_socket_full_call(NULL, STMT_SINGLE_COLUMN);
    expect_string(__wrap__mwarn, formatted_msg, "The agent's groups exceed the socket maximum response size.");

    j_result = wdb_global_select_group_belong(data->wdb, 1);
    assert_null(j_result);
}

void test_wdb_global_select_group_belong_success(void **state)
{
    cJSON *j_result = NULL;
    cJSON *j_root = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    j_root = cJSON_Parse("[\"default\",\"new_group\"]");

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    /* wdb_exec_stmt_sized */
    wrap_wdb_exec_stmt_sized_success_call(j_root, STMT_SINGLE_COLUMN);

    j_result = wdb_global_select_group_belong(data->wdb, 1);

    char *result = cJSON_PrintUnformatted(j_result);
    assert_string_equal(result, "[\"default\",\"new_group\"]");
    __real_cJSON_Delete(j_root);
    os_free(result);
}

/* Tests wdb_global_get_group_agents */

void test_wdb_global_get_group_agents_cache_fail(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *j_result = NULL;
    wdbc_result status = WDBC_UNKNOWN;
    char* group_name = "group_name";
    int last_agent_id = 0;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    j_result = wdb_global_get_group_agents(data->wdb, &status, group_name, last_agent_id);

    assert_null(j_result);
    assert_int_equal(status, WDBC_ERROR);
}

void test_wdb_global_get_group_agents_bind_text_fail(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *j_result = NULL;
    wdbc_result status = WDBC_UNKNOWN;
    char* group_name = "group_name";
    int last_agent_id = 0;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    j_result = wdb_global_get_group_agents(data->wdb, &status, group_name, last_agent_id);

    assert_null(j_result);
    assert_int_equal(status, WDBC_ERROR);
}

void test_wdb_global_get_group_agents_bind_int_fail(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *j_result = NULL;
    wdbc_result status = WDBC_UNKNOWN;
    char* group_name = "group_name";
    int last_agent_id = 0;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    j_result = wdb_global_get_group_agents(data->wdb, &status, group_name, last_agent_id);

    assert_null(j_result);
    assert_int_equal(status, WDBC_ERROR);
}

void test_wdb_global_get_group_agents_stmt_ok(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *j_result = NULL;
    wdbc_result status = WDBC_UNKNOWN;
    char* group_name = "group_name";
    int last_agent_id = 0;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    wrap_wdb_exec_stmt_sized_success_call(j_result, STMT_SINGLE_COLUMN);

    j_result = wdb_global_get_group_agents(data->wdb, &status, group_name, last_agent_id);

    assert_null(j_result);
    assert_int_equal(status, WDBC_OK);
}

void test_wdb_global_get_group_agents_stmt_due(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *j_result = NULL;
    wdbc_result status = WDBC_UNKNOWN;
    char* group_name = "group_name";
    int last_agent_id = 0;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    wrap_wdb_exec_stmt_sized_socket_full_call(j_result, STMT_SINGLE_COLUMN);

    j_result = wdb_global_get_group_agents(data->wdb, &status, group_name, last_agent_id);

    assert_null(j_result);
    assert_int_equal(status, WDBC_DUE);
}

void test_wdb_global_get_group_agents_stmt_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *j_result = NULL;
    wdbc_result status = WDBC_UNKNOWN;
    char* group_name = "group_name";
    int last_agent_id = 0;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    wrap_wdb_exec_stmt_sized_failed_call(STMT_SINGLE_COLUMN);

    j_result = wdb_global_get_group_agents(data->wdb, &status, group_name, last_agent_id);

    assert_null(j_result);
    assert_int_equal(status, WDBC_ERROR);
}

/* Tests wdb_global_insert_agent_belong */

void test_wdb_global_insert_agent_belong_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;
    int priority = 0;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent, priority);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;
    int priority = 0;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent, priority);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;
    int priority = 0;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, id_group);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent, priority);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;
    int priority = 0;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, id_group);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, id_agent);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent, priority);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;
    int priority = 0;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, id_group);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, id_agent);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, priority);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent, priority);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;
    int priority = 0;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, id_group);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, id_agent);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, priority);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent, priority);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_insert_agent_belong_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int id_group = 2;
    int id_agent = 2;
    int priority = 0;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, id_group);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, id_agent);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, priority);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent, priority);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_is_group_empty */

void test_wdb_is_group_empty_stmt_init_group_not_found(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";
    cJSON *result = NULL;

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, SQLITE_OK);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_is_group_empty(data->wdb, group_name);

    assert_null(result);
}

void test_wdb_is_group_empty_stmt_init_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";
    cJSON *result = NULL;

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    result = wdb_is_group_empty(data->wdb, group_name);

    assert_null(result);
}

void test_wdb_is_group_empty_stmt_init_group_found(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";
    cJSON *result = NULL;

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);

    result = wdb_is_group_empty(data->wdb, group_name);

    assert_non_null(result);
}

void test_wdb_is_group_empty_stmt_invalid_result(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";
    cJSON *result = NULL;

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");
    result = wdb_is_group_empty(data->wdb, group_name);

    assert_null(result);
}

/* Tests wdb_global_delete_group */

void test_wdb_global_delete_group_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");
    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");
    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");
    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_recalculate_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "GROUP";
    cJSON *sql_agents_id = cJSON_Parse("[{\"id_agent\":1}]");
    cJSON* j_priority_resp = cJSON_Parse("[{\"id\":0}]");
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, sql_agents_id);

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    will_return(__wrap_w_is_single_node, 1);
    will_return(__wrap_w_is_single_node, 1);

    /* wdb_global_get_agent_max_group_priority */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_PRIORITY_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    cJSON* j_path = __real_cJSON_CreateArray();
    will_return(__wrap_cJSON_CreateArray, j_path);

    //wdb_global_find_group
    will_return(__wrap_wdb_begin2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
    expect_string(__wrap__mwarn, formatted_msg, "Unable to find the id of the group 'default'");
    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap__merror, formatted_msg, "There was an error assigning the agent '001' to default group");
    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap__merror, formatted_msg, "Couldn't recalculate hash group for agent: '001'");
    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
    __real_cJSON_Delete(j_priority_resp);
    __real_cJSON_Delete(j_group_array);
    __real_cJSON_Delete(sql_agents_id);
    __real_cJSON_Delete(j_path);
}

void test_wdb_global_delete_group_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "GROUP";
    char *sync_status = "syncreq";
    cJSON *sql_agents_id = cJSON_Parse("[{\"id_agent\":1}]");
    int agent_id = 1;
    cJSON* j_priority_resp = cJSON_Parse("[{\"id\":0}]");
    char hash[] = "19dcd0dd"; //"GROUP" hash

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, sql_agents_id);

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    will_return(__wrap_w_is_single_node, 0);
    will_return(__wrap_w_is_single_node, 0);

    /* wdb_global_get_agent_max_group_priority */
    create_wdb_global_get_agent_max_group_priority_success_call(agent_id, j_priority_resp);

    /* wdb_global_calculate_agent_group_csv */
    create_wdb_global_calculate_agent_group_csv_success_call(agent_id);

    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, group_name);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    /* wdb_global_set_agent_group_context */
    create_wdb_global_set_agent_group_context_success_call(agent_id, group_name, hash, sync_status);

    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_SUCCESS);
    __real_cJSON_Delete(j_priority_resp);
    __real_cJSON_Delete(sql_agents_id);
}

/* Tests wdb_global_delete_agent_belong */

void test_wdb_global_delete_agent_belong_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_delete_agent_belong(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_belong_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_delete_agent_belong(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_belong_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_delete_agent_belong(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_belong_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_delete_agent_belong(data->wdb, 1);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_agent_belong_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_delete_agent_belong(data->wdb, 1);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_delete_tuple_belong */

void test_wdb_global_delete_tuple_belong_init_stmt_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int group_id = 1;
    int agent_id = 1;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    result = wdb_global_delete_tuple_belong(data->wdb, group_id, agent_id);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_tuple_belong_exec_stmt_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int group_id = 1;
    int agent_id = 1;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, group_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    result = wdb_global_delete_tuple_belong(data->wdb, group_id, agent_id);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_tuple_belong_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    int group_id = 1;
    int agent_id = 1;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, group_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    result = wdb_global_delete_tuple_belong(data->wdb, group_id, agent_id);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_get_agent_info */

void test_wdb_global_get_agent_info_transaction_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    output = wdb_global_get_agent_info(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_info_cache_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    output = wdb_global_get_agent_info(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_info_bind_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    output = wdb_global_get_agent_info(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_info_exec_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_wdb_exec_stmt, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    output = wdb_global_get_agent_info(data->wdb, 1);
    assert_null(output);
}

void test_wdb_global_get_agent_info_success(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);

    output = wdb_global_get_agent_info(data->wdb, 1);
    assert_ptr_equal(output, (cJSON*)1);
}

/* Tests wdb_global_get_agents_to_disconnect */

void test_wdb_global_get_agents_to_disconnect_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_to_disconnect_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_to_disconnect_bind1_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_to_disconnect_bind2_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_to_disconnect_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    int keepalive = 0;
    const char *sync_status = "synced";
    cJSON* root = __real_cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_success_call(root, STMT_MULTI_COLUMN);

    //Setting agents as disconnected
    for (int i=0; i<agents_amount; i++){
        will_return(__wrap_time, (time_t)0);
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_text, pos, 1);
        expect_string(__wrap_sqlite3_bind_text, buffer, "disconnected");
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_text, pos, 2);
        expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

        // wdb_global_get_sync_status
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_int, index, 1);
        expect_value(__wrap_sqlite3_bind_int, value, i);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        will_return(__wrap_wdb_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, "synced");

        expect_value(__wrap_sqlite3_bind_int, index, 3);
        expect_value(__wrap_sqlite3_bind_int, value, (time_t)0);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 4);
        expect_value(__wrap_sqlite3_bind_int, value, NO_KEEPALIVE);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 5);
        expect_in_range(__wrap_sqlite3_bind_int, value, 0, agents_amount);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
    }

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_OK);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_to_disconnect_due(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";
    cJSON* root = __real_cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_socket_full_call(root, STMT_MULTI_COLUMN);

    //Setting agents as disconnected
    for (int i=0; i<agents_amount; i++){
        will_return(__wrap_time, (time_t)0);
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_text, pos, 1);
        expect_string(__wrap_sqlite3_bind_text, buffer, "disconnected");
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_text, pos, 2);
        expect_string(__wrap_sqlite3_bind_text, buffer, "synced");
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

        // wdb_global_get_sync_status
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_int, index, 1);
        expect_value(__wrap_sqlite3_bind_int, value, i);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        will_return(__wrap_wdb_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, "synced");

        expect_value(__wrap_sqlite3_bind_int, index, 3);
        expect_value(__wrap_sqlite3_bind_int, value, (time_t)0);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 4);
        expect_value(__wrap_sqlite3_bind_int, value, NO_KEEPALIVE);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 5);
        expect_in_range(__wrap_sqlite3_bind_int, value, 0, agents_amount);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
    }

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_DUE);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_to_disconnect_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 0;
    const char *sync_status = "synced";

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_failed_call(STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_to_disconnect_invalid_elements(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";
    cJSON* root = __real_cJSON_CreateArray();
    cJSON* json_agent = cJSON_CreateObject();
    cJSON_AddItemToArray(root, json_agent);

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_success_call(root, STMT_MULTI_COLUMN);
    //Element error
    expect_string(__wrap__merror, formatted_msg, "Invalid element returned by disconnect query");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_to_disconnect_update_status_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int keepalive = 100;
    const char *sync_status = "synced";
    cJSON* root = __real_cJSON_CreateArray();
    cJSON* json_agent = cJSON_CreateObject();
    cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(10));
    cJSON_AddItemToArray(root, json_agent);

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, keepalive);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_success_call(root, STMT_MULTI_COLUMN);
    //Disconnect query error
    will_return(__wrap_time, (time_t)0);
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_string(__wrap__merror, formatted_msg, "Cannot set connection_status for agent 10");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(data->wdb, last_id, keepalive, sync_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

/* Tests wdb_global_get_all_agents */

void test_wdb_global_get_all_agents_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_all_agents_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_all_agents_bind_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_all_agents_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    cJSON* root = __real_cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_success_call(root, STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_OK);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_all_agents_due(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    cJSON* root = __real_cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);

    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_socket_full_call(root, STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_DUE);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_all_agents_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_failed_call(STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_all_agents(data->wdb, last_id, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

/* Tests wdb_global_reset_agents_connection */

void test_wdb_global_reset_agents_connection_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_reset_agents_connection_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_reset_agents_connection_bind1_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);


    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, RESET_BY_MANAGER);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_reset_agents_connection_bind2_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);


    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, RESET_BY_MANAGER);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_reset_agents_step_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, RESET_BY_MANAGER);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_reset_agents_connection_success(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, RESET_BY_MANAGER);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_get_agents_by_connection_status */

void test_wdb_global_get_agents_by_connection_status_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, NULL, -1, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, NULL, -1, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_and_node_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";
    const char node_name[] = "node01";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, node_name, -1, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_bind1_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, NULL, -1, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_bind2_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, NULL, -1, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_and_node_bind3_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";
    const char node_name[] = "node01";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, node_name, -1, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_and_node_bind4_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int limit = -1;
    const char connection_status[] = "active";
    const char node_name[] = "node01";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, limit);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, node_name, -1, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    const char connection_status[] = "active";
    cJSON* root = __real_cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_success_call(root, STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, NULL, -1, &status);

    assert_int_equal(status, WDBC_OK);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_by_connection_status_and_node_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    int limit = -1;
    const char connection_status[] = "active";
    const char node_name[] = "node01";
    cJSON* root = __real_cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, limit);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_success_call(root, STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, node_name, -1, &status);

    assert_int_equal(status, WDBC_OK);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_by_connection_status_due(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    const char connection_status[] = "active";
    cJSON* root = __real_cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_socket_full_call(root, STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, NULL, -1, &status);

    assert_int_equal(status, WDBC_DUE);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_by_connection_status_and_node_due(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    int limit = -1;
    const char connection_status[] = "active";
    const char node_name[] = "node01";
    cJSON* root = __real_cJSON_CreateArray();
    for (int i=0; i<agents_amount; i++){
        cJSON* json_agent = cJSON_CreateObject();
        cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(i));
        cJSON_AddItemToArray(root, json_agent);
    }

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, limit);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_socket_full_call(root, STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, node_name, -1, &status);

    assert_int_equal(status, WDBC_DUE);
    assert_non_null(result);

    __real_cJSON_Delete(root);
}

void test_wdb_global_get_agents_by_connection_status_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    const char connection_status[] = "active";

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_failed_call(STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, NULL, -1, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_and_node_err(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int last_id = 0;
    int limit = -1;
    const char connection_status[] = "active";
    const char node_name[] = "node01";

    //Preparing statement
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, connection_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, node_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, limit);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    //Executing statement
    wrap_wdb_exec_stmt_sized_failed_call(STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, node_name, -1, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

/* Tests wdb_global_create_backup */

void test_wdb_global_create_backup_commit_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char* test_date = strdup("2015/11/23 12:00:00");

    will_return(__wrap_time, (time_t)0);
    expect_value(__wrap_w_get_timestamp, time, 0);
    will_return(__wrap_w_get_timestamp, test_date);
    will_return(__wrap_wdb_commit2, OS_INVALID);

    result = wdb_global_create_backup(data->wdb, data->output, "-tag");

    assert_string_equal(data->output, "err Cannot commit current transaction to create backup");
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_create_backup_prepare_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char* test_date = strdup("2015/11/23 12:00:00");

    will_return(__wrap_time, (time_t)0);
    expect_value(__wrap_w_get_timestamp, time, 0);
    will_return(__wrap_w_get_timestamp, test_date);
    will_return(__wrap_wdb_commit2, OS_SUCCESS);
    expect_function_call(__wrap_wdb_finalize_all_statements);
    will_return(__wrap_sqlite3_prepare_v2, NULL);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    result = wdb_global_create_backup(data->wdb, data->output, "-tag");

    assert_string_equal(data->output, "err DB(global) sqlite3_prepare_v2(): ERROR MESSAGE");
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_create_backup_bind_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char* test_date = strdup("2015/11/23 12:00:00");

    will_return(__wrap_time, (time_t)0);
    expect_value(__wrap_w_get_timestamp, time, 0);
    will_return(__wrap_w_get_timestamp, test_date);
    will_return(__wrap_wdb_commit2, OS_SUCCESS);
    expect_function_call(__wrap_wdb_finalize_all_statements);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "backup/db/global.db-backup-2015-11-23-12:00:00-tag");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    result = wdb_global_create_backup(data->wdb, data->output, "-tag");

    assert_string_equal(data->output, "err DB(global) sqlite3_bind_text(): ERROR MESSAGE");
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_create_backup_exec_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char* test_date = strdup("2015/11/23 12:00:00");

    will_return(__wrap_time, (time_t)0);
    expect_value(__wrap_w_get_timestamp, time, 0);
    will_return(__wrap_w_get_timestamp, test_date);
    will_return(__wrap_wdb_commit2, OS_SUCCESS);
    expect_function_call(__wrap_wdb_finalize_all_statements);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "backup/db/global.db-backup-2015-11-23-12:00:00-tag");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    result = wdb_global_create_backup(data->wdb, data->output, "-tag");

    assert_string_equal(data->output, "err SQLite: ERROR MESSAGE");
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_create_backup_compress_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char* test_date = strdup("2015/11/23 12:00:00");

    will_return(__wrap_time, (time_t)0);
    expect_value(__wrap_w_get_timestamp, time, 0);
    will_return(__wrap_w_get_timestamp, test_date);
    will_return(__wrap_wdb_commit2, OS_SUCCESS);
    expect_function_call(__wrap_wdb_finalize_all_statements);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "backup/db/global.db-backup-2015-11-23-12:00:00-tag");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_string(__wrap_w_compress_gzfile, filesrc, "backup/db/global.db-backup-2015-11-23-12:00:00-tag");
    expect_string(__wrap_w_compress_gzfile, filedst, "backup/db/global.db-backup-2015-11-23-12:00:00-tag.gz");
    will_return(__wrap_w_compress_gzfile, OS_INVALID);
    expect_string(__wrap_unlink, file, "backup/db/global.db-backup-2015-11-23-12:00:00-tag");
    will_return(__wrap_unlink, OS_SUCCESS);

    result = wdb_global_create_backup(data->wdb, data->output, "-tag");

    assert_string_equal(data->output, "err Failed during database backup compression");
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_create_backup_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char* test_date = strdup("2015/11/23 12:00:00");

    will_return(__wrap_time, (time_t)0);
    expect_value(__wrap_w_get_timestamp, time, 0);
    will_return(__wrap_w_get_timestamp, test_date);
    will_return(__wrap_wdb_commit2, OS_SUCCESS);
    expect_function_call(__wrap_wdb_finalize_all_statements);
    will_return(__wrap_sqlite3_prepare_v2, 1);
    will_return(__wrap_sqlite3_prepare_v2, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "backup/db/global.db-backup-2015-11-23-12:00:00-tag");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
    will_return(__wrap_sqlite3_finalize, SQLITE_OK);

    expect_string(__wrap_w_compress_gzfile, filesrc, "backup/db/global.db-backup-2015-11-23-12:00:00-tag");
    expect_string(__wrap_w_compress_gzfile, filedst, "backup/db/global.db-backup-2015-11-23-12:00:00-tag.gz");
    will_return(__wrap_w_compress_gzfile, OS_SUCCESS);
    expect_string(__wrap_unlink, file, "backup/db/global.db-backup-2015-11-23-12:00:00-tag");
    will_return(__wrap_unlink, OS_SUCCESS);
    expect_string(__wrap__minfo, formatted_msg, "Created Global database backup \"backup/db/global.db-backup-2015-11-23-12:00:00-tag.gz\"");
    cJSON* j_path = __real_cJSON_CreateArray();
    will_return(__wrap_cJSON_CreateArray, j_path);
    expect_function_call(__wrap_cJSON_Delete);

    // wdb_global_remove_old_backups
    will_return(__wrap_opendir, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to open backup directory 'backup/db'");

    result = wdb_global_create_backup(data->wdb, data->output, "-tag");

    assert_string_equal(data->output, "ok [\"backup/db/global.db-backup-2015-11-23-12:00:00-tag.gz\"]");
    assert_int_equal(result, OS_SUCCESS);
    __real_cJSON_Delete(j_path);
}

/* Tests wdb_global_remove_old_backups */

void test_wdb_global_remove_old_backups_opendir_failed(void **state) {
    int result = OS_INVALID;

    will_return(__wrap_opendir, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to open backup directory 'backup/db'");

    result = wdb_global_remove_old_backups();

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_remove_old_backups_success_without_removing(void **state) {
    int result = OS_INVALID;

    will_return(__wrap_opendir, (DIR*)1);
    will_return(__wrap_readdir, NULL);

    result = wdb_global_remove_old_backups();

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_global_remove_old_backups_success(void **state) {
    int result = OS_INVALID;
    struct dirent* entry = calloc(1, sizeof(struct dirent));

    snprintf(entry->d_name, OS_SIZE_256, "%s", "global.db-backup-TIMESTAMP");

    will_return(__wrap_opendir, (DIR*)1);
    // To delete a backup, it must find at least one more than max_files
    wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->max_files = 3;
    will_return_count(__wrap_readdir, entry, 4);
    will_return(__wrap_readdir, NULL);

    /* wdb_global_get_oldest_backup */
    test_mode = 1;
    will_return(__wrap_opendir, (DIR*)1);
    will_return(__wrap_readdir, entry);
    will_return(__wrap_readdir, NULL);
    will_return(__wrap_time, (time_t)0);
    struct stat* file_info = calloc(1, sizeof(struct stat));
    file_info->st_mtime = 0;
    expect_string(__wrap_stat, __file, "backup/db/global.db-backup-TIMESTAMP");
    will_return(__wrap_stat, file_info);
    will_return(__wrap_stat, OS_SUCCESS);

    expect_string(__wrap_unlink, file, "backup/db/global.db-backup-TIMESTAMP");
    will_return(__wrap_unlink, OS_SUCCESS);
    expect_string(__wrap__minfo, formatted_msg, "Deleted Global database backup: \"backup/db/global.db-backup-TIMESTAMP\"");

    result = wdb_global_remove_old_backups();

    assert_int_equal(result, OS_SUCCESS);
    os_free(entry);
    os_free(file_info);
    test_mode = 0;
}

/* Tests wdb_global_get_backups */

void test_wdb_global_get_backups_opendir_failed(void **state) {
    cJSON* j_result = NULL;

    will_return(__wrap_opendir, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to open backup directory 'backup/db'");

    j_result = wdb_global_get_backups();

    assert_ptr_equal(j_result, NULL);
}

void test_wdb_global_get_backups_success(void **state) {
    cJSON* j_result = NULL;
    struct dirent* entry = calloc(1, sizeof(struct dirent));

    snprintf(entry->d_name, OS_SIZE_256, "%s", "global.db-backup-TIMESTAMP");

    will_return(__wrap_opendir, (DIR*)1);
    will_return_count(__wrap_readdir, entry, 2);
    will_return(__wrap_readdir, NULL);

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());
    j_result = wdb_global_get_backups();

    char* str_result = cJSON_PrintUnformatted(j_result);
    assert_string_equal(str_result, "[\"global.db-backup-TIMESTAMP\",\"global.db-backup-TIMESTAMP\"]");
    os_free(entry);
    os_free(str_result);
    __real_cJSON_Delete(j_result);
}

/* Tests wdb_global_restore_backup */

void test_wdb_global_restore_backup_pre_restore_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char* test_date = strdup("2015/11/23 12:00:00");

    will_return(__wrap_time, (time_t)0);
    expect_value(__wrap_w_get_timestamp, time, 0);
    will_return(__wrap_w_get_timestamp, test_date);
    will_return(__wrap_wdb_commit2, OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "Creating pre-restore Global DB snapshot failed. Backup restore stopped: "
                                                 "err Cannot commit current transaction to create backup");

    result = wdb_global_restore_backup(&data->wdb, "global.db-backup-TIMESTAMP", true, data->output);

    assert_string_equal(data->output, "err Cannot commit current transaction to create backup");
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_restore_backup_no_snapshot(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;

    // wdb_global_get_most_recent_backup
    will_return(__wrap_opendir, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to open backup directory 'backup/db'");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to found a snapshot to restore");

    result = wdb_global_restore_backup(&data->wdb, NULL, false, data->output);

    assert_string_equal(data->output, "err Unable to found a snapshot to restore");
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_restore_backup_compression_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, "backup/db/global.db-backup-TIMESTAMP.gz");
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, "queue/db/global.db.back");
    will_return(__wrap_w_uncompress_gzfile, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Failed during backup decompression");

    result = wdb_global_restore_backup(&data->wdb, "global.db-backup-TIMESTAMP.gz", false, data->output);

    assert_string_equal(data->output, "err Failed during backup decompression");
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_restore_backup_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    wdb_t *wdb = NULL;
    os_calloc(1,sizeof(wdb_t),wdb);
    os_strdup("global",wdb->id);
    os_calloc(1,sizeof(sqlite3 *),wdb->db);

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, "backup/db/global.db-backup-TIMESTAMP.gz");
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, "queue/db/global.db.back");
    will_return(__wrap_w_uncompress_gzfile, OS_SUCCESS);
    will_return(__wrap_wdb_close, 1);
    will_return(__wrap_wdb_close, OS_SUCCESS);
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, OS_SUCCESS);
    expect_string(__wrap_rename, __old, "queue/db/global.db.back");
    expect_string(__wrap_rename, __new, "queue/db/global.db");
    will_return(__wrap_rename, OS_SUCCESS);

    result = wdb_global_restore_backup(&wdb, "global.db-backup-TIMESTAMP.gz", false, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(result, OS_SUCCESS);
    os_free(wdb->id);
    os_free(wdb);
}

/* Tests wdb_global_get_most_recent_backup */

void test_wdb_global_get_most_recent_backup_opendir_failed(void **state) {
    char* most_recent_backup_name = NULL;
    time_t most_recent_backup_time = OS_INVALID;

    will_return(__wrap_opendir, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to open backup directory 'backup/db'");

    most_recent_backup_time = wdb_global_get_most_recent_backup(&most_recent_backup_name);

    assert_int_equal(most_recent_backup_time, OS_INVALID);
    assert_ptr_equal(most_recent_backup_name, NULL);
}

void test_wdb_global_get_most_recent_backup_success(void **state) {
    char* most_recent_backup_name = NULL;
    time_t most_recent_backup_time = OS_INVALID;
    struct dirent* entry = calloc(1, sizeof(struct dirent));
    struct stat* file_info = calloc(1, sizeof(struct stat));

    test_mode = 1;
    snprintf(entry->d_name, OS_SIZE_256, "%s", "global.db-backup-TIMESTAMP");
    will_return(__wrap_opendir, (DIR*)1);
    will_return(__wrap_readdir, entry);
    will_return(__wrap_readdir, NULL);
    file_info->st_mtime = 123;
    expect_string(__wrap_stat, __file, "backup/db/global.db-backup-TIMESTAMP");
    will_return(__wrap_stat, file_info);
    will_return(__wrap_stat, OS_SUCCESS);

    most_recent_backup_time = wdb_global_get_most_recent_backup(&most_recent_backup_name);

    assert_int_equal(most_recent_backup_time, 123);
    assert_string_equal(most_recent_backup_name, "global.db-backup-TIMESTAMP");
    os_free(most_recent_backup_name);
    os_free(entry);
    os_free(file_info);
    test_mode = 0;
}

/* Tests wdb_global_get_oldest_backup */

void test_wdb_global_get_oldest_backup_opendir_failed(void **state) {
    char* oldest_backup_name = NULL;
    time_t oldest_backup_time = OS_INVALID;

    will_return(__wrap_opendir, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to open backup directory 'backup/db'");

    oldest_backup_time = wdb_global_get_oldest_backup(&oldest_backup_name);

    assert_int_equal(oldest_backup_time, OS_INVALID);
    assert_ptr_equal(oldest_backup_name, NULL);
}

void test_wdb_global_get_oldest_backup_success(void **state) {
    char* oldest_backup_name = NULL;
    time_t oldest_backup_time = OS_INVALID;
    struct dirent* entry = calloc(1, sizeof(struct dirent));
    struct stat* file_info = calloc(1, sizeof(struct stat));

    test_mode = 1;
    will_return(__wrap_opendir, (DIR*)1);
    will_return(__wrap_time, (time_t)123);
    snprintf(entry->d_name, OS_SIZE_256, "%s", "global.db-backup-TIMESTAMP");
    will_return(__wrap_readdir, entry);
    will_return(__wrap_readdir, NULL);
    file_info->st_mtime = 123;
    expect_string(__wrap_stat, __file, "backup/db/global.db-backup-TIMESTAMP");
    will_return(__wrap_stat, file_info);
    will_return(__wrap_stat, OS_SUCCESS);

    oldest_backup_time = wdb_global_get_oldest_backup(&oldest_backup_name);

    assert_int_equal(oldest_backup_time, 123);
    assert_string_equal(oldest_backup_name, "global.db-backup-TIMESTAMP");
    os_free(oldest_backup_name);
    os_free(entry);
    os_free(file_info);
    test_mode = 0;
}

/* Tests wdb_global_update_agent_groups_hash */

void test_wdb_global_update_agent_groups_hash_begin_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *groups_string = "group1,group2";

    data->wdb->transaction = 0;
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
    will_return(__wrap_wdb_begin2, OS_INVALID);

    int result = wdb_global_update_agent_groups_hash(data->wdb, agent_id, groups_string);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_groups_hash_cache_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *groups_string = "group1,group2";

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    int result = wdb_global_update_agent_groups_hash(data->wdb, agent_id, groups_string);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_groups_hash_bind_text_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *groups_string = "group1,group2";
    char *groups_string_hash = "ef48b4cd";

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, groups_string_hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    int result = wdb_global_update_agent_groups_hash(data->wdb, agent_id, groups_string);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_groups_hash_bind_int_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *groups_string = "group1,group2";
    char *groups_string_hash = "ef48b4cd";

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, groups_string_hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    int result = wdb_global_update_agent_groups_hash(data->wdb, agent_id, groups_string);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_groups_hash_step_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *groups_string = "group1,group2";
    char *groups_string_hash = "ef48b4cd";

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, groups_string_hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);

    int result = wdb_global_update_agent_groups_hash(data->wdb, agent_id, groups_string);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_agent_groups_hash_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *groups_string = "group1,group2";
    char *groups_string_hash = "ef48b4cd";

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, groups_string_hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    int result = wdb_global_update_agent_groups_hash(data->wdb, agent_id, groups_string);

    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_global_update_agent_groups_hash_groups_string_null_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char *groups_string = "group1,group2";
    char *groups_string_hash = "ef48b4cd";
    data->wdb->transaction = 1;

    // wdb_global_select_agent_group
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    cJSON *j_result = __real_cJSON_CreateArray();
    cJSON *j_object = cJSON_CreateObject();
    cJSON_AddItemToObject(j_object, "group", cJSON_CreateString(groups_string));
    cJSON_AddItemToArray(j_result, j_object);
    will_return(__wrap_wdb_exec_stmt, j_result);
    expect_function_call(__wrap_cJSON_Delete);

    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, groups_string_hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    int result = wdb_global_update_agent_groups_hash(data->wdb, agent_id, NULL);

    assert_int_equal(result, OS_SUCCESS);
    __real_cJSON_Delete(j_result);
}

void test_wdb_global_update_agent_groups_hash_empty_group_column_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    data->wdb->transaction = 1;

    // wdb_global_select_agent_group
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    cJSON *j_result = __real_cJSON_CreateArray();
    cJSON *j_object = cJSON_CreateObject();
    cJSON_AddItemToArray(j_result, j_object);
    will_return(__wrap_wdb_exec_stmt, j_result);
    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap__mdebug2, formatted_msg, "Unable to get group column for agent '1'. The groups_hash column won't be updated");

    int result = wdb_global_update_agent_groups_hash(data->wdb, agent_id, NULL);

    assert_int_equal(result, OS_SUCCESS);
    __real_cJSON_Delete(j_result);
}

/* Tests wdb_global_adjust_v4 */

void test_wdb_global_adjust_v4_begin_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->wdb->transaction = 0;
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
    will_return(__wrap_wdb_begin2, OS_INVALID);

    int result = wdb_global_adjust_v4(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_adjust_v4_cache_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    int result = wdb_global_adjust_v4(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_adjust_v4_bind_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    int result = wdb_global_adjust_v4(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_adjust_v4_step_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    int result = wdb_global_adjust_v4(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_adjust_v4_commit_fail(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, agent_id);

    // wdb_global_select_agent_group
    char *groups_string = "group1,group2";
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    cJSON *j_result = __real_cJSON_CreateArray();
    cJSON *j_object = cJSON_CreateObject();
    cJSON_AddItemToObject(j_object, "group", cJSON_CreateString(groups_string));
    cJSON_AddItemToArray(j_result, j_object);
    will_return(__wrap_wdb_exec_stmt, j_result);
    expect_function_call(__wrap_cJSON_Delete);

    // wdb_global_update_agent_groups_hash
    char *groups_string_hash = "ef48b4cd";
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, groups_string_hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_commit2, OS_INVALID);
    expect_string(__wrap__merror, formatted_msg, "DB(global) The commit statement could not be executed.");

    int result = wdb_global_adjust_v4(data->wdb);

    assert_int_equal(result, OS_INVALID);
    __real_cJSON_Delete(j_result);
}

void test_wdb_global_adjust_v4_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, agent_id);

    // wdb_global_select_agent_group
    char *groups_string = "group1,group2";
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    cJSON *j_result = __real_cJSON_CreateArray();
    cJSON *j_object = cJSON_CreateObject();
    cJSON_AddItemToObject(j_object, "group", cJSON_CreateString(groups_string));
    cJSON_AddItemToArray(j_result, j_object);
    will_return(__wrap_wdb_exec_stmt, j_result);
    expect_function_call(__wrap_cJSON_Delete);

    // wdb_global_update_agent_groups_hash
    char *groups_string_hash = "ef48b4cd";
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, groups_string_hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    will_return(__wrap_wdb_step, SQLITE_DONE);


    will_return(__wrap_wdb_commit2, OS_SUCCESS);

    int result = wdb_global_adjust_v4(data->wdb);

    assert_int_equal(result, OS_SUCCESS);
    __real_cJSON_Delete(j_result);
}

/* Tests wdb_global_calculate_agent_group_csv */

void test_wdb_global_calculate_agent_group_csv_unable_to_get_group(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    // wdb_global_select_group_belong
    data->wdb->transaction = 0;
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
    will_return(__wrap_wdb_begin2, OS_INVALID);

    char *result = wdb_global_calculate_agent_group_csv(data->wdb, agent_id);

    assert_ptr_equal(result, NULL);
}

void test_wdb_global_calculate_agent_group_csv_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    cJSON *j_groups = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_groups, cJSON_CreateString("group1"));
    cJSON_AddItemToArray(j_groups, cJSON_CreateString("group2"));

    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "group1");
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "group2");
    will_return(__wrap_wdb_step, SQLITE_DONE);

    char *result = wdb_global_calculate_agent_group_csv(data->wdb, agent_id);

    assert_string_equal(result, "group1,group2");
    os_free(result);
    __real_cJSON_Delete(j_groups);
}

/* wdb_global_assign_agent_group */

void test_wdb_global_assign_agent_group_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    int initial_priority = 0;
    int actual_priority = initial_priority;
    cJSON* find_group_resp = cJSON_Parse("[{\"id\":1}]");
    char group_name[GROUPS_SIZE][OS_SIZE_128] = {0};
    cJSON* j_groups = __real_cJSON_CreateArray();

    for (int i=0; i<GROUPS_SIZE; i++) {
        snprintf(group_name[i], OS_SIZE_128, "GROUP%d", i);
        cJSON_AddItemToArray(j_groups, cJSON_CreateString(group_name[i]));

        // wdb_global_find_group
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_text, pos, 1);
        expect_string(__wrap_sqlite3_bind_text, buffer, group_name[i]);
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        will_return(__wrap_wdb_exec_stmt, find_group_resp);

        expect_function_call(__wrap_cJSON_Delete);

        // wdb_global_insert_agent_belong
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_int, index, group_id);
        expect_value(__wrap_sqlite3_bind_int, value, 1);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 2);
        expect_value(__wrap_sqlite3_bind_int, value, agent_id);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 3);
        expect_value(__wrap_sqlite3_bind_int, value, actual_priority);
        actual_priority++;
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
    }

    wdbc_result result = wdb_global_assign_agent_group(data->wdb, agent_id, j_groups, initial_priority);

    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(find_group_resp);
}

void test_wdb_global_assign_agent_group_insert_belong_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int initial_priority = 0;
    cJSON* find_group_resp = cJSON_Parse("[{\"id\":1}]");
    char debug_message[GROUPS_SIZE][OS_MAXSTR] = {0};
    char group_name[GROUPS_SIZE][OS_SIZE_128] = {0};
    cJSON* j_groups = __real_cJSON_CreateArray();

    for (int i=0; i<GROUPS_SIZE; i++) {
        snprintf(group_name[i], OS_SIZE_128, "GROUP%d", i);
        cJSON_AddItemToArray(j_groups, cJSON_CreateString(group_name[i]));

        // wdb_global_find_group
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_text, pos, 1);
        expect_string(__wrap_sqlite3_bind_text, buffer, group_name[i]);
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        will_return(__wrap_wdb_exec_stmt, find_group_resp);

        expect_function_call(__wrap_cJSON_Delete);

        // wdb_global_insert_agent_belong
        will_return(__wrap_wdb_begin2, OS_INVALID);
        expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
        snprintf(debug_message[i], OS_MAXSTR, "Unable to insert group '%s' for agent '%d'", group_name[i], agent_id);
        expect_string(__wrap__mdebug1, formatted_msg, debug_message[i]);
    }

    wdbc_result result = wdb_global_assign_agent_group(data->wdb, agent_id, j_groups, initial_priority);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(find_group_resp);
}

void test_wdb_global_assign_agent_group_find_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int initial_priority = 0;
    cJSON* find_group_resp = cJSON_Parse("[{\"id\":1}]");
    char warn_message[GROUPS_SIZE][OS_MAXSTR] = {0};
    char group_name[GROUPS_SIZE][OS_SIZE_128] = {0};
    cJSON* j_groups = __real_cJSON_CreateArray();

    for (int i=0; i<GROUPS_SIZE; i++) {
        snprintf(group_name[i], OS_SIZE_128, "GROUP%d", i);
        cJSON_AddItemToArray(j_groups, cJSON_CreateString(group_name[i]));

        // wdb_global_find_group
        will_return(__wrap_wdb_begin2, OS_INVALID);
        expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
        snprintf(warn_message[i], OS_MAXSTR, "Unable to find the id of the group '%s'", group_name[i]);
        expect_string(__wrap__mwarn, formatted_msg, warn_message[i]);
        expect_function_call(__wrap_cJSON_Delete);
    }

    wdbc_result result = wdb_global_assign_agent_group(data->wdb, agent_id, j_groups, initial_priority);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(find_group_resp);
}

void test_wdb_global_assign_agent_group_invalid_json(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int initial_priority = 0;
    cJSON* find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_groups = __real_cJSON_CreateArray();

    for (int i=0; i<GROUPS_SIZE; i++) {
        cJSON_AddItemToArray(j_groups, cJSON_CreateNumber(1));
        expect_string(__wrap__mdebug1, formatted_msg, "Invalid groups set information");
    }

    wdbc_result result = wdb_global_assign_agent_group(data->wdb, agent_id, j_groups, initial_priority);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(find_group_resp);
}

/* wdb_global_unassign_agent_group */

void test_wdb_global_unassign_agent_group_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    cJSON* find_group_resp = cJSON_Parse("[{\"id\":1}]");
    char group_name[GROUPS_SIZE][OS_SIZE_128] = {0};
    cJSON* j_groups = __real_cJSON_CreateArray();
    cJSON* j_priority_resp = cJSON_Parse("[{\"id\":0}]");

    for (int i=0; i<GROUPS_SIZE; i++) {
        snprintf(group_name[i], OS_SIZE_128, "GROUP%d", i);
        cJSON_AddItemToArray(j_groups, cJSON_CreateString(group_name[i]));

        // wdb_global_find_group
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_text, pos, 1);
        expect_string(__wrap_sqlite3_bind_text, buffer, group_name[i]);
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        will_return(__wrap_wdb_exec_stmt, find_group_resp);

        expect_function_call(__wrap_cJSON_Delete);

        // wdb_global_delete_tuple_belong
        expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG);
        will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
        expect_value(__wrap_sqlite3_bind_int, index, 1);
        expect_value(__wrap_sqlite3_bind_int, value, group_id);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 2);
        expect_value(__wrap_sqlite3_bind_int, value, agent_id);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

        /* wdb_global_get_agent_max_group_priority */
        create_wdb_global_get_agent_max_group_priority_success_call(agent_id, j_priority_resp);
    }

    wdbc_result result = wdb_global_unassign_agent_group(data->wdb, agent_id, j_groups);

    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(find_group_resp);
    __real_cJSON_Delete(j_priority_resp);
}

/**
 * @brief Configure all the wrappers to simulate a successful call to wdb_global_assign_agent_group() method
 * @param agent_id The id of the agent being assigned in the belongs table
 * @param group_id The id of the group being assigned in the belongs table
 * @param group_name The name of the group being inserted in the group table
 * @param find_group_resp The response of the find group query
 */
void create_wdb_global_assign_agent_group_success_call(int agent_id, int group_id, char* group_name, cJSON* find_group_resp) {
    int actual_priority = 0;
    // wdb_global_find_group
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, find_group_resp);
    expect_function_call(__wrap_cJSON_Delete);
    // wdb_global_insert_agent_belong
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, group_id);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, actual_priority);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);
}

void test_wdb_global_unassign_agent_group_success_assign_default_group(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_groups = __real_cJSON_CreateArray();
    cJSON* j_priority_resp = cJSON_Parse("[{\"id\":-1}]");

    cJSON_AddItemToArray(j_groups, cJSON_CreateString("random_group"));

    // wdb_global_find_group
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "random_group");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, j_find_group_resp);

    expect_function_call(__wrap_cJSON_Delete);

    // wdb_global_delete_tuple_belong
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, group_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    /* wdb_global_get_agent_max_group_priority */
    create_wdb_global_get_agent_max_group_priority_success_call(agent_id, j_priority_resp);

    cJSON* j_default_group = __real_cJSON_CreateArray();
    will_return(__wrap_cJSON_CreateArray, j_default_group);
    expect_function_call(__wrap_cJSON_Delete);

    /* wdb_global_assign_agent_group */
    create_wdb_global_assign_agent_group_success_call(agent_id, group_id, "default", j_find_group_resp);
    expect_string(__wrap__mdebug1, formatted_msg, "Agent '001' reassigned to 'default' group");

    wdbc_result result = wdb_global_unassign_agent_group(data->wdb, agent_id, j_groups);

    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_priority_resp);
    __real_cJSON_Delete(j_default_group);
}

void test_wdb_global_unassign_agent_group_delete_tuple_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    cJSON* find_group_resp = cJSON_Parse("[{\"id\":1}]");
    char debug_message[GROUPS_SIZE][OS_MAXSTR] = {0};
    char group_name[GROUPS_SIZE][OS_SIZE_128] = {0};
    cJSON* j_groups = __real_cJSON_CreateArray();

    for (int i=0; i<GROUPS_SIZE; i++) {
        snprintf(group_name[i], OS_SIZE_128, "GROUP%d", i);
        cJSON_AddItemToArray(j_groups, cJSON_CreateString(group_name[i]));

        // wdb_global_find_group
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_text, pos, 1);
        expect_string(__wrap_sqlite3_bind_text, buffer, group_name[i]);
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        will_return(__wrap_wdb_exec_stmt, find_group_resp);

        expect_function_call(__wrap_cJSON_Delete);

        // wdb_global_delete_tuple_belong
        expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG);
        will_return(__wrap_wdb_init_stmt_in_cache, NULL);

        snprintf(debug_message[i], OS_MAXSTR, "Unable to delete group '%s' for agent '%d'", group_name[i], agent_id);
        expect_string(__wrap__mdebug1, formatted_msg, debug_message[i]);
    }

    wdbc_result result = wdb_global_unassign_agent_group(data->wdb, agent_id, j_groups);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(find_group_resp);
}

void test_wdb_global_unassign_agent_group_find_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    cJSON* find_group_resp = cJSON_Parse("[{\"id\":1}]");
    char warn_message[GROUPS_SIZE][OS_MAXSTR] = {0};
    char group_name[GROUPS_SIZE][OS_SIZE_128] = {0};
    cJSON* j_groups = __real_cJSON_CreateArray();

    for (int i=0; i<GROUPS_SIZE; i++) {
        snprintf(group_name[i], OS_SIZE_128, "GROUP%d", i);
        cJSON_AddItemToArray(j_groups, cJSON_CreateString(group_name[i]));

        // wdb_global_find_group
        will_return(__wrap_wdb_begin2, OS_INVALID);
        expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
        snprintf(warn_message[i], OS_MAXSTR, "Unable to find the id of the group '%s'", group_name[i]);
        expect_string(__wrap__mwarn, formatted_msg, warn_message[i]);
        expect_function_call(__wrap_cJSON_Delete);
    }

    wdbc_result result = wdb_global_unassign_agent_group(data->wdb, agent_id, j_groups);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(find_group_resp);
}

void test_wdb_global_unassign_agent_group_find_invalid_response(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    cJSON* find_group_resp = cJSON_Parse("[{\"id\":\"invalid\"}]");
    char group_name[GROUPS_SIZE][OS_SIZE_128] = {0};
    cJSON* j_groups = __real_cJSON_CreateArray();

    for (int i=0; i<GROUPS_SIZE; i++) {
        snprintf(group_name[i], OS_SIZE_128, "GROUP%d", i);
        cJSON_AddItemToArray(j_groups, cJSON_CreateString(group_name[i]));

        // wdb_global_find_group
        will_return(__wrap_wdb_begin2, 1);
        will_return(__wrap_wdb_stmt_cache, 1);
        expect_value(__wrap_sqlite3_bind_text, pos, 1);
        expect_string(__wrap_sqlite3_bind_text, buffer, group_name[i]);
        will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
        will_return(__wrap_wdb_exec_stmt, find_group_resp);

        expect_string(__wrap__mwarn, formatted_msg, "Invalid response from wdb_global_find_group.");
        expect_function_call(__wrap_cJSON_Delete);
    }

    wdbc_result result = wdb_global_unassign_agent_group(data->wdb, agent_id, j_groups);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(find_group_resp);
}

void test_wdb_global_unassign_agent_group_invalid_json(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    cJSON* find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_groups = __real_cJSON_CreateArray();

    for (int i=0; i<GROUPS_SIZE; i++) {
        cJSON_AddItemToArray(j_groups, cJSON_CreateNumber(1));
        expect_string(__wrap__mdebug1, formatted_msg, "Invalid groups remove information");
    }

    wdbc_result result = wdb_global_unassign_agent_group(data->wdb, agent_id, j_groups);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(find_group_resp);
}

void test_wdb_global_unassign_agent_group_error_assign_default_group(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_groups = __real_cJSON_CreateArray();
    cJSON* j_priority_resp = cJSON_Parse("[{\"id\":-1}]");

    cJSON_AddItemToArray(j_groups, cJSON_CreateString("random_group"));

    // wdb_global_find_group
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "random_group");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, j_find_group_resp);

    expect_function_call(__wrap_cJSON_Delete);

    // wdb_global_delete_tuple_belong
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, group_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    /* wdb_global_get_agent_max_group_priority */
    create_wdb_global_get_agent_max_group_priority_success_call(agent_id, j_priority_resp);

    cJSON* j_default_group = __real_cJSON_CreateArray();
    will_return(__wrap_cJSON_CreateArray, j_default_group);
    expect_function_call(__wrap_cJSON_Delete);

    /* wdb_global_if_empty_set_default_agent_group */
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "default");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, j_find_group_resp);
    expect_function_call(__wrap_cJSON_Delete);

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to insert group 'default' for agent '1'");

    expect_string(__wrap__merror, formatted_msg, "There was an error assigning the agent '001' to default group");

    wdbc_result result = wdb_global_unassign_agent_group(data->wdb, agent_id, j_groups);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_priority_resp);
    __real_cJSON_Delete(j_default_group);
}

/* wdb_global_set_agent_group_context */

void test_wdb_global_set_agent_group_context_success(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char* csv = "GROUP1,GROUP2,GROUP3";
    char* hash = "DUMMYHASH";
    char* sync_status = "synced";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_CTX_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, csv);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    wdbc_result result = wdb_global_set_agent_group_context(data->wdb, agent_id, csv, hash, sync_status);

    assert_int_equal(result, WDBC_OK);
}

void test_wdb_global_set_agent_group_context_init_stmt_error(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char* csv = "GROUP1,GROUP2,GROUP3";
    char* hash = "DUMMYHASH";
    char* sync_status = "synced";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_CTX_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    wdbc_result result = wdb_global_set_agent_group_context(data->wdb, agent_id, csv, hash, sync_status);

    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_set_agent_group_context_exec_stmt_error(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char* csv = "GROUP1,GROUP2,GROUP3";
    char* hash = "DUMMYHASH";
    char* sync_status = "synced";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_CTX_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, csv);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "Error executing setting the agent group context: ERROR MESSAGE");

    wdbc_result result = wdb_global_set_agent_group_context(data->wdb, agent_id, csv, hash, sync_status);

    assert_int_equal(result, WDBC_ERROR);
}

/* wdb_global_set_agent_group_hash */

void test_wdb_global_set_agent_group_hash_success(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char* csv = "GROUP1,GROUP2,GROUP3";
    char* hash = "DUMMYHASH";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_HASH_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, csv);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    wdbc_result result = wdb_global_set_agent_group_hash(data->wdb, agent_id, csv, hash);

    assert_int_equal(result, WDBC_OK);
}

void test_wdb_global_set_agent_group_hash_init_stmt_error(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char* csv = "GROUP1,GROUP2,GROUP3";
    char* hash = "DUMMYHASH";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_HASH_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    wdbc_result result = wdb_global_set_agent_group_hash(data->wdb, agent_id, csv, hash);

    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_global_set_agent_group_hash_exec_stmt_error(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char* csv = "GROUP1,GROUP2,GROUP3";
    char* hash = "DUMMYHASH";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_HASH_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, csv);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, hash);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt_silent, OS_INVALID);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "Error executing setting the agent group hash: ERROR MESSAGE");

    wdbc_result result = wdb_global_set_agent_group_hash(data->wdb, agent_id, csv, hash);

    assert_int_equal(result, WDBC_ERROR);
}

/* Tests wdb_global_groups_number_get */

void test_wdb_global_groups_number_get_stmt_error(void **state)
{
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    result = wdb_global_groups_number_get(data->wdb, agent_id);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_groups_number_get_bind_fail(void **state)
{
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_groups_number_get(data->wdb, agent_id);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_groups_number_get_exec_fail(void **state)
{
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_groups_number_get(data->wdb, agent_id);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_groups_number_get_success(void **state)
{
    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    cJSON *j_groups_number = cJSON_Parse("[{\"groups_number\":100}]");

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt, j_groups_number);
    expect_function_call(__wrap_cJSON_Delete);

    result = wdb_global_groups_number_get(data->wdb, agent_id);

    assert_int_equal(result, 100);
    __real_cJSON_Delete(j_groups_number);
}

/* wdb_global_validate_group_name */

void test_wdb_global_validate_group_name_fail_group_name_contains_invalid_character_1(void **state)
{
    char *group_name = "group_name,with_comma";

    expect_string(__wrap__mwarn, formatted_msg, "Invalid group name. 'group_name,with_comma' "
                                                "contains invalid characters");

    w_err_t result = wdb_global_validate_group_name(group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_validate_group_name_fail_group_name_contains_invalid_character_2(void **state)
{
    char *group_name = "group_name/with_slash";

    expect_string(__wrap__mwarn, formatted_msg, "Invalid group name. 'group_name/with_slash' "
                                                "contains invalid characters");

    w_err_t result = wdb_global_validate_group_name(group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_validate_group_name_fail_group_name_exceeds_max_length(void **state)
{
    char *group_name = "zrosiZrfyMMKt9Lw9qMTCO45OsaFG0NOiHn8noYsuuXHCqPCeDpFE3NxZt8mb44g6G36xL4y59TA_7obQfkSwjczMp9vrNZI9Jltc_8k322ZApibRftAi_T6SD9-AD0YwY_eWbG-uSfYw7BFX2OAgkD2vp3Z9AgZsN3NQNiDG1ng5WNm5H_bbLh6_BtotzJfNYr8awmZ62IuhTH6eNLN9yzn4ZhWt_XxaHUe6O-uf68PNh4HMv3NuvDGFFXBkysN";

    expect_string(__wrap__mwarn, formatted_msg, "Invalid group name. The group 'zrosiZrfyMMKt9Lw9qMTCO45OsaFG0NOiHn8noYsuuXHCqPCeDpFE3NxZt8mb44g"
                                                                               "6G36xL4y59TA_7obQfkSwjczMp9vrNZI9Jltc_8k322ZApibRftAi_T6SD9-AD0Y"
                                                                               "wY_eWbG-uSfYw7BFX2OAgkD2vp3Z9AgZsN3NQNiDG1ng5WNm5H_bbLh6_BtotzJf"
                                                                               "NYr8awmZ62IuhTH6eNLN9yzn4ZhWt_XxaHUe6O-uf68PNh4HMv3NuvDGFFXBkysN'"
                                                " exceeds the maximum length of 255 characters permitted");

    w_err_t result = wdb_global_validate_group_name(group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_validate_group_name_fail_group_name_current_directory_reserved_name(void **state)
{
    char *group_name = ".";

    expect_string(__wrap__mwarn, formatted_msg, "Invalid group name. '.' represents the current directory in unix systems");

    w_err_t result = wdb_global_validate_group_name(group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_validate_group_name_fail_group_name_parent_directory_reserved_name(void **state)
{
    char *group_name = "..";

    expect_string(__wrap__mwarn, formatted_msg, "Invalid group name. '..' represents the parent directory in unix systems");

    w_err_t result = wdb_global_validate_group_name(group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_validate_group_name_success(void **state)
{
    char *group_name = "5eCJIZNU_U8vxPcxPXOrtCM22qKbwz95jvkQVYpHwbz6D9KUIgLyd-Tf1HnBJrAUqI9ytsLdMVA6UhOM6Ej_XAVU9POtKCUzJSHml0g7yOzBnuNxt-8VzL2t5tosAZ7zBImnl0Yq-1LgAVecU_p7yBTw5ZmXg3ZswuCgeVrD0NSk_bwOKMHeRx7XuvIOlJGRC8YO7QeE6Gpc_tK5ZkAty4HyVlMlUI72kQeDAoGK1mhq1LfiUu9VGNFXi6HBGnd";

    w_err_t result = wdb_global_validate_group_name(group_name);

    assert_int_equal(result, OS_SUCCESS);
}

/* wdb_global_validate_groups */

void test_wdb_global_validate_groups_fail_groups_exceeds_max_number(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    cJSON* j_groups = __real_cJSON_CreateArray();
    char group_name[MAX_GROUP_NAME] = {0};

    snprintf(group_name, MAX_GROUP_NAME, "RANDOM_GROUP");
    cJSON_AddItemToArray(j_groups, cJSON_CreateString(group_name));

    /* wdb_global_groups_number_get */
    cJSON *j_groups_number = cJSON_Parse("[{\"groups_number\":128}]");
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, j_groups_number);
    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap__mwarn, formatted_msg, "The groups assigned to agent 001 exceed the maximum of 128 permitted.");

    w_err_t result = wdb_global_validate_groups(data->wdb, j_groups, agent_id);

    assert_int_equal(result, OS_INVALID);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(j_groups_number);
}

void test_wdb_global_validate_groups_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    cJSON* j_groups = __real_cJSON_CreateArray();
    char group_name[MAX_GROUP_NAME+1] = {0};

    snprintf(group_name, MAX_GROUP_NAME+1,
            /* Random 255 characters long group name */
            "5eCJIZNU_U8vxPcxPXOrtCM22qKbwz95jvkQVYpHwbz6D9KUIgLyd-Tf1HnBJrAU"
            "qI9ytsLdMVA6UhOM6Ej_XAVU9POtKCUzJSHml0g7yOzBnuNxt-8VzL2t5tosAZ7z"
            "BImnl0Yq-1LgAVecU_p7yBTw5ZmXg3ZswuCgeVrD0NSk_bwOKMHeRx7XuvIOlJGR"
            "C8YO7QeE6Gpc_tK5ZkAty4HyVlMlUI72kQeDAoGK1mhq1LfiUu9VGNFXi6HBGnd"
            );
    cJSON_AddItemToArray(j_groups, cJSON_CreateString(group_name));

    /* wdb_global_groups_number_get */
    cJSON *j_groups_number = cJSON_Parse("[{\"groups_number\":127}]");
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, j_groups_number);
    expect_function_call(__wrap_cJSON_Delete);

    w_err_t result = wdb_global_validate_groups(data->wdb, j_groups, agent_id);

    assert_int_equal(result, OS_SUCCESS);
    __real_cJSON_Delete(j_groups);
    __real_cJSON_Delete(j_groups_number);
}

/* wdb_global_set_agent_groups */

void test_wdb_global_set_agent_groups_override_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    char group_name[] = "GROUP";
    char hash[] = "19dcd0dd"; //"GROUP" hash
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_OVERRIDE;
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();
    cJSON* j_groups_number = cJSON_Parse("[{\"groups_number\":0}]");

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateNumber(agent_id));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_Duplicate(j_group_array, TRUE));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        /* wdb_global_delete_agent_belong */
        create_wdb_global_delete_agent_belong_success_call(agent_id);

        /* wdb_global_validate_groups_success_call */
        create_wdb_global_validate_groups_success_call(agent_id, j_groups_number);

        /* wdb_global_assign_agent_group */
        create_wdb_global_assign_agent_group_success_call(agent_id, group_id, group_name, j_find_group_resp);

        /* wdb_global_calculate_agent_group_csv */
        create_wdb_global_calculate_agent_group_csv_success_call(agent_id);

        will_return(__wrap_wdb_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, group_name);
        will_return(__wrap_wdb_step, SQLITE_DONE);

        /* wdb_global_set_agent_group_context */
        create_wdb_global_set_agent_group_context_success_call(agent_id, group_name, hash, sync_status);
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_agents_group_info);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_group_array);
    __real_cJSON_Delete(j_groups_number);
}

void test_wdb_global_set_agent_groups_override_delete_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    char group_name[] = "GROUP";
    char hash[] = "19dcd0dd"; //"GROUP" hash
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_OVERRIDE;
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();
    cJSON* j_groups_number = cJSON_Parse("[{\"groups_number\":0}]");

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateNumber(agent_id));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_Duplicate(j_group_array, TRUE));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        /* wdb_global_delete_agent_belong */
        will_return(__wrap_wdb_begin2, -1);
        expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

        expect_string(__wrap__merror, formatted_msg, "There was an error cleaning the previous agent groups");

        /* wdb_global_validate_groups_success_call */
        create_wdb_global_validate_groups_success_call(agent_id, j_groups_number);

        /* wdb_global_assign_agent_group */
        create_wdb_global_assign_agent_group_success_call(agent_id, group_id, group_name, j_find_group_resp);

        /* wdb_global_calculate_agent_group_csv */
        create_wdb_global_calculate_agent_group_csv_success_call(agent_id);

        will_return(__wrap_wdb_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, group_name);
        will_return(__wrap_wdb_step, SQLITE_DONE);

        /* wdb_global_set_agent_group_context */
        create_wdb_global_set_agent_group_context_success_call(agent_id, group_name, hash, sync_status);
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_agents_group_info);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_group_array);
    __real_cJSON_Delete(j_groups_number);
}

void test_wdb_global_set_agent_groups_add_modes_assign_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char group_name[] = "GROUP";
    char hash[] = "19dcd0dd"; //"GROUP" hash
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_OVERRIDE;
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));
    cJSON* j_group_array_invalid = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array_invalid, cJSON_CreateNumber(-1)); //Invalid group information
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();
    cJSON* j_groups_number = cJSON_Parse("[{\"groups_number\":0}]");

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateNumber(agent_id));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_Duplicate(j_group_array_invalid, TRUE));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        /* wdb_global_delete_agent_belong */
        create_wdb_global_delete_agent_belong_success_call(agent_id);

        /* wdb_global_validate_groups_success_call */
        create_wdb_global_validate_groups_success_call(agent_id, j_groups_number);

        /* wdb_global_assign_agent_group */
        expect_string(__wrap__mdebug1, formatted_msg, "Invalid groups set information");
        expect_string(__wrap__merror, formatted_msg, "There was an error assigning the groups to agent '001'");

        /* wdb_global_calculate_agent_group_csv */
        create_wdb_global_calculate_agent_group_csv_success_call(agent_id);

        will_return(__wrap_wdb_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, group_name);
        will_return(__wrap_wdb_step, SQLITE_DONE);

        /* wdb_global_set_agent_group_context */
        create_wdb_global_set_agent_group_context_success_call(agent_id, group_name, hash, sync_status);
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_agents_group_info);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_group_array);
    __real_cJSON_Delete(j_group_array_invalid);
    __real_cJSON_Delete(j_groups_number);
}

void test_wdb_global_set_agent_groups_append_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    char group_name[] = "GROUP";
    char hash[] = "19dcd0dd"; //"GROUP" hash
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_APPEND;
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_priority_resp = cJSON_Parse("[]");
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();
    cJSON* j_groups_number = cJSON_Parse("[{\"groups_number\":0}]");

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateNumber(agent_id));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_Duplicate(j_group_array, TRUE));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        /* wdb_global_get_agent_max_group_priority */
        create_wdb_global_get_agent_max_group_priority_success_call(agent_id, j_priority_resp);

        /* wdb_global_validate_groups_success_call */
        create_wdb_global_validate_groups_success_call(agent_id, j_groups_number);

        /* wdb_global_assign_agent_group */
        create_wdb_global_assign_agent_group_success_call(agent_id, group_id, group_name, j_find_group_resp);

        /* wdb_global_calculate_agent_group_csv */
        create_wdb_global_calculate_agent_group_csv_success_call(agent_id);

        will_return(__wrap_wdb_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, group_name);
        will_return(__wrap_wdb_step, SQLITE_DONE);

        /* wdb_global_set_agent_group_context */
        create_wdb_global_set_agent_group_context_success_call(agent_id, group_name, hash, sync_status);
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_agents_group_info);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_priority_resp);
    __real_cJSON_Delete(j_group_array);
    __real_cJSON_Delete(j_groups_number);
}

void test_wdb_global_set_agent_groups_empty_only_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    char group_name[] = "GROUP";
    char hash[] = "19dcd0dd"; //"GROUP" hash
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_EMPTY_ONLY;
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_priority_resp = cJSON_Parse("[]");
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();
    cJSON* j_groups_number = cJSON_Parse("[{\"groups_number\":0}]");

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateNumber(agent_id));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_Duplicate(j_group_array, TRUE));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        /* wdb_global_get_agent_max_group_priority */
        create_wdb_global_get_agent_max_group_priority_success_call(agent_id, j_priority_resp);

        /* wdb_global_validate_groups_success_call */
        create_wdb_global_validate_groups_success_call(agent_id, j_groups_number);

        /* wdb_global_assign_agent_group */
        create_wdb_global_assign_agent_group_success_call(agent_id, group_id, group_name, j_find_group_resp);

        /* wdb_global_calculate_agent_group_csv */
        create_wdb_global_calculate_agent_group_csv_success_call(agent_id);

        will_return(__wrap_wdb_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, group_name);
        will_return(__wrap_wdb_step, SQLITE_DONE);

        /* wdb_global_set_agent_group_context */
        create_wdb_global_set_agent_group_context_success_call(agent_id, group_name, hash, sync_status);
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_agents_group_info);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_priority_resp);
    __real_cJSON_Delete(j_group_array);
    __real_cJSON_Delete(j_groups_number);
}

void test_wdb_global_set_agent_groups_empty_only_not_empty_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char group_name[] = "GROUP";
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_EMPTY_ONLY;
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));
    cJSON* j_priority_resp = cJSON_Parse("[{\"MAX(priority)\":0}]");
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateNumber(agent_id));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_Duplicate(j_group_array, TRUE));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        /* wdb_global_get_agent_max_group_priority */
        create_wdb_global_get_agent_max_group_priority_success_call(agent_id, j_priority_resp);
        expect_string(__wrap__mdebug1, formatted_msg, "Agent group set in empty_only mode ignored because the agent already contains groups");
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_agents_group_info);
    __real_cJSON_Delete(j_priority_resp);
    __real_cJSON_Delete(j_group_array);
}

void test_wdb_global_set_agent_groups_remove_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    char group_name[] = "GROUP";
    char hash[] = "19dcd0dd"; //"GROUP" hash
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_REMOVE;
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();
    cJSON* j_priority_resp = cJSON_Parse("[{\"id\":0}]");

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateNumber(agent_id));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_Duplicate(j_group_array, TRUE));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        /* wdb_global_unassign_agent_group */
        create_wdb_global_unassign_agent_group_success_call(agent_id, group_id, group_name, j_find_group_resp);

        /* wdb_global_get_agent_max_group_priority */
        create_wdb_global_get_agent_max_group_priority_success_call(agent_id, j_priority_resp);

        /* wdb_global_calculate_agent_group_csv */
        create_wdb_global_calculate_agent_group_csv_success_call(agent_id);

        will_return(__wrap_wdb_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, group_name);
        will_return(__wrap_wdb_step, SQLITE_DONE);

        /* wdb_global_set_agent_group_context */
        create_wdb_global_set_agent_group_context_success_call(agent_id, group_name, hash, sync_status);
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_agents_group_info);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_group_array);
    __real_cJSON_Delete(j_priority_resp);
}

void test_wdb_global_set_agent_groups_remove_unassign_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    char group_name[] = "GROUP";
    char hash[] = "19dcd0dd"; //"GROUP" hash
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_REMOVE;
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));
    cJSON* j_group_array_invalid = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array_invalid, cJSON_CreateNumber(-1)); //Invalid group information
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateNumber(agent_id));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_Duplicate(j_group_array_invalid, TRUE));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        /* wdb_global_unassign_agent_group */
        expect_string(__wrap__mdebug1, formatted_msg, "Invalid groups remove information");
        expect_string(__wrap__merror, formatted_msg, "There was an error un-assigning the groups to agent '001'");

        /* wdb_global_calculate_agent_group_csv */
        create_wdb_global_calculate_agent_group_csv_success_call(agent_id);

        will_return(__wrap_wdb_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, group_name);
        will_return(__wrap_wdb_step, SQLITE_DONE);

        /* wdb_global_set_agent_group_context */
        create_wdb_global_set_agent_group_context_success_call(agent_id, group_name, hash, sync_status);
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_agents_group_info);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_group_array);
    __real_cJSON_Delete(j_group_array_invalid);
}

void test_wdb_global_set_agent_groups_invalid_json(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_REMOVE;
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateString("not_int_id"));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_CreateString("not_array_groups"));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        expect_string(__wrap__mdebug1, formatted_msg, "Invalid groups set information");
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_agents_group_info);
}

void test_wdb_global_set_agent_groups_calculate_csv_empty(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    char group_name[] = "GROUP";
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_REMOVE;
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();
    cJSON* j_priority_resp = cJSON_Parse("[{\"id\":0}]");

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateNumber(agent_id));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_Duplicate(j_group_array, TRUE));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        /* wdb_global_unassign_agent_group */
        create_wdb_global_unassign_agent_group_success_call(agent_id, group_id, group_name, j_find_group_resp);

        /* wdb_global_get_agent_max_group_priority */
        create_wdb_global_get_agent_max_group_priority_success_call(agent_id, j_priority_resp);

        /* wdb_global_calculate_agent_group_csv */
        will_return(__wrap_wdb_begin2, -1);
        expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
        expect_string(__wrap__mwarn, formatted_msg, "The groups were empty right after the set for agent '001'");

        /* wdb_global_set_agent_group_context */
        create_wdb_global_set_agent_group_context_success_call(agent_id, NULL, NULL, sync_status);
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_OK);
    __real_cJSON_Delete(j_agents_group_info);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_group_array);
    __real_cJSON_Delete(j_priority_resp);
}

void test_wdb_global_set_agent_groups_set_group_ctx_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;
    int group_id = 1;
    char group_name[] = "GROUP";
    char sync_status[] = "synced";
    wdb_groups_set_mode_t mode = WDB_GROUP_REMOVE;
    cJSON* j_group_array = __real_cJSON_CreateArray();
    cJSON_AddItemToArray(j_group_array, cJSON_CreateString(group_name));
    cJSON* j_find_group_resp = cJSON_Parse("[{\"id\":1}]");
    cJSON* j_agents_group_info = __real_cJSON_CreateArray();
    cJSON* j_priority_resp = cJSON_Parse("[{\"id\":0}]");

    for (int i=0; i<AGENTS_SIZE; i++) {
        cJSON* j_agent_group = cJSON_CreateObject();
        cJSON_AddItemToObject(j_agent_group, "id", cJSON_CreateNumber(agent_id));
        cJSON_AddItemToObject(j_agent_group, "groups", cJSON_Duplicate(j_group_array, TRUE));
        cJSON_AddItemToArray(j_agents_group_info, j_agent_group);

        /* wdb_global_unassign_agent_group */
        create_wdb_global_unassign_agent_group_success_call(agent_id, group_id, group_name, j_find_group_resp);

        /* wdb_global_get_agent_max_group_priority */
        create_wdb_global_get_agent_max_group_priority_success_call(agent_id, j_priority_resp);

        /* wdb_global_calculate_agent_group_csv */
        create_wdb_global_calculate_agent_group_csv_success_call(agent_id);

        will_return(__wrap_wdb_step, SQLITE_ROW);
        expect_value(__wrap_sqlite3_column_text, iCol, 0);
        will_return(__wrap_sqlite3_column_text, group_name);
        will_return(__wrap_wdb_step, SQLITE_DONE);

        /* wdb_global_set_agent_group_context */
        expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_CTX_SET);
        will_return(__wrap_wdb_init_stmt_in_cache, NULL);
        expect_string(__wrap__merror, formatted_msg, "There was an error assigning the groups context to agent '001'");
        expect_string(__wrap__merror,formatted_msg, "Couldn't recalculate hash group for agent: '001'");
    }

    wdbc_result result = wdb_global_set_agent_groups(data->wdb, mode, sync_status, j_agents_group_info);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(j_agents_group_info);
    __real_cJSON_Delete(j_find_group_resp);
    __real_cJSON_Delete(j_group_array);
    __real_cJSON_Delete(j_priority_resp);
}

void test_wdb_global_set_agent_groups_sync_status_invalid_stmt(){
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNC_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    assert_int_equal(OS_INVALID, wdb_global_set_agent_groups_sync_status((wdb_t *)0xDEADBEEF, 1, "test"));
}

void test_wdb_global_set_agent_groups_sync_status_bad_bind_sync(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char sync[] = "test";

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNC_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt *)1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "test_error");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): test_error");

    assert_int_equal(OS_INVALID, wdb_global_set_agent_groups_sync_status(data->wdb, 1, sync));
}

void test_wdb_global_set_agent_groups_sync_status_bad_bind_id(void** state){
    test_struct_t *data  = (test_struct_t *)*state;
    char sync[] = "test";
    int id = 001;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNC_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt *)1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "test_error");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): test_error");

    assert_int_equal(OS_INVALID, wdb_global_set_agent_groups_sync_status(data->wdb, id, sync));
}

void test_wdb_global_set_agent_groups_sync_status_success(void** state){
    test_struct_t *data  = (test_struct_t *)*state;
    char sync[] = "test";
    int id = 001;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNC_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt *)1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, sync);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_exec_stmt_silent, OS_SUCCESS);

    assert_int_equal(OS_SUCCESS, wdb_global_set_agent_groups_sync_status(data->wdb, id, sync));
}

/* Tests wdb_global_get_distinct_agent_groups */

void test_wdb_global_get_distinct_agent_groups_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char group_hash[] = "abcdef";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_distinct_agent_groups(data->wdb, group_hash, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_distinct_agent_groups_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char group_hash[] = "abcdef";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_distinct_agent_groups(data->wdb, group_hash, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_distinct_agent_groups_bind_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char group_hash[] = "abcdef";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "abcdef");
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_distinct_agent_groups(data->wdb, group_hash, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_distinct_agent_groups_exec_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char group_hash[] = "abcdef";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "abcdef");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    wrap_wdb_exec_stmt_sized_failed_call(STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_distinct_agent_groups(data->wdb, group_hash, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_distinct_agent_groups_succes_due(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char group_hash[] = "abcdef";
    cJSON* j_result = cJSON_Parse("[{\"group\":\"group1\",\"group_hash\":\"ec282560\"}]");

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "abcdef");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    wrap_wdb_exec_stmt_sized_socket_full_call(j_result, STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_distinct_agent_groups(data->wdb, group_hash, &status);

    char *output = cJSON_PrintUnformatted(result);
    assert_string_equal(output, "[{\"group\":\"group1\",\"group_hash\":\"ec282560\"}]");
    os_free(output);
    assert_int_equal(status, WDBC_DUE);
    __real_cJSON_Delete(result);
}

void test_wdb_global_get_distinct_agent_groups_succes_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char group_hash[] = "abcdef";
    cJSON* j_result = cJSON_Parse("[{\"group\":\"group1\",\"group_hash\":\"ec282560\"}]");

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "abcdef");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    wrap_wdb_exec_stmt_sized_success_call(j_result, STMT_MULTI_COLUMN);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_distinct_agent_groups(data->wdb, group_hash, &status);

    char *output = cJSON_PrintUnformatted(result);
    assert_string_equal(output, "[{\"group\":\"group1\",\"group_hash\":\"ec282560\"}]");
    os_free(output);
    assert_int_equal(status, WDBC_OK);
    __real_cJSON_Delete(result);
}

/* Tests wdb_global_recalculate_all_agent_groups_hash */

void test_wdb_global_recalculate_all_agent_groups_hash_transaction_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    int result = wdb_global_recalculate_all_agent_groups_hash(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_recalculate_all_agent_groups_hash_cache_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    int result = wdb_global_recalculate_all_agent_groups_hash(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_recalculate_all_agent_groups_hash_bind_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    int result = wdb_global_recalculate_all_agent_groups_hash(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_recalculate_all_agent_groups_hash_recalculate_error(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "GROUP";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, 1);
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, group_name);

    /* wdb_global_calculate_agent_group_csv */
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
    expect_string(__wrap__mdebug1, formatted_msg, "No groups in belongs table for agent '001'");

    /* wdb_global_set_agent_group_hash */
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_HASH_SET);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);
    expect_string(__wrap__merror, formatted_msg, "There was an error assigning the groups hash to agent '001'");

    expect_string(__wrap__merror, formatted_msg, "Couldn't recalculate hash group for agent: '001'");

    int result = wdb_global_recalculate_all_agent_groups_hash(data->wdb);

    assert_int_equal(result, OS_INVALID);
}


int main()
{
    const struct CMUnitTest tests[] = {
        /* Tests wdb_global_get_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_labels_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_labels_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_labels_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_labels_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_labels_success, test_setup, test_teardown),
        /* Tests wdb_global_del_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_global_del_agent_labels_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_del_agent_labels_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_del_agent_labels_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_del_agent_labels_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_del_agent_labels_success, test_setup, test_teardown),
        /* Tests wdb_global_set_agent_label */
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_label_success, test_setup, test_teardown),
        /* Tests wdb_global_set_sync_status */
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_success, test_setup, test_teardown),
        /* Tests wdb_global_validate_sync_status */
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_no_old_status, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_synced_to_synced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_to_synced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_status_to_synced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_keepalive_to_synced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_synced_to_syncreq, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_to_syncreq, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_status_to_syncreq, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_keepalive_to_syncreq, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_synced_to_syncreq_status, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_to_syncreq_status, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_status_to_syncreq_status, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_keepalive_to_syncreq_status, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_synced_to_syncreq_keepalive, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_to_syncreq_keepalive, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_status_to_syncreq_keepalive, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_sync_status_syncreq_keepalive_to_syncreq_keepalive, test_setup, test_teardown),
        /* Tests wdb_global_get_sync_status */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_sync_status_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_sync_status_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_sync_status_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_sync_status_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_sync_status_success_no_status, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_sync_status_success, test_setup, test_teardown),
        /* Tests wdb_global_sync_agent_info_get */
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_transaction_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_no_agents, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_sync_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_full, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_size_limit, test_setup, test_teardown),
        /* Tests wdb_global_get_groups_integrity */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_groups_integrity_statement_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_groups_integrity_syncreq, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_groups_integrity_hash_mismatch, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_groups_integrity_synced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_groups_integrity_error, test_setup, test_teardown),
        /* Tests wdb_global_get_agent_max_group_priority */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_max_group_priority_statement_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_max_group_priority_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_max_group_priority_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_max_group_priority_success, test_setup, test_teardown),
        /* Tests wdb_global_sync_agent_groups_get */
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_invalid_condition, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_no_condition_get_hash_true, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_no_agents_get_hash_false, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_exec_fail_get_hash_true_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_exec_fail_get_hash_true_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_set_synced_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_groups_get_due_buffer_full, test_setup, test_teardown),
        /* Tests wdb_global_add_global_group_hash_to_response */
        cmocka_unit_test_setup_teardown(test_wdb_global_add_global_group_hash_to_resposne_response_null, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_add_global_group_hash_to_resposne_response_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_add_global_group_hash_to_resposne_get_hash_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_add_global_group_hash_to_resposne_get_hash_return_null, test_setup, test_teardown),
        /* Tests wdb_global_sync_agent_info_set */
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_transaction_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_success, test_setup, test_teardown),
        /* Tests wdb_global_insert_agent */
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind4_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind5_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind6_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_bind7_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_name_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_version */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_transaction_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind4_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind5_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind6_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind7_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind8_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind9_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind10_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind11_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind12_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind13_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind14_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind15_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind16_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind17_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind18_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_bind19_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_transaction_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_connection_status */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_transaction_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_cache_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind1_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind2_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind3_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind4_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind5_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_step_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_success,
                                        test_setup,
                                        test_teardown),
        /* Tests wdb_global_update_agent_status_code */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_status_code_transaction_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_status_code_cache_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_status_code_bind1_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_status_code_bind2_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_status_code_bind3_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_status_code_bind4_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_status_code_step_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_status_code_success,
                                        test_setup,
                                        test_teardown),
        /* Tests wdb_global_delete_agent */
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_success, test_setup, test_teardown),
        /* Tests wdb_global_select_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_name_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_name_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_name_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_name_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_name_success, test_setup, test_teardown),
        /* Tests wdb_global_select_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_group_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_group_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_group_success, test_setup, test_teardown),
        /* Tests wdb_global_select_groups */
        cmocka_unit_test_setup_teardown(test_wdb_global_select_groups_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_groups_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_groups_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_groups_socket_full, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_groups_success, test_setup, test_teardown),
        /* Tests wdb_global_find_agent */
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_agent_success, test_setup, test_teardown),
        /* Tests wdb_global_find_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_find_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_group_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_group_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_find_group_success, test_setup, test_teardown),
        /* Tests wdb_global_insert_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_invalid_group_name, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_success, test_setup, test_teardown),
        /* Tests wdb_global_select_group_belong */
        cmocka_unit_test_setup_teardown(test_wdb_global_select_group_belong_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_group_belong_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_group_belong_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_group_belong_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_group_belong_socket_size_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_group_belong_success, test_setup, test_teardown),
        /* Tests wdb_global_get_group_agents */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_group_agents_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_group_agents_bind_text_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_group_agents_bind_int_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_group_agents_stmt_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_group_agents_stmt_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_group_agents_stmt_error, test_setup, test_teardown),
        /* Tests wdb_global_insert_agent_belong */
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_belong_success, test_setup, test_teardown),
        /* Tests wdb_is_group_empty */
        cmocka_unit_test_setup_teardown(test_wdb_is_group_empty_stmt_init_group_not_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_is_group_empty_stmt_init_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_is_group_empty_stmt_init_group_found, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_is_group_empty_stmt_invalid_result, test_setup, test_teardown),
        /* Tests wdb_global_delete_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_recalculate_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_success, test_setup, test_teardown),
        /* Tests wdb_global_delete_agent_belong */
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_transaction_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_success, test_setup, test_teardown),
        /* Tests wdb_global_delete_tuple_belong */
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_tuple_belong_init_stmt_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_tuple_belong_exec_stmt_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_tuple_belong_success, test_setup, test_teardown),
        /* Tests wdb_global_get_agent_info */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_success, test_setup, test_teardown),
        /* Tests wdb_global_get_agents_to_disconnect */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_transaction_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_update_status_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_invalid_elements,
                                        test_setup,
                                        test_teardown),
        /* Tests wdb_global_get_all_agents */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_err, test_setup, test_teardown),
        /* Tests wdb_global_reset_agents_connection */
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_transaction_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_success, test_setup, test_teardown),
        /* Tests wdb_global_get_agents_by_connection_status */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_transaction_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_cache_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_and_node_cache_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_bind1_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_bind2_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_and_node_bind3_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_and_node_bind4_fail,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_and_node_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_and_node_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_and_node_err, test_setup, test_teardown),
        /* Tests wdb_global_create_backup */
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_commit_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_prepare_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_bind_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_exec_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_compress_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_success, test_setup, test_teardown),
        /* Tests wdb_global_remove_old_backups */
        cmocka_unit_test_setup_teardown(test_wdb_global_remove_old_backups_opendir_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_remove_old_backups_success_without_removing,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_remove_old_backups_success, test_setup, test_teardown),
        /* Tests wdb_global_get_backups */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_backups_opendir_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_backups_success, test_setup, test_teardown),
        /* Tests wdb_global_restore_backup */
        cmocka_unit_test_setup_teardown(test_wdb_global_restore_backup_pre_restore_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_restore_backup_no_snapshot, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_restore_backup_compression_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_restore_backup_success, test_setup, test_teardown),
        /* Tests wdb_global_get_most_recent_backup */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_most_recent_backup_opendir_failed,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_most_recent_backup_success, test_setup, test_teardown),
        /* Tests wdb_global_get_oldest_backup */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_oldest_backup_opendir_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_oldest_backup_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_groups_hash */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_begin_failed,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_cache_failed,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_bind_text_failed,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_bind_int_failed,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_step_failed,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_groups_string_null_success,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_empty_group_column_success,
                                        test_setup,
                                        test_teardown),
        /* Tests wdb_global_adjust_v4 */
        cmocka_unit_test_setup_teardown(test_wdb_global_adjust_v4_begin_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_adjust_v4_cache_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_adjust_v4_bind_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_adjust_v4_step_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_adjust_v4_commit_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_adjust_v4_success, test_setup, test_teardown),
        /* Tests wdb_global_calculate_agent_group_csv */
        cmocka_unit_test_setup_teardown(test_wdb_global_calculate_agent_group_csv_unable_to_get_group,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_calculate_agent_group_csv_success, test_setup, test_teardown),
        /* Tests wdb_global_assign_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_assign_agent_group_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_assign_agent_group_insert_belong_error,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_assign_agent_group_find_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_assign_agent_group_invalid_json, test_setup, test_teardown),
        /* Tests wdb_global_unassign_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_unassign_agent_group_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_unassign_agent_group_success_assign_default_group, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_unassign_agent_group_delete_tuple_error,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_unassign_agent_group_find_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_unassign_agent_group_find_invalid_response, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_unassign_agent_group_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_unassign_agent_group_error_assign_default_group, test_setup, test_teardown),
        /* Tests wdb_global_set_agent_group_context */
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_group_context_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_group_context_init_stmt_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_group_context_exec_stmt_error, test_setup, test_teardown),
        /* Tests wdb_global_set_agent_group_hash */
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_group_hash_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_group_hash_init_stmt_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_group_hash_exec_stmt_error, test_setup, test_teardown),
        /* Tests wdb_global_groups_number_get */
        cmocka_unit_test_setup_teardown(test_wdb_global_groups_number_get_stmt_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_groups_number_get_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_groups_number_get_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_groups_number_get_success, test_setup, test_teardown),
        /* Tests wdb_global_validate_group_name */
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_group_name_fail_group_name_contains_invalid_character_1, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_group_name_fail_group_name_contains_invalid_character_2, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_group_name_fail_group_name_exceeds_max_length, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_group_name_fail_group_name_current_directory_reserved_name, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_group_name_fail_group_name_parent_directory_reserved_name, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_group_name_success, test_setup, test_teardown),
        /* Tests wdb_global_validate_groups */
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_groups_fail_groups_exceeds_max_number, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_validate_groups_success, test_setup, test_teardown),
        /* Tests wdb_global_set_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_override_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_override_delete_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_add_modes_assign_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_append_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_empty_only_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_empty_only_not_empty_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_remove_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_remove_unassign_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_calculate_csv_empty, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_set_group_ctx_error, test_setup, test_teardown),
        /* Tests wdb_global_set_agent_groups_sync_status*/
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_sync_status_invalid_stmt, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_sync_status_bad_bind_sync, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_sync_status_bad_bind_id, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_agent_groups_sync_status_success, test_setup, test_teardown),
        /* Tests wdb_global_get_distinct_agent_groups */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_distinct_agent_groups_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_distinct_agent_groups_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_distinct_agent_groups_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_distinct_agent_groups_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_distinct_agent_groups_succes_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_distinct_agent_groups_succes_ok, test_setup, test_teardown),
        /* Tests wdb_global_recalculate_all_agent_groups_hash */
        cmocka_unit_test_setup_teardown(test_wdb_global_recalculate_all_agent_groups_hash_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_recalculate_all_agent_groups_hash_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_recalculate_all_agent_groups_hash_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_recalculate_all_agent_groups_hash_recalculate_error, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
