
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/time_op_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/posix/time_wrappers.h"
#include "wazuhdb_op.h"

extern void __real_cJSON_Delete(cJSON *item);
extern int test_mode;

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
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

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
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

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
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_set_sync_status(data->wdb, 1, status);
    assert_int_equal(result, OS_SUCCESS);
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
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, last_agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, NULL);
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

    root = cJSON_CreateArray();
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
    json_labels = cJSON_CreateArray();
    json_label = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_label, "id", agent_id);
    cJSON_AddStringToObject(json_label,"key", "test_key");
    cJSON_AddStringToObject(json_label,"value", "test_value");
    cJSON_AddItemToArray(json_labels, json_label);
    will_return(__wrap_wdb_exec_stmt, json_labels);

    // Required for wdb_global_set_sync_status()
    will_return(__wrap_wdb_step, SQLITE_DONE);

    // No more agents
    will_return(__wrap_wdb_exec_stmt, NULL);

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

    root = cJSON_CreateArray();
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
    json_labels = cJSON_CreateArray();
    will_return(__wrap_wdb_exec_stmt, json_labels);

    // Required for wdb_global_set_sync_status()
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");
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

    root = cJSON_CreateArray();
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
    json_labels = cJSON_CreateArray();
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

    root = cJSON_CreateArray();
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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    // No more agents
    will_return(__wrap_wdb_exec_stmt, NULL);

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

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    expect_string(__wrap_wdb_get_global_group_hash, hexdigest, "");
    will_return(__wrap_wdb_get_global_group_hash, OS_INVALID);

    j_result = wdb_global_get_groups_integrity(data->wdb, "");

    char *result = cJSON_PrintUnformatted(j_result);
    assert_string_equal(result, "[\"hash_mismatch\"]");
    os_free(result);
    __real_cJSON_Delete(j_result);
}

void test_wdb_global_get_groups_integrity_synced(void **state)
{
    cJSON* j_result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    expect_string(__wrap_wdb_get_global_group_hash, hexdigest, "");
    will_return(__wrap_wdb_get_global_group_hash, OS_SUCCESS);

    j_result = wdb_global_get_groups_integrity(data->wdb, "");

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
    expect_string(__wrap__mdebug1, formatted_msg, "DB(global) sqlite3_step(): ERROR MESSAGE");

    j_result = wdb_global_get_groups_integrity(data->wdb, NULL);

    assert_null(j_result);
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
    will_return(__wrap_wdb_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

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

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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

    will_return(__wrap_wdb_step, SQLITE_DONE);

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

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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

    will_return(__wrap_wdb_step, SQLITE_DONE);

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

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, os_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 18);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);


    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 18);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 18);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_update_agent_version(data->wdb, agent_id, os_name, os_version, os_major,
                                            os_minor, os_codename, os_platform, os_build, os_uname, os_arch, version,
                                            config_sum, merged_sum, manager_host, node_name, agent_ip, connection_status, sync_status);

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
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
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
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
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
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

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

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

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

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

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

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

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
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");
    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

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
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");
    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

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
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");

    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");
    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

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
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

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
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_update_agent_connection_status(data->wdb, 1, connection_status, sync_status);

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

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_delete_agent(data->wdb, 1);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_global_select_agent_name */

void test_wdb_global_select_agent_name_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_name_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_agent_name(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_name_bind_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

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

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

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

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

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

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_group_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_agent_group(data->wdb, 1);

    assert_null(result);
}

void test_wdb_global_select_agent_group_bind_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

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

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

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

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

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

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_groups(data->wdb);

    assert_null(result);
}

void test_wdb_global_select_groups_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_groups(data->wdb);

    assert_null(result);
}

void test_wdb_global_select_groups_exec_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    will_return(__wrap_wdb_exec_stmt, NULL);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "wdb_exec_stmt(): ERROR MESSAGE");

    result = wdb_global_select_groups(data->wdb);

    assert_null(result);
}

void test_wdb_global_select_groups_success(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_wdb_exec_stmt, (cJSON*) 1);

    result = wdb_global_select_groups(data->wdb);

    assert_ptr_equal(result, (cJSON*) 1);
}

/* Tests wdb_global_select_agent_keepalive */

void test_wdb_global_select_agent_keepalive_transaction_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_cache_fail(void **state)
{
    cJSON *result = NULL;
    test_struct_t *data  = (test_struct_t *)*state;
    char *name = "test_name";
    char *ip = "0.0.0.0";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_bind1_fail(void **state)
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

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_bind2_fail(void **state)
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

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_bind3_fail(void **state)
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

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_exec_fail(void **state)
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

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

    assert_null(result);
}

void test_wdb_global_select_agent_keepalive_success(void **state)
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

    result = wdb_global_select_agent_keepalive(data->wdb, name, ip);

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

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_insert_agent_group(data->wdb, group_name);

    assert_int_equal(result, OS_SUCCESS);
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

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_insert_agent_belong(data->wdb, id_group, id_agent, priority);

    assert_int_equal(result, OS_SUCCESS);
}

/* Tests wdb_is_group_empty */

void test_wdb_is_group_empty_stmt_init_group_not_found(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    bool result = wdb_is_group_empty(data->wdb, group_name);

    assert_true(result);
}

void test_wdb_is_group_empty_stmt_init_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, NULL);

    bool result = wdb_is_group_empty(data->wdb, group_name);

    assert_false(result);
}

void test_wdb_is_group_empty_stmt_init_group_found(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ROW);

    bool result = wdb_is_group_empty(data->wdb, group_name);

    assert_false(result);
}

void test_wdb_is_group_empty_stmt_invalid_result(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    char *group_name = "test_name";

    //wdb_is_group_empty
    expect_value(__wrap_wdb_init_stmt_in_cache, statement_index, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    will_return(__wrap_wdb_init_stmt_in_cache, (sqlite3_stmt*)1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "SQL statement execution failed");

    bool result = wdb_is_group_empty(data->wdb, group_name);

    assert_false(result);
}

/* Tests wdb_global_delete_group */

void test_wdb_global_delete_group_group_not_empty(void **state)
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
    will_return(__wrap_wdb_step, SQLITE_ROW);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to delete group 'test_name', the group isn't empty");

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_text(): ERROR MESSAGE");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_delete_group_success(void **state)
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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, group_name);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_delete_group(data->wdb, group_name);

    assert_int_equal(result, OS_SUCCESS);
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

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_delete_agent_belong(data->wdb, 1);

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
    cJSON* root = cJSON_CreateArray();
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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);
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
        expect_value(__wrap_sqlite3_bind_int, index, 3);
        expect_value(__wrap_sqlite3_bind_int, value, (time_t)0);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 4);
        expect_in_range(__wrap_sqlite3_bind_int, value, 0, agents_amount);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        will_return(__wrap_wdb_step, SQLITE_DONE);
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
    cJSON* root = cJSON_CreateArray();
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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ROW);
    will_return(__wrap_wdb_exec_stmt_sized, root);
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
        expect_value(__wrap_sqlite3_bind_int, index, 3);
        expect_value(__wrap_sqlite3_bind_int, value, (time_t)0);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        expect_value(__wrap_sqlite3_bind_int, index, 4);
        expect_in_range(__wrap_sqlite3_bind_int, value, 0, agents_amount);
        will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
        will_return(__wrap_wdb_step, SQLITE_DONE);
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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ERROR);
    will_return(__wrap_wdb_exec_stmt_sized, NULL);

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
    cJSON* root = cJSON_CreateArray();
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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);
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
    cJSON* root = cJSON_CreateArray();
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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);
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
    cJSON* root = cJSON_CreateArray();
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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);

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
    cJSON* root = cJSON_CreateArray();
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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ROW);
    will_return(__wrap_wdb_exec_stmt_sized, root);

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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ERROR);
    will_return(__wrap_wdb_exec_stmt_sized, NULL);

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

void test_wdb_global_reset_agents_connection_bind_fail(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
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

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);

    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    int result = wdb_global_reset_agents_connection(data->wdb, sync_status);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_reset_agents_connection_success(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const char *sync_status = "synced";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_value(__wrap_sqlite3_bind_text, buffer, sync_status);
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

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
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

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
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

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
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

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
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

    assert_int_equal(status, WDBC_ERROR);
    assert_null(result);
}

void test_wdb_global_get_agents_by_connection_status_ok(void **state)
{
    test_struct_t *data  = (test_struct_t *)*state;
    const int agents_amount = 10;
    int last_id = 0;
    const char connection_status[] = "active";
    cJSON* root = cJSON_CreateArray();
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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_DONE);
    will_return(__wrap_wdb_exec_stmt_sized, root);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

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
    cJSON* root = cJSON_CreateArray();
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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ROW);
    will_return(__wrap_wdb_exec_stmt_sized, root);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

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
    expect_value(__wrap_wdb_exec_stmt_sized, max_size, WDB_MAX_RESPONSE_SIZE);
    will_return(__wrap_wdb_exec_stmt_sized, SQLITE_ERROR);
    will_return(__wrap_wdb_exec_stmt_sized, NULL);

    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(data->wdb, last_id, connection_status, &status);

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
    expect_function_call(__wrap_cJSON_Delete);

    // wdb_global_remove_old_backups
    will_return(__wrap_opendir, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to open backup directory 'backup/db'");

    result = wdb_global_create_backup(data->wdb, data->output, "-tag");

    assert_string_equal(data->output, "ok [\"backup/db/global.db-backup-2015-11-23-12:00:00-tag.gz\"]");
    assert_int_equal(result, OS_SUCCESS);
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

    expect_string(__wrap_w_uncompress_gzfile, gzfilesrc, "backup/db/global.db-backup-TIMESTAMP.gz");
    expect_string(__wrap_w_uncompress_gzfile, gzfiledst, "queue/db/global.db.back");
    will_return(__wrap_w_uncompress_gzfile, OS_SUCCESS);
    will_return(__wrap_wdb_close, OS_SUCCESS);
    expect_string(__wrap_unlink, file, "queue/db/global.db");
    will_return(__wrap_unlink, OS_SUCCESS);
    expect_string(__wrap_rename, __old, "queue/db/global.db.back");
    expect_string(__wrap_rename, __new, "queue/db/global.db");
    will_return(__wrap_rename, OS_SUCCESS);

    result = wdb_global_restore_backup(&wdb, "global.db-backup-TIMESTAMP.gz", false, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(result, OS_SUCCESS);
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
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

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
    will_return(__wrap_wdb_step, SQLITE_DONE);

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
    cJSON *j_result = cJSON_CreateArray();
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
    will_return(__wrap_wdb_step, SQLITE_DONE);

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
    cJSON *j_result = cJSON_CreateArray();
    cJSON *j_object = cJSON_CreateObject();
    cJSON_AddItemToArray(j_result, j_object);
    will_return(__wrap_wdb_exec_stmt, j_result);
    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap__mdebug2, formatted_msg, "Unable to get group column for agent '1'. The groups_hash column won't be updated");

    int result = wdb_global_update_agent_groups_hash(data->wdb, agent_id, NULL);

    assert_int_equal(result, OS_SUCCESS);
    __real_cJSON_Delete(j_result);
}

/* Tests wdb_global_update_all_agents_groups_hash */

void test_wdb_global_update_all_agents_groups_hash_begin_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->wdb->transaction = 0;
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");
    will_return(__wrap_wdb_begin2, OS_INVALID);

    int result = wdb_global_update_all_agents_groups_hash(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_all_agents_groups_hash_cache_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    int result = wdb_global_update_all_agents_groups_hash(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_all_agents_groups_hash_bind_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(global) sqlite3_bind_int(): ERROR MESSAGE");

    int result = wdb_global_update_all_agents_groups_hash(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_all_agents_groups_hash_step_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    int result = wdb_global_update_all_agents_groups_hash(data->wdb);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_update_all_agents_groups_hash_success(void **state) {
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
    cJSON *j_result = cJSON_CreateArray();
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
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    int result = wdb_global_update_all_agents_groups_hash(data->wdb);

    assert_int_equal(result, OS_SUCCESS);
    __real_cJSON_Delete(j_result);
}

/* Tests wdb_global_calculate_agent_group_csv */

void test_wdb_global_calculate_agent_group_csv_unable_to_get_group(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    // wdb_global_select_group_belong
    data->wdb->transaction = 0;
    will_return(__wrap_wdb_begin2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to get groups of agent '1'");

    char *result = wdb_global_calculate_agent_group_csv(data->wdb, agent_id);

    assert_ptr_equal(result, NULL);
}

void test_wdb_global_calculate_agent_group_csv_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int agent_id = 1;

    // wdb_global_select_group_belong
    data->wdb->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    cJSON *j_groups = cJSON_CreateArray();
    cJSON_AddItemToArray(j_groups, cJSON_CreateString("group1"));
    cJSON_AddItemToArray(j_groups, cJSON_CreateString("group2"));
    will_return(__wrap_wdb_exec_stmt_single_column, j_groups);

    expect_function_call(__wrap_cJSON_Delete);

    char *result = wdb_global_calculate_agent_group_csv(data->wdb, agent_id);

    assert_string_equal(result, "group1,group2");
    os_free(result);
    __real_cJSON_Delete(j_groups);
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
        /* Tests wdb_global_sync_agent_info_get */
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_get_transaction_fail, test_setup, test_teardown),
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
        /* Tests wdb_global_sync_agent_info_set */
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_transaction_fail, test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_transaction_fail, test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_version_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_keepalive_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_connection_status */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_bind4_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_connection_status_success, test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_wdb_global_select_groups_success, test_setup, test_teardown),
        /* Tests wdb_global_select_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_bind3_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_select_agent_keepalive_success, test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_insert_agent_group_success, test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_group_not_empty, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_group_success, test_setup, test_teardown),
        /* Tests wdb_global_delete_agent_belong */
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_delete_agent_belong_success, test_setup, test_teardown),
        /* Tests wdb_global_get_agent_info */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_exec_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agent_info_success, test_setup, test_teardown),
        /* Tests wdb_global_get_agents_to_disconnect */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_err, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_update_status_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_to_disconnect_invalid_elements, test_setup, test_teardown),
        /* Tests wdb_global_get_all_agents */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_all_agents_err, test_setup, test_teardown),
        /* Tests wdb_global_reset_agents_connection */
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_bind_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_step_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_reset_agents_connection_success, test_setup, test_teardown),
        /* Tests wdb_global_get_agents_by_connection_status */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_bind1_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_bind2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_due, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_agents_by_connection_status_err, test_setup, test_teardown),
        /* Tests wdb_global_create_backup */
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_commit_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_prepare_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_bind_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_exec_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_compress_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_create_backup_success, test_setup, test_teardown),
        /* Tests wdb_global_remove_old_backups */
        cmocka_unit_test_setup_teardown(test_wdb_global_remove_old_backups_opendir_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_remove_old_backups_success_without_removing, test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_wdb_global_get_most_recent_backup_opendir_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_most_recent_backup_success, test_setup, test_teardown),
        /* Tests wdb_global_get_oldest_backup */
        cmocka_unit_test_setup_teardown(test_wdb_global_get_oldest_backup_opendir_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_get_oldest_backup_success, test_setup, test_teardown),
        /* Tests wdb_global_update_agent_groups_hash */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_begin_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_cache_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_bind_text_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_bind_int_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_step_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_groups_string_null_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_agent_groups_hash_empty_group_column_success, test_setup, test_teardown),
        /* Tests wdb_global_update_all_agents_groups_hash */
        cmocka_unit_test_setup_teardown(test_wdb_global_update_all_agents_groups_hash_begin_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_all_agents_groups_hash_cache_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_all_agents_groups_hash_bind_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_all_agents_groups_hash_step_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_update_all_agents_groups_hash_success, test_setup, test_teardown),
        /* Tests wdb_global_calculate_agent_group_csv */
        cmocka_unit_test_setup_teardown(test_wdb_global_calculate_agent_group_csv_unable_to_get_group, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_calculate_agent_group_csv_success, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
