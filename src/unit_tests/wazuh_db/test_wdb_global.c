
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"

int __wrap_wdb_open_global()
{
    return mock_type(int);
}

void __wrap_wdb_leave(){}

int  __wrap_wdb_begin2(){
    return mock_type(int);
}

int  __wrap_wdb_step(){
    return mock_type(int);
}

int  __wrap_wdb_stmt_cache(){
    return mock_type(int);
}

cJSON * __wrap_wdb_exec_stmt()
{
    return mock_type(cJSON *);
}

cJSON * __wrap_wdb_exec()
{
    return mock_type(cJSON *);
}

typedef struct test_struct {
    wdb_t *socket;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->socket);
    os_strdup("000",init_data->socket->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->socket->db);
    *state = init_data;
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->socket->id);
    os_free(data->socket->db);
    os_free(data->socket);
    os_free(data);
    return 0;
}

void test_get_agent_labels_transaction_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    output = wdb_global_get_agent_labels(data->socket, atoi(data->socket->id));
    assert_null(output);
}

void test_get_agent_labels_cache_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    output = wdb_global_get_agent_labels(data->socket, atoi(data->socket->id));
    assert_null(output);
}

void test_get_agent_labels_bind_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
   
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_int(): ERROR MESSAGE");

    output = wdb_global_get_agent_labels(data->socket, atoi(data->socket->id));
    assert_null(output);
}

void test_get_agent_labels_exec_fail(void **state)
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
    expect_string(__wrap__mdebug1, formatted_msg, "sqlite3_step(): ERROR MESSAGE");

    output = wdb_global_get_agent_labels(data->socket, atoi(data->socket->id));
    assert_null(output);
}

void test_get_agent_labels_success(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_any_always(__wrap_sqlite3_bind_int, index);
    expect_any_always(__wrap_sqlite3_bind_int, value);
    will_return_always(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_exec_stmt, (cJSON*)1);

    output = wdb_global_get_agent_labels(data->socket, atoi(data->socket->id));
    assert_non_null(output);
}

void test_del_agent_labels_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_del_agent_labels(data->socket, atoi(data->socket->id));
    assert_int_equal(result, OS_INVALID);
}

void test_del_agent_labels_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_del_agent_labels(data->socket, atoi(data->socket->id));
    assert_int_equal(result, OS_INVALID);
}

void test_del_agent_labels_bind_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_del_agent_labels(data->socket, atoi(data->socket->id));
    assert_int_equal(result, OS_INVALID);
}

void test_del_agent_labels_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_del_agent_labels(data->socket, atoi(data->socket->id));
    assert_int_equal(result, OS_INVALID);
}

void test_del_agent_labels_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_del_agent_labels(data->socket, atoi(data->socket->id));
    assert_int_equal(result, OS_SUCCESS);
}

void test_set_agent_label_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_set_agent_label(data->socket, atoi(data->socket->id), key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_set_agent_label_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_set_agent_label(data->socket, atoi(data->socket->id), key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_set_agent_label_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_set_agent_label(data->socket, atoi(data->socket->id), key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_set_agent_label_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_set_agent_label(data->socket, atoi(data->socket->id), key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_set_agent_label_bind3_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_value");
    will_return(__wrap_sqlite3_bind_text, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_set_agent_label(data->socket, atoi(data->socket->id), key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_set_agent_label_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
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

    result = wdb_global_set_agent_label(data->socket, atoi(data->socket->id), key, value);
    assert_int_equal(result, OS_INVALID);
}

void test_set_agent_label_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char key[] = "test_key";
    char value[] = "test_value";

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_key");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "test_value");
    will_return(__wrap_sqlite3_bind_text, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_set_agent_label(data->socket, atoi(data->socket->id), key, value);
    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_global_set_sync_status_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_sync_status_t status = WDB_SYNCED;
 
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_set_sync_status(data->socket, atoi(data->socket->id), status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_cache_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_sync_status_t status = WDB_SYNCED;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_global_set_sync_status(data->socket, atoi(data->socket->id), status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_bind1_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_sync_status_t status = WDB_SYNCED;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, status);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_set_sync_status(data->socket, atoi(data->socket->id), status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_bind2_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_sync_status_t status = WDB_SYNCED;
 
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, status);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_set_sync_status(data->socket, atoi(data->socket->id), status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_step_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_sync_status_t status = WDB_SYNCED;
  
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, status);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_set_sync_status(data->socket, atoi(data->socket->id), status);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_set_sync_status_success(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    wdb_sync_status_t status = WDB_SYNCED;
   
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, status);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, atoi(data->socket->id));
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_set_sync_status(data->socket, atoi(data->socket->id), status);
    assert_int_equal(result, OS_SUCCESS);
}

void test_wdb_sync_agent_info_get_transaction_fail(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;
   
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_sync_agent_info_get(data->socket, &last_agent_id, &output);

    os_free(output);
    assert_int_equal(result, WDB_CHUNKS_ERROR);
}

void test_wdb_sync_agent_info_get_cache_fail(void **state)
{
    int result = 0;
    int last_agent_id = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *output = NULL;
   
    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot cache statement");

    result = wdb_sync_agent_info_get(data->socket, &last_agent_id, &output);

    os_free(output);
    assert_int_equal(result, WDB_CHUNKS_ERROR);
}

void test_wdb_sync_agent_info_get_bind_fail(void **state)
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
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_sync_agent_info_get(data->socket, &last_agent_id, &output);

    os_free(output);
    assert_int_equal(result, WDB_CHUNKS_ERROR);
}

void test_wdb_sync_agent_info_get_no_agents(void **state)
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

    result = wdb_sync_agent_info_get(data->socket, &last_agent_id, &output);

    os_free(output);
    assert_int_equal(result, WDB_CHUNKS_COMPLETE);
}

void test_wdb_sync_agent_info_get_success(void **state)
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

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_global_set_sync_status()
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, WDB_SYNCED);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Mocking one valid agent
    will_return(__wrap_wdb_exec_stmt, root);

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

    result = wdb_sync_agent_info_get(data->socket, &last_agent_id, &output);

    json_output = cJSON_Parse(output);
    assert_non_null(json_output);

    if(json_output){
        json_agent = cJSON_GetObjectItem(json_output->child, "id");
        assert_non_null(json_agent);
        if(json_agent){
            assert_int_equal(json_agent->valueint, agent_id);
        }
        json_agent = cJSON_GetObjectItem(json_output->child, "test_field");
        if(json_agent){
            assert_string_equal(json_agent->valuestring, "test_value");
        }
        json_labels = cJSON_GetObjectItem(json_output->child, "labels");
        assert_non_null(json_labels);
        if(json_labels){
            json_label = cJSON_GetObjectItem(json_labels->child, "id");
            assert_non_null(json_label);
            if(json_label){
                assert_int_equal(json_label->valueint, agent_id);
            }
            json_label = cJSON_GetObjectItem(json_labels->child, "key");
            assert_non_null(json_label);
            if(json_label){
                assert_string_equal(json_label->valuestring, "test_key");
            }
            json_label = cJSON_GetObjectItem(json_labels->child, "value");
            assert_non_null(json_label);
            if(json_label){
                assert_string_equal(json_label->valuestring, "test_value");
            }
        }
    }

    os_free(output);
    cJSON_Delete(json_output);
    assert_int_equal(result, WDB_CHUNKS_COMPLETE);
}

void test_wdb_sync_agent_info_get_sync_fail(void **state)
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

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Required for wdb_global_set_sync_status()
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, WDB_SYNCED);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Mocking one valid agent
    will_return(__wrap_wdb_exec_stmt, root);

    // Required for wdb_get_agent_labels()
    json_labels = cJSON_CreateArray();
    will_return(__wrap_wdb_exec_stmt, json_labels);

    // Required for wdb_global_set_sync_status()
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_sync_agent_info_get(data->socket, &last_agent_id, &output);

    os_free(output);
    cJSON_Delete(root);
    assert_int_equal(result, WDB_CHUNKS_ERROR);
}

void test_wdb_sync_agent_info_get_full(void **state)
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

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    expect_value(__wrap_sqlite3_bind_int, index, 4);
    expect_value(__wrap_sqlite3_bind_int, value, agent_id);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);

    // Mocking one valid agent
    will_return(__wrap_wdb_exec_stmt, root);

    // Required for wdb_get_agent_labels()
    json_labels = cJSON_CreateArray();
    json_label = cJSON_CreateObject();
    cJSON_AddNumberToObject(json_label, "id", 1);
    cJSON_AddStringToObject(json_label,"key", "test_key");
    cJSON_AddStringToObject(json_label,"value", "test_value");
    cJSON_AddItemToArray(json_labels, json_label);
    will_return(__wrap_wdb_exec_stmt, json_labels);

    result = wdb_sync_agent_info_get(data->socket, &last_agent_id, &output);

    os_free(output);
    assert_int_equal(result, WDB_CHUNKS_BUFFER_FULL);
}

void test_wdb_global_sync_agent_info_set_transaction_fail(void **state)
{
    int result = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    cJSON *json_agent = NULL;
   
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot begin transaction");

    result = wdb_global_sync_agent_info_set(data->socket, json_agent);

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

    result = wdb_global_sync_agent_info_set(data->socket, json_agent);

    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_bind1_fail(void **state)
{
    int result = 0;
    int n = 0;
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
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_text(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->socket, json_agent);

    cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_bind2_fail(void **state)
{
    int result = 0;
    int n = 0;
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
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->socket, json_agent);
    cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_bind3_fail(void **state)
{
    int result = 0;
    int n = 0;
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
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, WDB_SYNCED);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_int(): ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->socket, json_agent);
    cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_step_fail(void **state)
{
    int result = 0;
    int n = 0;
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
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, WDB_SYNCED);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR MESSAGE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: ERROR MESSAGE");

    result = wdb_global_sync_agent_info_set(data->socket, json_agent);
    cJSON_Delete(json_agent);
    assert_int_equal(result, OS_INVALID);
}

void test_wdb_global_sync_agent_info_set_success(void **state)
{
    int result = 0;
    int n = 0;
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
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, WDB_SYNCED);
    will_return(__wrap_sqlite3_bind_int, SQLITE_OK);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    result = wdb_global_sync_agent_info_set(data->socket, json_agent);
    cJSON_Delete(json_agent);
    assert_int_equal(result, OS_SUCCESS);
}

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_agent_labels_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_labels_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_labels_bind_fail, test_setup, test_teardown),      
        cmocka_unit_test_setup_teardown(test_get_agent_labels_exec_fail, test_setup, test_teardown),      
        cmocka_unit_test_setup_teardown(test_get_agent_labels_success, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_del_agent_labels_transaction_fail, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_del_agent_labels_cache_fail, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_del_agent_labels_bind_fail, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_del_agent_labels_step_fail, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_del_agent_labels_success, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_set_agent_label_transaction_fail, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_set_agent_label_cache_fail, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_set_agent_label_bind1_fail, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_set_agent_label_bind2_fail, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_set_agent_label_bind3_fail, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_set_agent_label_step_fail, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_set_agent_label_success, test_setup, test_teardown),       
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_cache_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_bind1_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_bind2_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_step_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_set_sync_status_success, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_sync_agent_info_get_transaction_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_sync_agent_info_get_cache_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_sync_agent_info_get_bind_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_sync_agent_info_get_no_agents, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_sync_agent_info_get_success, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_sync_agent_info_get_sync_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_sync_agent_info_get_full, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_transaction_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_cache_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_bind1_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_bind2_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_bind3_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_step_fail, test_setup, test_teardown),              
        cmocka_unit_test_setup_teardown(test_wdb_global_sync_agent_info_set_success, test_setup, test_teardown)              
        };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
