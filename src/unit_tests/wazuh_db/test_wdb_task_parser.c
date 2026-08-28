
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "hash_op.h"
#include "os_err.h"
#include "wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_task_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "wazuhdb_op.h"

// Setup/teardown

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int teardown_json(void **state) {
    cJSON *json = *state;
    cJSON_Delete(json);
    return 0;
}

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("001",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    *state = init_data;
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

// Tests

void test_wdb_parse_task_open_tasks_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "task ";

    will_return(__wrap_wdb_open_tasks, NULL);
    expect_string(__wrap__mdebug2, formatted_msg, "Task query: ");
    expect_string(__wrap__mdebug2, formatted_msg, "Couldn't open DB task: queue/tasks/tasks.db");

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Couldn't open DB task");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_task_no_space(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "task";

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query: task");

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'task'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_task_invalid_command(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "task invalid command";

    expect_string(__wrap__mdebug2, formatted_msg, "Task query: invalid command");

    will_return(__wrap_wdb_open_tasks, data->wdb);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "Task DB query error near: invalid");

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'invalid'");
    assert_int_equal(ret, OS_INVALID);
}

/* Test wdb_parse_task_create */

void test_wdb_parse_task_create_ok(void **state)
{
    char *task_id = "task-12345";
    char *agent_id = "001";
    char *task_type = "upgrade";
    char *payload = "{\"version\":\"4.5.0\"}";

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", task_id);
    cJSON_AddStringToObject(parameters, "agent_id", agent_id);
    cJSON_AddStringToObject(parameters, "task_type", task_type);
    cJSON_AddStringToObject(parameters, "payload", payload);

    expect_string(__wrap_wdb_task_create, task_id, task_id);
    expect_string(__wrap_wdb_task_create, agent_id, agent_id);
    expect_string(__wrap_wdb_task_create, task_type, task_type);
    expect_string(__wrap_wdb_task_create, payload, payload);
    will_return(__wrap_wdb_task_create, OS_SUCCESS);

    int result = wdb_parse_task_create((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_SUCCESS);
    assert_string_equal(output, "ok {\"error\":0,\"task_id\":\"task-12345\"}");
}

void test_wdb_parse_task_create_err(void **state)
{
    char *task_id = "task-12345";
    char *agent_id = "001";
    char *task_type = "upgrade";
    char *payload = "{\"version\":\"4.5.0\"}";

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", task_id);
    cJSON_AddStringToObject(parameters, "agent_id", agent_id);
    cJSON_AddStringToObject(parameters, "task_type", task_type);
    cJSON_AddStringToObject(parameters, "payload", payload);

    expect_string(__wrap_wdb_task_create, task_id, task_id);
    expect_string(__wrap_wdb_task_create, agent_id, agent_id);
    expect_string(__wrap_wdb_task_create, task_type, task_type);
    expect_string(__wrap_wdb_task_create, payload, payload);
    will_return(__wrap_wdb_task_create, OS_INVALID);

    int result = wdb_parse_task_create((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "ok {\"error\":-1}");
}

void test_wdb_parse_task_create_task_id_err(void **state)
{
    char *agent_id = "001";
    char *task_type = "upgrade";
    char *payload = "{\"version\":\"4.5.0\"}";

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "agent_id", agent_id);
    cJSON_AddStringToObject(parameters, "task_type", task_type);
    cJSON_AddStringToObject(parameters, "payload", payload);

    int result = wdb_parse_task_create((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "err Error create task: 'parsing task_id error'");
}

void test_wdb_parse_task_create_agent_id_err(void **state)
{
    char *task_id = "task-12345";
    char *task_type = "upgrade";
    char *payload = "{\"version\":\"4.5.0\"}";

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", task_id);
    cJSON_AddStringToObject(parameters, "task_type", task_type);
    cJSON_AddStringToObject(parameters, "payload", payload);

    int result = wdb_parse_task_create((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "err Error create task: 'parsing agent_id error'");
}

void test_wdb_parse_task_create_task_type_err(void **state)
{
    char *task_id = "task-12345";
    char *agent_id = "001";
    char *payload = "{\"version\":\"4.5.0\"}";

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", task_id);
    cJSON_AddStringToObject(parameters, "agent_id", agent_id);
    cJSON_AddStringToObject(parameters, "payload", payload);

    int result = wdb_parse_task_create((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "err Error create task: 'parsing task_type error'");
}

void test_wdb_parse_task_create_payload_err(void **state)
{
    char *task_id = "task-12345";
    char *agent_id = "001";
    char *task_type = "upgrade";

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", task_id);
    cJSON_AddStringToObject(parameters, "agent_id", agent_id);
    cJSON_AddStringToObject(parameters, "task_type", task_type);

    int result = wdb_parse_task_create((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "err Error create task: 'parsing payload error'");
}

/* Test wdb_parse_task_get_pending */

void test_wdb_parse_task_get_pending_ok(void **state)
{
    char *agent_id = "001";

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "agent_id", agent_id);

    cJSON *tasks_array = cJSON_CreateArray();
    cJSON *task = cJSON_CreateObject();
    cJSON_AddStringToObject(task, "task_id", "task-123");
    cJSON_AddStringToObject(task, "task_type", "upgrade");
    cJSON_AddStringToObject(task, "payload", "{\"version\":\"4.5.0\"}");
    cJSON_AddNumberToObject(task, "create_time", 1234567890);
    cJSON_AddItemToArray(tasks_array, task);

    expect_string(__wrap_wdb_task_get_pending, agent_id, agent_id);
    expect_value(__wrap_wdb_task_get_pending, max_tasks, 100);
    will_return(__wrap_wdb_task_get_pending, tasks_array);
    will_return(__wrap_wdb_task_get_pending, OS_SUCCESS);

    int result = wdb_parse_task_get_pending((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_SUCCESS);
    assert_true(strstr(output, "ok {\"error\":0,\"tasks\":[{\"task_id\":\"task-123\"") != NULL);
}

void test_wdb_parse_task_get_pending_err(void **state)
{
    char *agent_id = "001";

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "agent_id", agent_id);

    expect_string(__wrap_wdb_task_get_pending, agent_id, agent_id);
    expect_value(__wrap_wdb_task_get_pending, max_tasks, 100);
    will_return(__wrap_wdb_task_get_pending, NULL);
    will_return(__wrap_wdb_task_get_pending, OS_INVALID);

    int result = wdb_parse_task_get_pending((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "ok {\"error\":-1,\"tasks\":[]}");
}

void test_wdb_parse_task_get_pending_agent_id_err(void **state)
{
    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();

    int result = wdb_parse_task_get_pending((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "err Error get pending tasks: 'parsing agent_id error'");
}

/* Test wdb_parse_task_mark_delivered */

void test_wdb_parse_task_mark_delivered_ok(void **state)
{
    char *task_id = "task-12345";
    int delivery_time = 1234567890;

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", task_id);
    cJSON_AddNumberToObject(parameters, "delivery_time", delivery_time);

    expect_string(__wrap_wdb_task_mark_delivered, task_id, task_id);
    expect_value(__wrap_wdb_task_mark_delivered, delivery_time, delivery_time);
    will_return(__wrap_wdb_task_mark_delivered, OS_SUCCESS);

    int result = wdb_parse_task_mark_delivered((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_SUCCESS);
    assert_string_equal(output, "ok {\"error\":0}");
}

void test_wdb_parse_task_mark_delivered_err(void **state)
{
    char *task_id = "task-12345";
    int delivery_time = 1234567890;

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddStringToObject(parameters, "task_id", task_id);
    cJSON_AddNumberToObject(parameters, "delivery_time", delivery_time);

    expect_string(__wrap_wdb_task_mark_delivered, task_id, task_id);
    expect_value(__wrap_wdb_task_mark_delivered, delivery_time, delivery_time);
    will_return(__wrap_wdb_task_mark_delivered, OS_INVALID);

    int result = wdb_parse_task_mark_delivered((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "ok {\"error\":-1}");
}

void test_wdb_parse_task_mark_delivered_task_id_err(void **state)
{
    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();

    int result = wdb_parse_task_mark_delivered((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "err Error mark delivered: 'parsing task_id error'");
}

/* Test wdb_parse_task_cleanup_expired */

void test_wdb_parse_task_cleanup_expired_ok(void **state)
{
    int ttl = 3600;

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddNumberToObject(parameters, "ttl", ttl);

    expect_value(__wrap_wdb_task_cleanup_expired, ttl, ttl);
    will_return(__wrap_wdb_task_cleanup_expired, OS_SUCCESS);

    int result = wdb_parse_task_cleanup_expired((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_SUCCESS);
    assert_string_equal(output, "ok {\"error\":0}");
}

void test_wdb_parse_task_cleanup_expired_err(void **state)
{
    int ttl = 3600;

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddNumberToObject(parameters, "ttl", ttl);

    expect_value(__wrap_wdb_task_cleanup_expired, ttl, ttl);
    will_return(__wrap_wdb_task_cleanup_expired, OS_INVALID);

    int result = wdb_parse_task_cleanup_expired((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "ok {\"error\":-1}");
}

void test_wdb_parse_task_cleanup_expired_ttl_err(void **state)
{
    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();

    int result = wdb_parse_task_cleanup_expired((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "err Error cleanup expired: 'parsing ttl error'");
}

/* Test wdb_parse_task_delete_old */

void test_wdb_parse_task_delete_old_ok(void **state)
{
    int timestamp = 1234567890;

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddNumberToObject(parameters, "timestamp", timestamp);

    expect_value(__wrap_wdb_task_delete_old, timestamp, timestamp);
    will_return(__wrap_wdb_task_delete_old, OS_SUCCESS);

    int result = wdb_parse_task_delete_old((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_SUCCESS);
    assert_string_equal(output, "ok {\"error\":0}");
}

void test_wdb_parse_task_delete_old_err(void **state)
{
    int timestamp = 1234567890;

    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();
    cJSON_AddNumberToObject(parameters, "timestamp", timestamp);

    expect_value(__wrap_wdb_task_delete_old, timestamp, timestamp);
    will_return(__wrap_wdb_task_delete_old, OS_INVALID);

    int result = wdb_parse_task_delete_old((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "ok {\"error\":-1}");
}

void test_wdb_parse_task_delete_old_timestamp_err(void **state)
{
    char output[OS_MAXSTR + 1];
    *output = '\0';

    cJSON *parameters = cJSON_CreateObject();

    int result = wdb_parse_task_delete_old((wdb_t*)1, parameters, output);

    *state = (void*)parameters;

    assert_int_equal(result, OS_INVALID);
    assert_string_equal(output, "err Error delete old tasks: 'parsing timestamp error'");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // General tests
        cmocka_unit_test_setup_teardown(test_wdb_parse_task_open_tasks_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_task_no_space, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_task_invalid_command, test_setup, test_teardown),
        // wdb_parse_task_create
        cmocka_unit_test_teardown(test_wdb_parse_task_create_ok, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_create_err, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_create_task_id_err, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_create_agent_id_err, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_create_task_type_err, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_create_payload_err, teardown_json),
        // wdb_parse_task_get_pending
        cmocka_unit_test_teardown(test_wdb_parse_task_get_pending_ok, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_get_pending_err, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_get_pending_agent_id_err, teardown_json),
        // wdb_parse_task_mark_delivered
        cmocka_unit_test_teardown(test_wdb_parse_task_mark_delivered_ok, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_mark_delivered_err, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_mark_delivered_task_id_err, teardown_json),
        // wdb_parse_task_cleanup_expired
        cmocka_unit_test_teardown(test_wdb_parse_task_cleanup_expired_ok, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_cleanup_expired_err, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_cleanup_expired_ttl_err, teardown_json),
        // wdb_parse_task_delete_old
        cmocka_unit_test_teardown(test_wdb_parse_task_delete_old_ok, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_delete_old_err, teardown_json),
        cmocka_unit_test_teardown(test_wdb_parse_task_delete_old_timestamp_err, teardown_json),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
