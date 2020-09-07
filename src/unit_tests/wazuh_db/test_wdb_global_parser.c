
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"

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

void test_wdb_global_parse_open_global_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global ";

    will_return(__wrap_wdb_open_global, NULL);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: ");
    expect_string(__wrap__mdebug2, formatted_msg, "Couldn't open DB global: queue/db/global.db");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Couldn't open DB global");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_global_parse_no_space(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global";

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query: global");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'global'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_global_parse_substr_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global error";

    will_return(__wrap_wdb_open_global, (wdb_t*)1);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: error");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: error");


    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'error'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_global_parse_sql_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sql";

    will_return(__wrap_wdb_open_global, (wdb_t*)1);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sql");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: sql");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'sql'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_global_parse_sql_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sql TEST QUERY";
    cJSON *root = NULL;
    cJSON *object = NULL;

    root = cJSON_CreateArray();
    object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "test_field", "test_value");
    cJSON_AddItemToArray(root, object);

    will_return(__wrap_wdb_open_global, data->socket);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sql TEST QUERY");
    will_return(__wrap_wdb_exec,root);
    expect_string(__wrap_wdb_exec, sql, "TEST QUERY");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok [{\"test_field\":\"test_value\"}]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_global_parse_sql_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sql TEST QUERY";

    will_return(__wrap_wdb_open_global, data->socket);
    expect_string(__wrap_wdb_exec, sql, "TEST QUERY");
    will_return(__wrap_wdb_exec, NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sql TEST QUERY");
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "GLobal DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: TEST QUERY");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_open_global_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_no_space, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_substr_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_sql_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_sql_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_sql_fail, test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
