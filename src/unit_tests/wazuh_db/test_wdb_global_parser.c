
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "wazuh_db/wdb.h"

int __wrap__mdebug1()
{
    return 0;
}

int __wrap__mdebug2()
{
    return 0;
}

int __wrap__mwarn()
{
    return 0;
}

int __wrap__merror()
{
    return 0;
}

int __wrap_wdb_open_global2()
{
    return mock_type(int);
}

void __wrap_wdb_leave(){}

cJSON * __wrap_wdb_exec()
{
    return mock_type(cJSON *);
}

const char * __wrap_sqlite3_errmsg(sqlite3 *db)
{
    return mock_type(const char*);
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

void test_wdb_global_parse_open_global_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;
    
    os_strdup("global ",query);
    will_return(__wrap_wdb_open_global2, NULL);

    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, "err Couldn't open DB global");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_wdb_global_parse_no_space(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char * expected_output = NULL;
    char *query = NULL;

    os_strdup("global",query);
    os_strdup ("err Invalid DB query syntax, near 'global'",expected_output);

    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, expected_output);
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(expected_output);
}

void test_wdb_global_parse_substr_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;
    char * expected_output = NULL;

    will_return(__wrap_wdb_open_global2, 1);
    os_strdup("global error",query);
    os_strdup("err Invalid DB query syntax, near 'error'",expected_output);
    
    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, expected_output);
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(expected_output);
}

void test_wdb_global_parse_sql_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL; 
    char * expected_output = NULL;
    
    os_strdup("err Invalid DB query syntax, near 'sql'",expected_output);
    os_strdup("global sql",query);
    will_return(__wrap_wdb_open_global2, 1);

    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, expected_output);
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(expected_output);
}

void test_wdb_global_parse_sql_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL; 
    
    will_return(__wrap_wdb_open_global2, data->socket);
    os_strdup("global sql EXAMPLE QUERY",query);
    cJSON *object = cJSON_CreateString("EXPECTED RESULT FROM EXAMPLE QUERY");
    will_return(__wrap_wdb_exec,object);

    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, "ok \"EXPECTED RESULT FROM EXAMPLE QUERY\"");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_wdb_global_parse_sql_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL; 
    
    will_return(__wrap_wdb_open_global2, data->socket);
    will_return(__wrap_wdb_exec,NULL);
    will_return(__wrap_sqlite3_errmsg, "test_error");
    will_return(__wrap_sqlite3_errmsg, "test_error");

    os_strdup("global sql EXAMPLE QUERY",query);

    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, "err Cannot execute Global database query; test_error");
    assert_int_equal(ret, -1);

    os_free(query);
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
