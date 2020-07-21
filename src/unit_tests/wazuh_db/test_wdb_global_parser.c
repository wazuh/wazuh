
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
    return mock();
}

void __wrap_wdb_leave(){}

int __wrap_wdb_exec()
{
    return mock();

}

typedef struct test_struct {
    wdb_t *socket;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data;
    init_data = malloc(sizeof(test_struct_t));
    init_data->socket = malloc(sizeof(wdb_t));
    init_data->socket->id = strdup("000");
    init_data->output = malloc(256*sizeof(char));
    *state = init_data;
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    free(data->output);
    free(data->socket->id);
    free(data->socket);
    free(data);
    return 0;
}

void test_wdb_global_parse_open_global_fail(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("global ");
    will_return(__wrap_wdb_open_global2, NULL);

    
    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, "err Couldn't open DB global");
    assert_int_equal(ret, -1);
}

void test_wdb_global_parse_no_space(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("global");
    char * expected_output = strdup ("err Invalid DB query syntax, near 'global'");

    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, expected_output);
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(expected_output);
}

void test_wdb_global_parse_substr_fail(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("global error");
    will_return(__wrap_wdb_open_global2, 1);
    char * expected_output = strdup("err Invalid DB query syntax, near 'error'");
    
    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, expected_output);
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(expected_output);
}

void test_wdb_global_parse_sql_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("global sql");
    will_return(__wrap_wdb_open_global2, 1);
    char * expected_output = strdup("err Invalid DB query syntax, near 'sql'") ;

    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, expected_output);
    assert_int_equal(ret, -1);

    os_free(query);
    os_free(expected_output);
}

void test_wdb_global_parse_sql_success(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("global sql EXAMPLE QUERY");
    sqlite3 * db;
    data->socket->db=db;
    
    will_return(__wrap_wdb_open_global2, data->socket);

    cJSON *object = cJSON_CreateString("EXPECTED RESULT FROM EXAMPLE QUERY");
    will_return(__wrap_wdb_exec,object);

    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, "ok \"EXPECTED RESULT FROM EXAMPLE QUERY\"");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_wdb_global_parse_sql_fail(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("global sql EXAMPLE QUERY");
    sqlite3 * db;
    data->socket->db=db;
    will_return(__wrap_wdb_open_global2, data->socket);
    
    will_return(__wrap_wdb_exec,NULL);

    ret = wdb_parse(query, data->output);
    
    assert_string_equal(data->output, "err Cannot execute Global database query; library routine called out of sequence");
    assert_int_equal(ret, -1);

    os_free(query);
}

int main()
{
    const struct CMUnitTest tests[] = 
    {
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_open_global_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_no_space, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_substr_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_sql_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_sql_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_global_parse_sql_fail, test_setup, test_teardown)

    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}