
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "wazuh_db/wdb.h"

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap__mdebug2()
{
    return 0;
}

int __wrap__mwarn()
{
    return 0;
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_sqlite3_bind_int()
{
    return mock_type(int);
}


int __wrap_wdb_open_global()
{
    return mock_type(int);
}

void __wrap_wdb_leave(){}

int  __wrap_wdb_begin2(){
    return mock_type(int);
}

int  __wrap_wdb_stmt_cache(){
    return mock_type(int);
}

cJSON * __wrap_wdb_exec()
{
    return mock_type(cJSON *);
}

const char * __wrap_sqlite3_errmsg(sqlite3 *db)
{
    return NULL;
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
    expect_string(__wrap__mdebug1, formatted_msg, "cannot begin transaction");

    output = wdb_global_get_agent_labels(data->socket, atoi(data->socket->id));
    assert_null(output);
}

void test_get_agent_labels_cache_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "cannot cache statement");

    output = wdb_global_get_agent_labels(data->socket, atoi(data->socket->id));
    assert_null(output);
}

void test_get_agent_labels_bind_fail(void **state)
{
    cJSON *output = NULL;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, 1);
    will_return(__wrap_wdb_stmt_cache, 1);
    will_return(__wrap_sqlite3_bind_int, SQLITE_ERROR);
    expect_string(__wrap__merror, formatted_msg, "DB(000) sqlite3_bind_int(): (null)");

    output = wdb_global_get_agent_labels(data->socket, atoi(data->socket->id));
    assert_null(output);
}

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_agent_labels_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_labels_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_agent_labels_bind_fail, test_setup, test_teardown)      
        };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
