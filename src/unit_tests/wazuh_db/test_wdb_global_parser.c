
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "hash_op.h"
#include "os_err.h"
#include "../wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "wazuhdb_op.h"

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

/**
 * @brief Function that generates a random string of 'length' characters long.
 *
 * @param [in] length Length of the string to be generated.
 * @return Response with the generated group name string.
 */
char* group_name_generator(int length) {
    char *group_name = NULL;
    os_calloc(MAX_GROUP_NAME+1, sizeof(char), group_name);
    const char characters [] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    srand(time(NULL));
    for (int i = 0; i < length; ++i) {
        group_name[i] = characters[rand() % (int)sizeof(characters-1)];
    }
    return group_name;
}

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("global",init_data->wdb->id);
    os_calloc(OS_MAXSTR,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    init_data->wdb->enabled=true;
    *state = init_data;
    return 0;
}

static int test_teardown(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

void test_wdb_parse_global_open_global_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global ";

    will_return(__wrap_wdb_open_global, NULL);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: ");
    expect_string(__wrap__mdebug2, formatted_msg, "Couldn't open DB global: queue/db/global.db");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);

    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Couldn't open DB global");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_no_space(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global";

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query: global");

    expect_function_call(__wrap_w_inc_queries_total);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'global'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_substr_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global error";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: error");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: error");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);

    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'error'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sql_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sql";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sql");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: sql");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_sql);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'sql'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sql_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sql TEST QUERY";
    cJSON *root = NULL;
    cJSON *j_object = NULL;

    root = cJSON_CreateArray();
    j_object = cJSON_CreateObject();
    cJSON_AddStringToObject(j_object, "test_field", "test_value");
    cJSON_AddItemToArray(root, j_object);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sql TEST QUERY");
    will_return(__wrap_wdb_exec,root);
    expect_string(__wrap_wdb_exec, sql, "TEST QUERY");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_sql);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_sql_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [{\"test_field\":\"test_value\"}]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_sql_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sql TEST QUERY";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap_wdb_exec, sql, "TEST QUERY");
    will_return(__wrap_wdb_exec, NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sql TEST QUERY");
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: TEST QUERY");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_sql);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_sql_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_actor_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "error ";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid DB query actor: error");

    expect_function_call(__wrap_w_inc_queries_total);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query actor: 'error'");
    assert_int_equal(ret, OS_INVALID);
}

/* Tests wdb_parse_global_insert_agent */

void test_wdb_parse_global_insert_agent_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for insert-agent.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: insert-agent");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_insert_agent);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'insert-agent'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_insert_agent_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when inserting agent.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_insert_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_insert_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_insert_agent_compliant_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent {\"id\":1,\"name\":\"test_name\",\"date_add\":null}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent {\"id\":1,\"name\":\"test_name\",\"date_add\":null}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when inserting agent. Not compliant with constraints defined in the database.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_insert_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_insert_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"id\":1,\"name\":\"test_name\",\"date'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_insert_agent_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent {\"id\":1,\"name\":\"test_name\",\"date_add\":123}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent {\"id\":1,\"name\":\"test_name\",\"date_add\":123}");

    expect_value(__wrap_wdb_global_insert_agent, id, 1);
    expect_string(__wrap_wdb_global_insert_agent, name, "test_name");
    expect_value(__wrap_wdb_global_insert_agent, ip, NULL);
    expect_value(__wrap_wdb_global_insert_agent, register_ip, NULL);
    expect_value(__wrap_wdb_global_insert_agent, internal_key, NULL);
    expect_value(__wrap_wdb_global_insert_agent, group, NULL);
    expect_value(__wrap_wdb_global_insert_agent, date_add, 123);
    will_return(__wrap_wdb_global_insert_agent, OS_INVALID);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_insert_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_insert_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_insert_agent_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent {\"id\":1,\"name\":\"test_name\",\"date_add\":123,\
    \"ip\":\"0.0.0.0\",\"register_ip\":\"1.1.1.1\",\"internal_key\":\"test_key\",\"group\":\"test_group\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent {\"id\":1,\"name\":\"test_name\",\"date_add\":123,\
    \"ip\":\"0.0.0.0\",\"register_ip\":\"1.1.1.1\",\"internal_key\":\"test_key\",\"group\":\"test_group\"}");

    expect_value(__wrap_wdb_global_insert_agent, id, 1);
    expect_string(__wrap_wdb_global_insert_agent, name, "test_name");
    expect_string(__wrap_wdb_global_insert_agent, ip, "0.0.0.0");
    expect_string(__wrap_wdb_global_insert_agent, register_ip, "1.1.1.1");
    expect_string(__wrap_wdb_global_insert_agent, internal_key, "test_key");
    expect_string(__wrap_wdb_global_insert_agent, group, "test_group");
    expect_value(__wrap_wdb_global_insert_agent, date_add, 123);
    will_return(__wrap_wdb_global_insert_agent, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_insert_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_insert_agent_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_update_agent_name */

void test_wdb_parse_global_update_agent_name_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-name";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-name");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for update-agent-name.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: update-agent-name");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_name);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'update-agent-name'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_name_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-name {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-name {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when updating agent name.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_name);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_name_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_name_invalid_data(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-name {\"id\":1,\"name\":null}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-name {\"id\":1,\"name\":null}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when updating agent name.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_name);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_name_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"id\":1,\"name\":null}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_name_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-name {\"id\":1,\"name\":\"test_name\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-name {\"id\":1,\"name\":\"test_name\"}");
    expect_value(__wrap_wdb_global_update_agent_name, id, 1);
    expect_string(__wrap_wdb_global_update_agent_name, name, "test_name");
    will_return(__wrap_wdb_global_update_agent_name, OS_INVALID);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_name);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_name_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_name_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-name {\"id\":1,\"name\":\"test_name\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-name {\"id\":1,\"name\":\"test_name\"}");
    expect_value(__wrap_wdb_global_update_agent_name, id, 1);
    expect_string(__wrap_wdb_global_update_agent_name, name, "test_name");
    will_return(__wrap_wdb_global_update_agent_name, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_name);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_name_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_update_agent_data */

void test_wdb_parse_global_update_agent_data_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-data";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-data");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for update-agent-data.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: update-agent-data");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_data);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'update-agent-data'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_data_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-data {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-data {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when updating agent version.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_data);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_data_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_data_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-data {\"id\":1,\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"group_config_status\":\"synced\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg,
    "Global query: update-agent-data {\"id\":1,\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"group_config_status\":\"synced\"}");

    expect_value(__wrap_wdb_global_update_agent_version, id, 1);
    expect_string(__wrap_wdb_global_update_agent_version, os_name, "test_name");
    expect_string(__wrap_wdb_global_update_agent_version, os_version, "test_version");
    expect_string(__wrap_wdb_global_update_agent_version, os_major, "test_major");
    expect_string(__wrap_wdb_global_update_agent_version, os_minor, "test_minor");
    expect_string(__wrap_wdb_global_update_agent_version, os_codename, "test_codename");
    expect_string(__wrap_wdb_global_update_agent_version, os_platform, "test_platform");
    expect_string(__wrap_wdb_global_update_agent_version, os_build, "test_build");
    expect_string(__wrap_wdb_global_update_agent_version, os_uname, "test_uname");
    expect_string(__wrap_wdb_global_update_agent_version, os_arch, "test_arch");
    expect_string(__wrap_wdb_global_update_agent_version, version, "test_version");
    expect_string(__wrap_wdb_global_update_agent_version, config_sum, "test_config");
    expect_string(__wrap_wdb_global_update_agent_version, merged_sum, "test_merged");
    expect_string(__wrap_wdb_global_update_agent_version, manager_host, "test_manager");
    expect_string(__wrap_wdb_global_update_agent_version, node_name, "test_node");
    expect_string(__wrap_wdb_global_update_agent_version, agent_ip, "test_ip");
    expect_string(__wrap_wdb_global_update_agent_version, connection_status, "active");
    expect_string(__wrap_wdb_global_update_agent_version, sync_status, "syncreq");
    expect_string(__wrap_wdb_global_update_agent_version, group_config_status, "synced");

    will_return(__wrap_wdb_global_update_agent_version, OS_INVALID);

    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_data);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_data_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_data_invalid_data(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-data {\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"group_config_status\":\"synced\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg,
    "Global query: update-agent-data {\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"group_config_status\":\"synced\"}");

    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when updating agent version.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_data);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_data_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"os_name\":\"test_name\",\"os_versi'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_data_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-data {\"id\":1,\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"group_config_status\":\"not synced\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg,
    "Global query: update-agent-data {\"id\":1,\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"group_config_status\":\"not synced\"}");

    expect_value(__wrap_wdb_global_update_agent_version, id, 1);
    expect_string(__wrap_wdb_global_update_agent_version, os_name, "test_name");
    expect_string(__wrap_wdb_global_update_agent_version, os_version, "test_version");
    expect_string(__wrap_wdb_global_update_agent_version, os_major, "test_major");
    expect_string(__wrap_wdb_global_update_agent_version, os_minor, "test_minor");
    expect_string(__wrap_wdb_global_update_agent_version, os_codename, "test_codename");
    expect_string(__wrap_wdb_global_update_agent_version, os_platform, "test_platform");
    expect_string(__wrap_wdb_global_update_agent_version, os_build, "test_build");
    expect_string(__wrap_wdb_global_update_agent_version, os_uname, "test_uname");
    expect_string(__wrap_wdb_global_update_agent_version, os_arch, "test_arch");
    expect_string(__wrap_wdb_global_update_agent_version, version, "test_version");
    expect_string(__wrap_wdb_global_update_agent_version, config_sum, "test_config");
    expect_string(__wrap_wdb_global_update_agent_version, merged_sum, "test_merged");
    expect_string(__wrap_wdb_global_update_agent_version, manager_host, "test_manager");
    expect_string(__wrap_wdb_global_update_agent_version, node_name, "test_node");
    expect_string(__wrap_wdb_global_update_agent_version, agent_ip, "test_ip");
    expect_string(__wrap_wdb_global_update_agent_version, connection_status, "active");
    expect_string(__wrap_wdb_global_update_agent_version, sync_status, "syncreq");
    expect_string(__wrap_wdb_global_update_agent_version, group_config_status, "not synced");

    will_return(__wrap_wdb_global_update_agent_version, OS_SUCCESS);

    expect_value(__wrap_wdb_global_del_agent_labels, id, 1);
    will_return(__wrap_wdb_global_del_agent_labels, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_data);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_agent_data_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_get_agent_labels */

void test_wdb_parse_global_get_agent_labels_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-labels";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-labels");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for get-labels.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: get-labels");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_labels_get_labels);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'get-labels'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agent_labels_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-labels 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-labels 1");
    expect_value(__wrap_wdb_global_get_agent_labels, id, 1);
    will_return(__wrap_wdb_global_get_agent_labels, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting agent labels from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_labels_get_labels);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_labels_get_labels_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting agent labels from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agent_labels_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-labels 1";
    cJSON *root = NULL;
    cJSON *j_object = NULL;

    root = cJSON_CreateArray();
    j_object = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_object, "id", 1);
    cJSON_AddStringToObject(j_object, "key", "test_key");
    cJSON_AddStringToObject(j_object, "value", "test_value");
    cJSON_AddItemToArray(root, j_object);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-labels 1");
    expect_value(__wrap_wdb_global_get_agent_labels, id, 1);
    will_return(__wrap_wdb_global_get_agent_labels, root);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_labels_get_labels);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_labels_get_labels_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]");
    assert_int_equal(ret, OS_SUCCESS);

}

/* Tests wdb_parse_global_update_agent_keepalive */

void test_wdb_parse_global_update_agent_keepalive_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-keepalive";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-keepalive");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for update-keepalive.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: update-keepalive");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_keepalive);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'update-keepalive'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_keepalive_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-keepalive {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-keepalive {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when updating agent keepalive.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_keepalive);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_keepalive_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_keepalive_invalid_data(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":null}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":null}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when updating agent keepalive.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_keepalive);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_keepalive_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"id\":1,\"connection_status\":\"act'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_keepalive_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_value(__wrap_wdb_global_update_agent_keepalive, id, 1);
    expect_string(__wrap_wdb_global_update_agent_keepalive, connection_status, "active");
    expect_string(__wrap_wdb_global_update_agent_keepalive, status, "syncreq");
    will_return(__wrap_wdb_global_update_agent_keepalive, OS_INVALID);

    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\"}");
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_keepalive);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_keepalive_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_keepalive_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_value(__wrap_wdb_global_update_agent_keepalive, id, 1);
    expect_string(__wrap_wdb_global_update_agent_keepalive, connection_status, "active");
    expect_string(__wrap_wdb_global_update_agent_keepalive, status, "syncreq");
    will_return(__wrap_wdb_global_update_agent_keepalive, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\"}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_keepalive);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_keepalive_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_update_connection_status */

void test_wdb_parse_global_update_connection_status_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-connection-status";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-connection-status");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for update-connection-status.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: update-connection-status");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_connection_status);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'update-connection-status'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_connection_status_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-connection-status {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-connection-status {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when updating agent connection status.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_connection_status);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_connection_status_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_connection_status_invalid_data(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-connection-status {\"id\":1,\"connection_status\":null}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-connection-status {\"id\":1,\"connection_status\":null}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when updating agent connection status.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_connection_status);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_connection_status_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"id\":1,\"connection_status\":null'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_connection_status_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"status_code\":0}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_value(__wrap_wdb_global_update_agent_connection_status, id, 1);
    expect_string(__wrap_wdb_global_update_agent_connection_status, connection_status, "active");
    expect_string(__wrap_wdb_global_update_agent_connection_status, sync_status, "syncreq");
    expect_value(__wrap_wdb_global_update_agent_connection_status, status_code, 0);
    will_return(__wrap_wdb_global_update_agent_connection_status, OS_INVALID);

    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"status_code\":0}");
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_connection_status);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_connection_status_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_connection_status_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"status_code\":0}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_value(__wrap_wdb_global_update_agent_connection_status, id, 1);
    expect_string(__wrap_wdb_global_update_agent_connection_status, connection_status, "active");
    expect_string(__wrap_wdb_global_update_agent_connection_status, sync_status, "syncreq");
    expect_value(__wrap_wdb_global_update_agent_connection_status, status_code, 0);
    will_return(__wrap_wdb_global_update_agent_connection_status, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\"status_code\":0}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_connection_status);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_connection_status_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_update_status_code */

void test_wdb_parse_global_update_status_code_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-status-code";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-status-code");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for update-status-code.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: update-status-code");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_status_code);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'update-status-code'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_status_code_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-status-code {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-status-code {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when updating agent status code.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_status_code);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_status_code_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_status_code_invalid_data(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-status-code {\"id\":1,\"sync_status\":null}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-status-code {\"id\":1,\"sync_status\":null}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when updating agent status code.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_status_code);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_status_code_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"id\":1,\"sync_status\":null}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_status_code_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-status-code {\"id\":1,\"status_code\":0,\"version\":\"v4.5.0\",\"sync_status\":\"syncreq\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_value(__wrap_wdb_global_update_agent_status_code, id, 1);
    expect_value(__wrap_wdb_global_update_agent_status_code, status_code, 0);
    expect_string(__wrap_wdb_global_update_agent_status_code, version, "v4.5.0");
    expect_string(__wrap_wdb_global_update_agent_status_code, sync_status, "syncreq");
    will_return(__wrap_wdb_global_update_agent_status_code, OS_INVALID);

    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-status-code {\"id\":1,\"status_code\":0,\"version\":\"v4.5.0\",\"sync_status\":\"syncreq\"}");
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_status_code);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_status_code_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_status_code_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-status-code {\"id\":1,\"status_code\":0,\"version\":\"v4.5.0\",\"sync_status\":\"syncreq\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_value(__wrap_wdb_global_update_agent_status_code, id, 1);
    expect_value(__wrap_wdb_global_update_agent_status_code, status_code, 0);
    expect_string(__wrap_wdb_global_update_agent_status_code, version, "v4.5.0");
    expect_string(__wrap_wdb_global_update_agent_status_code, sync_status, "syncreq");
    will_return(__wrap_wdb_global_update_agent_status_code, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-status-code {\"id\":1,\"status_code\":0,\"version\":\"v4.5.0\",\"sync_status\":\"syncreq\"}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_update_status_code);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_update_status_code_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_delete_agent */

void test_wdb_parse_global_delete_agent_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-agent";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-agent");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for delete-agent.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: delete-agent");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_delete_agent);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'delete-agent'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_delete_agent_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-agent 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-agent 1");
    expect_value(__wrap_wdb_global_delete_agent, id, 1);
    will_return(__wrap_wdb_global_delete_agent, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Error deleting agent from agent table in global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_delete_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_delete_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error deleting agent from agent table in global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_delete_agent_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-agent 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-agent 1");
    expect_value(__wrap_wdb_global_delete_agent, id, 1);
    will_return(__wrap_wdb_global_delete_agent, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_delete_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_delete_agent_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_select_agent_name */

void test_wdb_parse_global_select_agent_name_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-agent-name";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-agent-name");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for select-agent-name.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: select-agent-name");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_select_agent_name);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'select-agent-name'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_select_agent_name_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-agent-name 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-agent-name 1");
    expect_value(__wrap_wdb_global_select_agent_name, id, 1);
    will_return(__wrap_wdb_global_select_agent_name, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting agent name from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_select_agent_name);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_select_agent_name_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting agent name from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_select_agent_name_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-agent-name 1";
    cJSON *j_object = NULL;

    j_object = cJSON_CreateObject();
    cJSON_AddStringToObject(j_object, "name", "test_name");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-agent-name 1");
    expect_value(__wrap_wdb_global_select_agent_name, id, 1);
    will_return(__wrap_wdb_global_select_agent_name, j_object);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_select_agent_name);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_select_agent_name_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"name\":\"test_name\"}");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_select_agent_group */

void test_wdb_parse_global_select_agent_group_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-agent-group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-agent-group");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for select-agent-group.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: select-agent-group");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_select_agent_group);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'select-agent-group'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_select_agent_group_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-agent-group 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-agent-group 1");
    expect_value(__wrap_wdb_global_select_agent_group, id, 1);
    will_return(__wrap_wdb_global_select_agent_group, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting agent group from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_select_agent_group);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_select_agent_group_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting agent group from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_select_agent_group_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-agent-group 1";
    cJSON *j_object = NULL;

    j_object = cJSON_CreateObject();
    cJSON_AddStringToObject(j_object, "name", "test_name");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-agent-group 1");
    expect_value(__wrap_wdb_global_select_agent_group, id, 1);
    will_return(__wrap_wdb_global_select_agent_group, j_object);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_select_agent_group);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_select_agent_group_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"name\":\"test_name\"}");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_find_agent */

void test_wdb_parse_global_find_agent_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global find-agent";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: find-agent");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for find-agent.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: find-agent");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_find_agent);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'find-agent'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_find_agent_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global find-agent {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: find-agent {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when finding agent id.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_find_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_find_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_find_agent_invalid_data(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global find-agent {\"ip\":null,\"name\":\"test_name\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: find-agent {\"ip\":null,\"name\":\"test_name\"}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when finding agent id.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_find_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_find_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"ip\":null,\"name\":\"test_name\"}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_find_agent_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global find-agent {\"ip\":\"0.0.0.0\",\"name\":\"test_name\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: find-agent {\"ip\":\"0.0.0.0\",\"name\":\"test_name\"}");
    expect_string(__wrap_wdb_global_find_agent, ip, "0.0.0.0");
    expect_string(__wrap_wdb_global_find_agent, name, "test_name");
    will_return(__wrap_wdb_global_find_agent, NULL);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_find_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_find_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_find_agent_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global find-agent {\"ip\":\"0.0.0.0\",\"name\":\"test_name\"}";
    cJSON *j_object = NULL;

    j_object = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_object, "id", 1);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: find-agent {\"ip\":\"0.0.0.0\",\"name\":\"test_name\"}");
    expect_string(__wrap_wdb_global_find_agent, ip, "0.0.0.0");
    expect_string(__wrap_wdb_global_find_agent, name, "test_name");
    will_return(__wrap_wdb_global_find_agent, j_object);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_find_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_find_agent_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"id\":1}");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_find_group */

void test_wdb_parse_global_find_group_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global find-group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: find-group");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for find-group.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: find-group");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_find_group);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'find-group'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_find_group_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global find-group test_group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: find-group test_group");
    expect_string(__wrap_wdb_global_find_group, group_name, "test_group");
    will_return(__wrap_wdb_global_find_group, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting group id from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_find_group);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_group_find_group_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting group id from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_find_group_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global find-group test_group";
    cJSON *j_object = NULL;

    j_object = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_object, "id", 1);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: find-group test_group");
    expect_string(__wrap_wdb_global_find_group, group_name, "test_group");
    will_return(__wrap_wdb_global_find_group, j_object);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_find_group);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_group_find_group_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"id\":1}");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_insert_agent_group */

void test_wdb_parse_global_insert_agent_group_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent-group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent-group");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for insert-agent-group.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: insert-agent-group");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_insert_agent_group);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'insert-agent-group'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_insert_agent_group_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent-group test_group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent-group test_group");
    expect_string(__wrap_wdb_global_insert_agent_group, group_name, "test_group");
    will_return(__wrap_wdb_global_insert_agent_group, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Error inserting group in global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_insert_agent_group);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_group_insert_agent_group_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error inserting group in global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_insert_agent_group_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent-group test_group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent-group test_group");
    expect_string(__wrap_wdb_global_insert_agent_group, group_name, "test_group");
    will_return(__wrap_wdb_global_insert_agent_group, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_insert_agent_group);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_group_insert_agent_group_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_select_group_belong */

void test_wdb_parse_global_select_group_belong_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-group-belong";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-group-belong");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for select-group-belong.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: select-group-belong");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_belongs_select_group_belong);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'select-group-belong'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_select_group_belong_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-group-belong 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-group-belong 1");
    expect_value(__wrap_wdb_global_select_group_belong, id_agent, 1);
    will_return(__wrap_wdb_global_select_group_belong, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting agent groups information from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_belongs_select_group_belong);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_belongs_select_group_belong_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting agent groups information from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_select_group_belong_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-group-belong 1";
    cJSON *j_response = NULL;

    j_response = cJSON_Parse("[\"default\",\"new_group\"]");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-group-belong 1");
    expect_value(__wrap_wdb_global_select_group_belong, id_agent, 1);
    will_return(__wrap_wdb_global_select_group_belong, j_response);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_belongs_select_group_belong);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_belongs_select_group_belong_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [\"default\",\"new_group\"]");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_get_group_agents */

void test_wdb_parse_global_get_group_agents_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-group-agents";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-group-agents");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for get-group-agents.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: get-group-agents");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'get-group-agents'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_group_agents_group_missing(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-group-agents ";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-group-agents ");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments, group name not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments, group name not found.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_group_agents_last_id_missing(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-group-agents group_name";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-group-agents group_name");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments, 'last_id' not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments, 'last_id' not found.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_group_agents_last_id_value_missing(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-group-agents group_name last_id";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-group-agents group_name last_id");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments, last agent id not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments, last agent id not found.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_group_agents_failed(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-group-agents group_name last_id 0";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-group-agents group_name last_id 0");

    expect_string(__wrap_wdb_global_get_group_agents, group_name, "group_name");
    expect_value(__wrap_wdb_global_get_group_agents, last_agent_id, 0);
    will_return(__wrap_wdb_global_get_group_agents, WDBC_ERROR);
    will_return(__wrap_wdb_global_get_group_agents, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting group agents from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting group agents from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_group_agents_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-group-agents group_name last_id 0";
    cJSON *result = cJSON_Parse("[1,2,3]");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-group-agents group_name last_id 0");

    expect_string(__wrap_wdb_global_get_group_agents, group_name, "group_name");
    expect_value(__wrap_wdb_global_get_group_agents, last_agent_id, 0);
    will_return(__wrap_wdb_global_get_group_agents, WDBC_OK);
    will_return(__wrap_wdb_global_get_group_agents, result);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_belongs_get_group_agent_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [1,2,3]");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_delete_group */

void test_wdb_parse_global_delete_group_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-group");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for delete-group.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: delete-group");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_delete_group);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'delete-group'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_delete_group_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-group test_group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-group test_group");
    expect_string(__wrap_wdb_global_delete_group, group_name, "test_group");
    will_return(__wrap_wdb_global_delete_group, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Error deleting group in global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_delete_group);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_group_delete_group_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error deleting group in global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_delete_group_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-group test_group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-group test_group");
    expect_string(__wrap_wdb_global_delete_group, group_name, "test_group");
    will_return(__wrap_wdb_global_delete_group, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_delete_group);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_group_delete_group_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_select_groups */

void test_wdb_parse_global_select_groups_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-groups";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-groups");
    will_return(__wrap_wdb_global_select_groups, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting groups from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_select_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_group_select_groups_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting groups from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_select_groups_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-groups";
    cJSON *j_object = NULL;

    j_object = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_object, "id", 1);
    cJSON_AddNumberToObject(j_object, "id", 2);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-groups");
    will_return(__wrap_wdb_global_select_groups, j_object);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_group_select_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_group_select_groups_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"id\":1,\"id\":2}");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_sync_agent_info_get */

void test_wdb_parse_global_sync_agent_info_get_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-info-get";
    char *sync_info = "{SYNC INFO}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-info-get");
    expect_value(__wrap_wdb_global_sync_agent_info_get, *last_agent_id, 0);
    will_return(__wrap_wdb_global_sync_agent_info_get, sync_info);
    will_return(__wrap_wdb_global_sync_agent_info_get, WDBC_OK);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_get_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {SYNC INFO}");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_sync_agent_info_get_last_id_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-info-get last_id 1";
    char *sync_info = "{SYNC INFO}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-info-get last_id 1");
    expect_value(__wrap_wdb_global_sync_agent_info_get, *last_agent_id, 1);
    will_return(__wrap_wdb_global_sync_agent_info_get, sync_info);
    will_return(__wrap_wdb_global_sync_agent_info_get, WDBC_OK);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_get_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {SYNC INFO}");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_sync_agent_info_get_size_limit(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-info-get";
    char sync_info[WDB_MAX_RESPONSE_SIZE + 1] = {0};
    char content = 'A';
    for (size_t i = 0; i < WDB_MAX_RESPONSE_SIZE; i++) {
        sync_info[i] = content;
        content = content <= 'z' ? content+1 : 'A';
    }

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-info-get");
    expect_value(__wrap_wdb_global_sync_agent_info_get, *last_agent_id, 0);
    will_return(__wrap_wdb_global_sync_agent_info_get, sync_info);
    will_return(__wrap_wdb_global_sync_agent_info_get, WDBC_OK);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_get_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    char delims[] = " ";
    char* payload = NULL;
    char* status = NULL;
    status = strtok_r(data->output, delims, &payload);

    assert_string_equal(status, "ok");
    assert_string_equal(payload, sync_info);
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_sync_agent_info_set */

void test_wdb_parse_global_sync_agent_info_set_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-info-set";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-info-set");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for sync-agent-info-set.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: sync-agent-info-set");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'sync-agent-info-set'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_info_set_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-info-set {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-info-set {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax updating unsynced agents.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_info_set_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-info-set [{\"id\":1,\"name\":\"test_name\",\
     \"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}]";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-info-set [{\"id\":1,\"name\":\"test_name\",\
     \"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}]");
    expect_string(__wrap_wdb_global_sync_agent_info_set, str_agent,
     "{\"id\":1,\"name\":\"test_name\",\"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}");
    will_return(__wrap_wdb_global_sync_agent_info_set, OS_INVALID);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_info_set_id_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-info-set [{\"id\":null,\"name\":\"test_name\",\
     \"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}]";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-info-set [{\"id\":null,\"name\":\"test_name\",\
     \"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}]");
    expect_string(__wrap_wdb_global_sync_agent_info_set, str_agent,
     "{\"id\":null,\"name\":\"test_name\",\"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}");
    will_return(__wrap_wdb_global_sync_agent_info_set, OS_SUCCESS);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; incorrect agent id in labels array.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot update labels due to invalid id.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_info_set_del_label_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-info-set [{\"id\":1,\"name\":\"test_name\",\
     \"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}]";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-info-set [{\"id\":1,\"name\":\"test_name\",\
     \"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}]");
    expect_string(__wrap_wdb_global_sync_agent_info_set, str_agent,
     "{\"id\":1,\"name\":\"test_name\",\"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}");
    will_return(__wrap_wdb_global_sync_agent_info_set, OS_SUCCESS);

    expect_value(__wrap_wdb_global_del_agent_labels, id, 1);
    will_return(__wrap_wdb_global_del_agent_labels, OS_INVALID);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_info_set_set_label_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-info-set [{\"id\":1,\"name\":\"test_name\",\
     \"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}]";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-info-set [{\"id\":1,\"name\":\"test_name\",\
     \"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}]");
    expect_string(__wrap_wdb_global_sync_agent_info_set, str_agent,
     "{\"id\":1,\"name\":\"test_name\",\"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}");
    will_return(__wrap_wdb_global_sync_agent_info_set, OS_SUCCESS);
    expect_value(__wrap_wdb_global_del_agent_labels, id, 1);
    will_return(__wrap_wdb_global_del_agent_labels, OS_SUCCESS);

    expect_value(__wrap_wdb_global_set_agent_label, id, 1);
    expect_string(__wrap_wdb_global_set_agent_label, key, "test_key");
    expect_string(__wrap_wdb_global_set_agent_label, value, "test_value");
    will_return(__wrap_wdb_global_set_agent_label, OS_INVALID);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_info_set_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-info-set [{\"id\":1,\"name\":\"test_name\",\
     \"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}]";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-info-set [{\"id\":1,\"name\":\"test_name\",\
     \"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}]");
    expect_string(__wrap_wdb_global_sync_agent_info_set, str_agent,
     "{\"id\":1,\"name\":\"test_name\",\"labels\":[{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]}");
    will_return(__wrap_wdb_global_sync_agent_info_set, OS_SUCCESS);
    expect_value(__wrap_wdb_global_del_agent_labels, id, 1);
    will_return(__wrap_wdb_global_del_agent_labels, OS_SUCCESS);

    expect_value(__wrap_wdb_global_set_agent_label, id, 1);
    expect_string(__wrap_wdb_global_set_agent_label, key, "test_key");
    expect_string(__wrap_wdb_global_set_agent_label, value, "test_value");
    will_return(__wrap_wdb_global_set_agent_label, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_info_set_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_set_agent_groups */

void test_wdb_parse_global_set_agent_groups_syntax_error(void **state)
{
    int ret = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-agent-groups";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-agent-groups");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for set-agent-groups.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: set-agent-groups");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'set-agent-groups'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_set_agent_groups_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-agent-groups {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-agent-groups {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when parsing set_agent_groups");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_set_agent_groups_missing_field(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-agent-groups {\"sync_status\":\"synced\",\"data\":[{\"id\":1,\"groups\":[\"default\"]}]}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-agent-groups {\"sync_status\":\"synced\",\"data\":[{\"id\":1,\"groups\":[\"default\"]}]}");
    expect_string(__wrap__mdebug1, formatted_msg, "Missing mandatory fields in set_agent_groups command.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, missing required fields");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_set_agent_groups_invalid_mode(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-agent-groups {\"mode\":\"invalid_mode\",\"sync_status\":\"synced\",\"data\":[{\"id\":1,\"groups\":[\"default\"]}]}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-agent-groups {\"mode\":\"invalid_mode\",\"sync_status\":\"synced\",\"data\":[{\"id\":1,\"groups\":[\"default\"]}]}");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid mode 'invalid_mode' in set_agent_groups command.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid mode 'invalid_mode' in set_agent_groups command");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_set_agent_groups_fail(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-agent-groups {\"mode\":\"override\",\"sync_status\":\"synced\",\"data\":[{\"id\":1,\"groups\":[\"default\"]}]}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-agent-groups {\"mode\":\"override\",\"sync_status\":\"synced\",\"data\":[{\"id\":1,\"groups\":[\"default\"]}]}");
    expect_value(__wrap_wdb_global_set_agent_groups, mode, WDB_GROUP_OVERRIDE);
    expect_string(__wrap_wdb_global_set_agent_groups, sync_status, "synced");
    expect_string(__wrap_wdb_global_set_agent_groups, agents_group_info, "[{\"id\":1,\"groups\":[\"default\"]}]");
    will_return(__wrap_wdb_global_set_agent_groups, WDBC_ERROR);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err An error occurred during the set of the groups");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_set_agent_groups_success(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-agent-groups {\"mode\":\"append\",\"sync_status\":\"synced\",\"data\":[{\"id\":1,\"groups\":[\"default\"]}]}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-agent-groups {\"mode\":\"append\",\"sync_status\":\"synced\",\"data\":[{\"id\":1,\"groups\":[\"default\"]}]}");
    expect_value(__wrap_wdb_global_set_agent_groups, mode, WDB_GROUP_APPEND);
    expect_string(__wrap_wdb_global_set_agent_groups, sync_status, "synced");
    expect_string(__wrap_wdb_global_set_agent_groups, agents_group_info, "[{\"id\":1,\"groups\":[\"default\"]}]");
    will_return(__wrap_wdb_global_set_agent_groups, WDBC_OK);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_set_agent_groups_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_sync_agent_groups_get */

void test_wdb_parse_global_sync_agent_groups_get_syntax_error(void **state)
{
    int ret = OS_SUCCESS;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for sync-agent-groups-get.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: sync-agent-groups-get");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'sync-agent-groups-get'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_groups_get_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when parsing sync-agent-groups-get");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_groups_without_condition_field_succes(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"get_global_hash\":true}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"get_global_hash\":true}");

    cJSON *output = cJSON_CreateArray();
    cJSON *j_response = cJSON_CreateObject();
    cJSON *j_data = cJSON_CreateArray();
    cJSON_AddItemToArray(output, j_response);
    cJSON_AddItemToObject(j_response, "data", j_data);
    cJSON_AddStringToObject(j_response, "hash", "random_hash");

    expect_value(__wrap_wdb_global_sync_agent_groups_get, condition, WDB_GROUP_NO_CONDITION);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, last_agent_id, 0);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, set_synced, false);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, get_hash, true);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, agent_registration_delta, 0);
    will_return(__wrap_wdb_global_sync_agent_groups_get, output);
    will_return(__wrap_wdb_global_sync_agent_groups_get, WDBC_OK);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [{\"data\":[],\"hash\":\"random_hash\"}]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_sync_agent_groups_get_invalid_last_id_data_type(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"condition\":\"sync_status\",\"last_id\":\"1_string\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"condition\":\"sync_status\",\"last_id\":\"1_string\"}");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid alternative fields data in sync-agent-groups-get command.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, invalid alternative fields data");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_groups_get_invalid_last_id_negative(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"condition\":\"sync_status\",\"last_id\":-1}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"condition\":\"sync_status\",\"last_id\":-1}");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid alternative fields data in sync-agent-groups-get command.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, invalid alternative fields data");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_groups_get_invalid_condition_data_type(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"condition\":10}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"condition\":10}");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid alternative fields data in sync-agent-groups-get command.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, invalid alternative fields data");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_groups_get_invalid_set_synced_data_type(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"condition\":\"sync_status\",\"set_synced\":\"true_string\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"condition\":\"sync_status\",\"set_synced\":\"true_string\"}");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid alternative fields data in sync-agent-groups-get command.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, invalid alternative fields data");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_groups_get_invalid_get_hash_data_type(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"condition\":\"sync_status\",\"get_global_hash\":\"true_string\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"condition\":\"sync_status\",\"get_global_hash\":\"true_string\"}");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid alternative fields data in sync-agent-groups-get command.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, invalid alternative fields data");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_groups_get_invalid_agent_registration_delta_data_type(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"condition\":\"sync_status\",\"agent_registration_delta\":\"0_string\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"condition\":\"sync_status\",\"agent_registration_delta\":\"0_string\"}");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid alternative fields data in sync-agent-groups-get command.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, invalid alternative fields data");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_groups_get_invalid_agent_registration_delta_negative(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"condition\":\"sync_status\",\"agent_registration_delta\":-1}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"condition\":\"sync_status\",\"agent_registration_delta\":-1}");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid alternative fields data in sync-agent-groups-get command.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON data, invalid alternative fields data");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_groups_get_null_response(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"condition\":\"sync_status\",\"last_id\":3,\"set_synced\":true,\"get_global_hash\":true}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"condition\":\"sync_status\",\"last_id\":3,\"set_synced\":true,\"get_global_hash\":true}");
    expect_value(__wrap_wdb_global_sync_agent_groups_get, condition, WDB_GROUP_SYNC_STATUS);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, last_agent_id, 3);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, set_synced, true);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, get_hash, true);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, agent_registration_delta, 0);
    will_return(__wrap_wdb_global_sync_agent_groups_get, NULL);
    will_return(__wrap_wdb_global_sync_agent_groups_get, WDBC_ERROR);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Could not obtain a response from wdb_global_sync_agent_groups_get");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_sync_agent_groups_get_success(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"condition\":\"all\",\"last_id\":3,\"set_synced\":true,\"get_global_hash\":true,"
                                 "\"agent_registration_delta\":10}";
    cJSON *output = cJSON_CreateArray();
    cJSON *j_response = cJSON_CreateObject();
    cJSON *j_data = cJSON_CreateArray();
    cJSON_AddItemToArray(output, j_response);
    cJSON_AddItemToObject(j_response, "data", j_data);
    cJSON_AddStringToObject(j_response, "hash", "random_hash");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"condition\":\"all\",\"last_id\":3,\"set_synced\":true,"
                                                  "\"get_global_hash\":true,\"agent_registration_delta\":10}");
    expect_value(__wrap_wdb_global_sync_agent_groups_get, condition, WDB_GROUP_ALL);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, last_agent_id, 3);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, set_synced, true);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, get_hash, true);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, agent_registration_delta, 10);
    will_return(__wrap_wdb_global_sync_agent_groups_get, output);
    will_return(__wrap_wdb_global_sync_agent_groups_get, WDBC_OK);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [{\"data\":[],\"hash\":\"random_hash\"}]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_sync_agent_groups_get_invalid_response(void **state)
{
    int ret = 0;
    test_struct_t *data = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sync-agent-groups-get {\"condition\":\"all\",\"last_id\":3,\"set_synced\":true,\"get_global_hash\":true,"
                                 "\"agent_registration_delta\":15}";

    cJSON *output = cJSON_CreateArray();
    cJSON *j_response = cJSON_CreateObject();
    cJSON *j_data = cJSON_CreateArray();
    cJSON_AddItemToArray(output, j_response);
    cJSON_AddItemToObject(j_response, "data", j_data);
    cJSON_AddStringToObject(j_response, "hash", "random_hash");

    cJSON *j_data_object_1 = cJSON_CreateObject();
    cJSON *j_groups = cJSON_CreateArray();
    cJSON_AddNumberToObject(j_data_object_1, "id", 1);
    cJSON_AddItemToObject(j_data_object_1, "groups", j_groups);

    for (int i = 0; i < MAX_GROUPS_PER_MULTIGROUP; ++i) {
        char *group_name = group_name_generator(MAX_GROUP_NAME);
        cJSON_AddItemToArray(j_groups, cJSON_CreateString(group_name));
        os_free(group_name);
    }

    cJSON_AddItemToArray(j_data, j_data_object_1);

    cJSON *j_data_object_2 = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_data_object_2, "id", 2);
    cJSON_AddItemToObject(j_data_object_2, "groups", cJSON_Duplicate(j_groups, true));
    cJSON_AddItemToArray(j_data, j_data_object_2);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: sync-agent-groups-get {\"condition\":\"all\",\"last_id\":3,\"set_synced\":true,"
                                                  "\"get_global_hash\":true,\"agent_registration_delta\":15}");
    expect_value(__wrap_wdb_global_sync_agent_groups_get, condition, WDB_GROUP_ALL);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, last_agent_id, 3);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, set_synced, true);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, get_hash, true);
    expect_value(__wrap_wdb_global_sync_agent_groups_get, agent_registration_delta, 15);
    will_return(__wrap_wdb_global_sync_agent_groups_get, output);
    will_return(__wrap_wdb_global_sync_agent_groups_get, WDBC_OK);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_sync_agent_groups_get_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid response from wdb_global_sync_agent_groups_get");
    assert_int_equal(ret, OS_INVALID);
}

/* Tests wdb_parse_global_get_groups_integrity */

void test_wdb_parse_global_get_groups_integrity_syntax_error(void **state)
{
    int ret = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-groups-integrity";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-groups-integrity");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for get-groups-integrity.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: get-groups-integrity");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'get-groups-integrity'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_groups_integrity_hash_length_expected_fail(void **state)
{
    int ret = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-groups-integrity small_hash";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-groups-integrity small_hash");
    // Expected hash should be OS_SHA1_HEXDIGEST_SIZE (40) characters long, and the received hash, "small_hash", is 10 characters long.
    expect_string(__wrap__mdebug1, formatted_msg, "Hash hex-digest does not have the expected length. Expected (40) got (10)");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Hash hex-digest does not have the expected length. Expected (40) got (10)");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_groups_integrity_query_error(void **state)
{
    int ret = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-groups-integrity xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-groups-integrity xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    expect_string(__wrap_wdb_global_get_groups_integrity, hash, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    will_return(__wrap_wdb_global_get_groups_integrity, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting groups integrity information from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting groups integrity information from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_groups_integrity_success_syncreq(void **state)
{
    int ret = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-groups-integrity xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    cJSON* j_response = cJSON_Parse("[\"syncreq\"]");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-groups-integrity xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    expect_string(__wrap_wdb_global_get_groups_integrity, hash, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    will_return(__wrap_wdb_global_get_groups_integrity, j_response);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [\"syncreq\"]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_get_groups_integrity_success_synced(void **state)
{
    int ret = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-groups-integrity xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    cJSON* j_response = cJSON_Parse("[\"synced\"]");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-groups-integrity xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    expect_string(__wrap_wdb_global_get_groups_integrity, hash, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    will_return(__wrap_wdb_global_get_groups_integrity, j_response);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [\"synced\"]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_get_groups_integrity_success_hash_mismatch(void **state)
{
    int ret = OS_SUCCESS;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-groups-integrity xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    cJSON* j_response = cJSON_Parse("[\"hash_mismatch\"]");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-groups-integrity xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    expect_string(__wrap_wdb_global_get_groups_integrity, hash, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    will_return(__wrap_wdb_global_get_groups_integrity, j_response);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_groups_integrity_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [\"hash_mismatch\"]");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_disconnect_agents */

void test_wdb_parse_global_disconnect_agents_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global disconnect-agents";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: disconnect-agents");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for disconnect-agents.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: disconnect-agents");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_disconnect_agents);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'disconnect-agents'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_disconnect_agents_last_id_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global disconnect-agents ";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: disconnect-agents ");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments last id not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_disconnect_agents);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_disconnect_agents_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments last id not found");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_disconnect_agents_keepalive_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global disconnect-agents 0";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: disconnect-agents 0");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments keepalive not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_disconnect_agents);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_disconnect_agents_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments keepalive not found");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_disconnect_agents_sync_status_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global disconnect-agents 0 100";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: disconnect-agents 0 100");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments sync_status not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_disconnect_agents);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_disconnect_agents_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments sync_status not found");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_disconnect_agents_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global disconnect-agents 0 100 syncreq";
    cJSON* root = cJSON_CreateArray();
    cJSON* json_agent = cJSON_CreateObject();
    cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(10));
    cJSON_AddItemToArray(root, json_agent);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: disconnect-agents 0 100 syncreq");
    expect_value(__wrap_wdb_global_get_agents_to_disconnect, last_agent_id, 0);
    expect_value(__wrap_wdb_global_get_agents_to_disconnect, keep_alive, 100);
    expect_string(__wrap_wdb_global_get_agents_to_disconnect, sync_status, "syncreq");
    will_return(__wrap_wdb_global_get_agents_to_disconnect, WDBC_OK);
    will_return(__wrap_wdb_global_get_agents_to_disconnect, root);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_disconnect_agents);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_disconnect_agents_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [{\"id\":10}]");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_get_all_agents */

void test_wdb_parse_global_get_all_agents_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-all-agents";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-all-agents");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for get-all-agents.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: get-all-agents");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'get-all-agents'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_all_agents_argument_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-all-agents invalid";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-all-agents invalid");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments 'last_id' or 'context' not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments 'last_id' or 'context' not found");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_all_agents_argument2_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-all-agents last_id";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-all-agents last_id");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments 'last_id' not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments 'last_id' not found");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_all_agents_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-all-agents last_id 1";
    cJSON* root = cJSON_CreateArray();
    cJSON* json_agent = cJSON_CreateObject();
    cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(10));
    cJSON_AddItemToArray(root, json_agent);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-all-agents last_id 1");
    expect_value(__wrap_wdb_global_get_all_agents, last_agent_id, 1);
    will_return(__wrap_wdb_global_get_all_agents, WDBC_OK);
    will_return(__wrap_wdb_global_get_all_agents, root);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [{\"id\":10}]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_get_all_agents_context_argument2_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-all-agents context";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-all-agents context");
    will_return(__wrap_wdb_global_get_all_agents_context, OS_INVALID);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting agents from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_all_agents_context_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-all-agents context";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-all-agents context");
    will_return(__wrap_wdb_global_get_all_agents_context, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_all_agents_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok []");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_get_agent_info */

void test_wdb_parse_global_get_agent_info_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agent-info";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agent-info");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for get-agent-info.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: get-agent-info");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'get-agent-info'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agent_info_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agent-info 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agent-info 1");
    expect_value(__wrap_wdb_global_get_agent_info, id, 1);
    will_return(__wrap_wdb_global_get_agent_info, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting agent information from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting agent information from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agent_info_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agent-info 1";
    cJSON *j_object = NULL;

    j_object = cJSON_CreateObject();
    cJSON_AddStringToObject(j_object, "name", "test_name");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agent-info 1");
    expect_value(__wrap_wdb_global_get_agent_info, id, 1);
    will_return(__wrap_wdb_global_get_agent_info, j_object);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"name\":\"test_name\"}");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_get_agent_info_by_connection_status_and_node */

void test_wdb_parse_global_get_agent_info_by_connection_status_and_node_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agent-info-by-connection-status-and-node";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agent-info-by-connection-status-and-node");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for get-agent-info-by-connection-status-and-node.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: get-agent-info-by-connection-status-and-node");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'get-agent-info-by-connection-status-and-node'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agent_info_by_connection_status_and_node_syntax_error2(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agent-info-by-connection-status-and-node 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agent-info-by-connection-status-and-node 1");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments 'connection_status' not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments 'connection_status' not found");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agent_info_by_connection_status_and_node_syntax_error3(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agent-info-by-connection-status-and-node 1 active";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agent-info-by-connection-status-and-node 1 active");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments 'node_name' not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments 'node_name' not found");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agent_info_by_connection_status_and_node_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agent-info-by-connection-status-and-node 1 active worker1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agent-info-by-connection-status-and-node 1 active worker1");
    expect_value(__wrap_wdb_global_get_agent_info_by_connection_status_and_node, id, 1);
    expect_string(__wrap_wdb_global_get_agent_info_by_connection_status_and_node, status, "active");
    expect_string(__wrap_wdb_global_get_agent_info_by_connection_status_and_node, node, "worker1");
    will_return(__wrap_wdb_global_get_agent_info_by_connection_status_and_node, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting agent filtered information from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting agent filtered information from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agent_info_by_connection_status_and_node_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agent-info-by-connection-status-and-node 1 active worker1";
    cJSON *j_object = NULL;

    j_object = cJSON_CreateObject();
    cJSON_AddStringToObject(j_object, "name", "test_name");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agent-info-by-connection-status-and-node 1 active worker1");
    expect_value(__wrap_wdb_global_get_agent_info_by_connection_status_and_node, id, 1);
    expect_string(__wrap_wdb_global_get_agent_info_by_connection_status_and_node, status, "active");
    expect_string(__wrap_wdb_global_get_agent_info_by_connection_status_and_node, node, "worker1");
    will_return(__wrap_wdb_global_get_agent_info_by_connection_status_and_node, j_object);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agent_info_by_connection_status_and_node_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"name\":\"test_name\"}");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_reset_agents_connection */

void test_wdb_parse_reset_agents_connection_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global reset-agents-connection";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: reset-agents-connection");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for reset-agents-connection.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: reset-agents-connection");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_reset_agents_connection);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'reset-agents-connection'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_reset_agents_connection_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global reset-agents-connection syncreq";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: reset-agents-connection syncreq");
    expect_string(__wrap_wdb_global_reset_agents_connection, sync_status, "syncreq");
    will_return(__wrap_wdb_global_reset_agents_connection, OS_INVALID);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_reset_agents_connection);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_reset_agents_connection_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_reset_agents_connection_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global reset-agents-connection syncreq";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: reset-agents-connection syncreq");
    expect_string(__wrap_wdb_global_reset_agents_connection, sync_status, "syncreq");
    will_return(__wrap_wdb_global_reset_agents_connection, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_reset_agents_connection);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_reset_agents_connection_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_get_agents_by_connection_status */

void test_wdb_parse_global_get_agents_by_connection_status_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agents-by-connection-status";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agents-by-connection-status");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for get-agents-by-connection-status.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: get-agents-by-connection-status");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'get-agents-by-connection-status'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agents_by_connection_status_status_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agents-by-connection-status 0 ";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agents-by-connection-status 0 ");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments 'connection_status' not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments 'connection_status' not found");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agents_by_connection_status_last_id_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agents-by-connection-status ";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agents-by-connection-status ");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments 'last_id' not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments 'last_id' not found");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agents_by_connection_status_limit_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agents-by-connection-status 0 active node01";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agents-by-connection-status 0 active node01");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments 'limit' not found.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid arguments 'limit' not found");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_agents_by_connection_status_limit_succes(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agents-by-connection-status 0 active node01 -1";
    cJSON* root = cJSON_CreateArray();
    cJSON* json_agent = cJSON_CreateObject();
    cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(10));
    cJSON_AddItemToArray(root, json_agent);


    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agents-by-connection-status 0 active node01 -1");
    expect_value(__wrap_wdb_global_get_agents_by_connection_status, last_agent_id, 0);
    expect_string(__wrap_wdb_global_get_agents_by_connection_status, connection_status, "active");
    expect_string(__wrap_wdb_global_get_agents_by_connection_status, node_name, "node01");
    expect_value(__wrap_wdb_global_get_agents_by_connection_status, limit, -1);
    will_return(__wrap_wdb_global_get_agents_by_connection_status, WDBC_OK);
    will_return(__wrap_wdb_global_get_agents_by_connection_status, root);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [{\"id\":10}]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_get_agents_by_connection_status_query_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agents-by-connection-status 0 active";
    cJSON* root = cJSON_CreateArray();
    cJSON* json_agent = cJSON_CreateObject();
    cJSON_AddItemToObject(json_agent, "id", cJSON_CreateNumber(10));
    cJSON_AddItemToArray(root, json_agent);


    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agents-by-connection-status 0 active");
    expect_value(__wrap_wdb_global_get_agents_by_connection_status, last_agent_id, 0);
    expect_string(__wrap_wdb_global_get_agents_by_connection_status, connection_status, "active");
    will_return(__wrap_wdb_global_get_agents_by_connection_status, WDBC_OK);
    will_return(__wrap_wdb_global_get_agents_by_connection_status, root);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [{\"id\":10}]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_get_agents_by_connection_status_query_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-agents-by-connection-status 0 active";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-agents-by-connection-status 0 active");
    expect_value(__wrap_wdb_global_get_agents_by_connection_status, last_agent_id, 0);
    expect_string(__wrap_wdb_global_get_agents_by_connection_status, connection_status, "active");
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting agents by connection status from global.db.");
    will_return(__wrap_wdb_global_get_agents_by_connection_status, WDBC_UNKNOWN);
    will_return(__wrap_wdb_global_get_agents_by_connection_status, NULL);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_agents_by_connection_status_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting agents by connection status from global.db.");
    assert_int_equal(ret, OS_INVALID);
}


/* wdb_parse_global_get_backup */

void test_wdb_parse_global_get_backup_failed(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global backup get", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: backup get");

    will_return(__wrap_wdb_global_get_backups, NULL);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_backup);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_backup_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot execute backup get command, unable to open 'backup/db' folder");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_get_backup_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;
    cJSON* j_backup = cJSON_Parse("[\"global.db-backup-TIMESTAMP\"]");

    os_strdup("global backup get", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: backup get");

    will_return(__wrap_wdb_global_get_backups, j_backup);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_backup);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_backup_time);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [\"global.db-backup-TIMESTAMP\"]");
    assert_int_equal(result, OS_SUCCESS);

    os_free(query);
}

/* wdb_parse_global_restore_backup */

void test_wdb_parse_global_restore_backup_invalid_syntax(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global backup restore {INVALID_JSON}", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: backup restore {INVALID_JSON}");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid backup JSON syntax when restoring snapshot.");
    expect_string(__wrap__mdebug2, formatted_msg, "JSON error near: NVALID_JSON}");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_backup);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_backup_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_restore_backup_success_missing_snapshot(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global backup restore", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: backup restore");

    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_backup);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_backup_time);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_int_equal(result, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_global_restore_backup_success_pre_restore_true(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global backup restore {\"snapshot\":\"global.db-backup-TIMESTAMP\",\"save_pre_restore_state\":true}", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: backup restore {\"snapshot\":\"global.db-backup-TIMESTAMP\",\"save_pre_restore_state\":true}");

    expect_string(__wrap_wdb_global_restore_backup, snapshot, "global.db-backup-TIMESTAMP");
    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, true);
    will_return(__wrap_wdb_global_restore_backup, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_backup);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_backup_time);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_int_equal(result, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_global_restore_backup_success_pre_restore_false(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global backup restore {\"snapshot\":\"global.db-backup-TIMESTAMP\",\"save_pre_restore_state\":false}", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: backup restore {\"snapshot\":\"global.db-backup-TIMESTAMP\",\"save_pre_restore_state\":false}");

    expect_string(__wrap_wdb_global_restore_backup, snapshot, "global.db-backup-TIMESTAMP");
    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_backup);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_backup_time);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_int_equal(result, OS_SUCCESS);

    os_free(query);
}

void test_wdb_parse_global_restore_backup_success_pre_restore_missing(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global backup restore {\"snapshot\":\"global.db-backup-TIMESTAMP\"}", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: backup restore {\"snapshot\":\"global.db-backup-TIMESTAMP\"}");

    expect_string(__wrap_wdb_global_restore_backup, snapshot, "global.db-backup-TIMESTAMP");
    expect_value(__wrap_wdb_global_restore_backup, save_pre_restore_state, false);
    will_return(__wrap_wdb_global_restore_backup, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_backup);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_backup_time);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_int_equal(result, OS_SUCCESS);

    os_free(query);
}

/* wdb_parse_global_vacuum */

void test_wdb_parse_global_vacuum_commit_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global vacuum", query);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    expect_function_call(__wrap_w_inc_global_vacuum);
    will_return(__wrap_gettimeofday, NULL);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: vacuum");
    will_return(__wrap_wdb_commit2, OS_INVALID);

    expect_function_call(__wrap_wdb_finalize_all_statements);

    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot end transaction.");

    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_vacuum_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot end transaction");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_vacuum_vacuum_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global vacuum", query);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    expect_function_call(__wrap_w_inc_global_vacuum);
    will_return(__wrap_gettimeofday, NULL);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: vacuum");
    will_return(__wrap_wdb_commit2, OS_SUCCESS);

    expect_function_call(__wrap_wdb_finalize_all_statements);

    will_return(__wrap_wdb_vacuum, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot vacuum database.");

    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_vacuum_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot vacuum database");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_vacuum_success_get_db_state_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global vacuum", query);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    expect_function_call(__wrap_w_inc_global_vacuum);
    will_return(__wrap_gettimeofday, NULL);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: vacuum");
    will_return(__wrap_wdb_commit2, OS_SUCCESS);

    expect_function_call(__wrap_wdb_finalize_all_statements);

    will_return(__wrap_wdb_vacuum, OS_SUCCESS);

    will_return(__wrap_wdb_get_db_state, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Couldn't get fragmentation after vacuum for the database.");

    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_vacuum_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Vacuum performed, but couldn't get fragmentation information after vacuum");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_vacuum_success_update_vacuum_data_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global vacuum", query);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    expect_function_call(__wrap_w_inc_global_vacuum);
    will_return(__wrap_gettimeofday, NULL);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: vacuum");
    will_return(__wrap_wdb_commit2, OS_SUCCESS);

    expect_function_call(__wrap_wdb_finalize_all_statements);

    will_return(__wrap_wdb_vacuum, OS_SUCCESS);

    will_return(__wrap_wdb_get_db_state, 10);

    expect_string(__wrap_wdb_update_last_vacuum_data, last_vacuum_value, "10");
    will_return(__wrap_wdb_update_last_vacuum_data, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Couldn't update last vacuum info for the database.");

    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_vacuum_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Vacuum performed, but last vacuum information couldn't be updated in the metadata table");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_vacuum_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global vacuum", query);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    expect_function_call(__wrap_w_inc_global_vacuum);
    will_return(__wrap_gettimeofday, NULL);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: vacuum");
    will_return(__wrap_wdb_commit2, OS_SUCCESS);

    expect_function_call(__wrap_wdb_finalize_all_statements);

    will_return(__wrap_wdb_vacuum, OS_SUCCESS);

    will_return(__wrap_wdb_get_db_state, 10);

    expect_string(__wrap_wdb_update_last_vacuum_data, last_vacuum_value, "10");
    will_return(__wrap_wdb_update_last_vacuum_data, OS_SUCCESS);

    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_vacuum_time);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"fragmentation_after_vacuum\":10}");
    assert_int_equal(result, OS_SUCCESS);

    os_free(query);
}

/* wdb_parse_global_get_fragmentation */

void test_wdb_parse_global_get_fragmentation_db_state_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global get_fragmentation", query);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    expect_function_call(__wrap_w_inc_global_get_fragmentation);
    will_return(__wrap_gettimeofday, NULL);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get_fragmentation");

    will_return(__wrap_wdb_get_db_state, OS_INVALID);
    will_return(__wrap_wdb_get_db_free_pages_percentage, 10);

    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot get database fragmentation.");

    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_get_fragmentation_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot get database fragmentation");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_get_fragmentation_free_pages_error(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global get_fragmentation", query);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    expect_function_call(__wrap_w_inc_global_get_fragmentation);
    will_return(__wrap_gettimeofday, NULL);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get_fragmentation");

    will_return(__wrap_wdb_get_db_state, 10);
    will_return(__wrap_wdb_get_db_free_pages_percentage, OS_INVALID);

    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot get database fragmentation.");

    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_get_fragmentation_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Cannot get database fragmentation");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

void test_wdb_parse_global_get_fragmentation_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    int result = OS_INVALID;
    char *query = NULL;

    os_strdup("global get_fragmentation", query);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    expect_function_call(__wrap_w_inc_global_get_fragmentation);
    will_return(__wrap_gettimeofday, NULL);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get_fragmentation");

    will_return(__wrap_wdb_get_db_state, 50);
    will_return(__wrap_wdb_get_db_free_pages_percentage, 10);

    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_get_fragmentation_time);

    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok {\"fragmentation\":50,\"free_pages_percentage\":10}");
    assert_int_equal(result, OS_SUCCESS);

    os_free(query);
}

/* Tests wdb_parse_global_get_distinct_agent_groups */

void test_wdb_parse_global_get_distinct_agent_groups_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-distinct-groups";
    cJSON *group_info = cJSON_Parse("[\"GROUP INFO\"]");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-distinct-groups");
    expect_value(__wrap_wdb_global_get_distinct_agent_groups, group_hash, NULL);
    will_return(__wrap_wdb_global_get_distinct_agent_groups, WDBC_OK);
    will_return(__wrap_wdb_global_get_distinct_agent_groups, group_info);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_distinct_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_distinct_groups_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [\"GROUP INFO\"]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_get_distinct_agent_groups_success_with_last_hash(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-distinct-groups abcdef";
    cJSON *group_info = cJSON_Parse("[\"GROUP INFO\"]");

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-distinct-groups abcdef");
    expect_string(__wrap_wdb_global_get_distinct_agent_groups, group_hash, "abcdef");
    will_return(__wrap_wdb_global_get_distinct_agent_groups, WDBC_OK);
    will_return(__wrap_wdb_global_get_distinct_agent_groups, group_info);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_distinct_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_distinct_groups_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok [\"GROUP INFO\"]");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_get_distinct_agent_groups_result_null(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-distinct-groups";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-distinct-groups");
    expect_value(__wrap_wdb_global_get_distinct_agent_groups, group_hash, NULL);
    will_return(__wrap_wdb_global_get_distinct_agent_groups, WDBC_ERROR);
    will_return(__wrap_wdb_global_get_distinct_agent_groups, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error getting agent groups from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_distinct_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_distinct_groups_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting agent groups from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_get_distinct_agent_groups_result_null_with_last_hash(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-distinct-groups abcdef";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-distinct-groups abcdef");
    expect_string(__wrap_wdb_global_get_distinct_agent_groups, group_hash, "abcdef");
    will_return(__wrap_wdb_global_get_distinct_agent_groups, WDBC_ERROR);
    will_return(__wrap_wdb_global_get_distinct_agent_groups, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error getting agent groups from global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_get_distinct_groups);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_get_distinct_groups_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error getting agent groups from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_delete_db_file (void **state) {

    int result = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = NULL;

    os_strdup("global non-query", query);
    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: non-query");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: non-query");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    //DB file deleted manually
    will_return(__wrap_w_is_file, 0);

    expect_string(__wrap__mwarn, formatted_msg, "DB(queue/db/global.db) not found. This behavior is unexpected, the database will be recreated.");
    will_return(__wrap_wdb_close, NULL);
    will_return(__wrap_wdb_close, OS_SUCCESS);
    expect_function_call(__wrap_wdb_pool_leave);

    result = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'non-query'");
    assert_int_equal(result, OS_INVALID);

    os_free(query);
}

/* Tests wdb_parse_global_recalculate_agent_group_hashes */

void test_wdb_parse_global_recalculate_agent_group_hashes_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global recalculate-agent-group-hashes";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: recalculate-agent-group-hashes");
    will_return(__wrap_wdb_global_recalculate_all_agent_groups_hash, OS_INVALID);
    expect_string(__wrap__mwarn, formatted_msg, "Error recalculating group hash of agents in global.db.");

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_recalculate_agent_group_hashes);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_recalculate_agent_group_hashes_time);

    expect_string(__wrap_w_is_file, file, "queue/db/global.db");
    will_return(__wrap_w_is_file, 1);
    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "err Error recalculating group hash of agents in global.db");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_recalculate_agent_group_hashes_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global recalculate-agent-group-hashes";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: recalculate-agent-group-hashes");
    will_return(__wrap_wdb_global_recalculate_all_agent_groups_hash, OS_SUCCESS);

    expect_function_call(__wrap_w_inc_queries_total);
    expect_function_call(__wrap_w_inc_global);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_open_time);
    expect_function_call(__wrap_w_inc_global_agent_recalculate_agent_group_hashes);
    will_return(__wrap_gettimeofday, NULL);
    will_return(__wrap_gettimeofday, NULL);
    expect_function_call(__wrap_w_inc_global_agent_recalculate_agent_group_hashes_time);

    expect_function_call(__wrap_wdb_pool_leave);

    ret = wdb_parse(query, data->output, 0);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_open_global_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_no_space, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_substr_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sql_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sql_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_actor_fail, test_setup, test_teardown),
        /* Tests wdb_parse_global_insert_agent */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_compliant_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_update_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_name_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_name_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_name_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_name_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_name_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_update_agent_data */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_data_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_data_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_data_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_data_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_data_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_labels_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_labels_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_labels_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_update_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_keepalive_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_keepalive_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_keepalive_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_keepalive_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_keepalive_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_update_connection_status */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_connection_status_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_connection_status_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_connection_status_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_connection_status_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_connection_status_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_update_status_code */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_status_code_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_status_code_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_status_code_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_status_code_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_status_code_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_delete_agent */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_agent_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_agent_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_agent_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_select_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_agent_name_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_agent_name_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_agent_name_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_select_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_agent_group_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_agent_group_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_agent_group_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_find_agent */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_agent_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_agent_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_agent_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_agent_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_agent_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_find_group */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_group_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_group_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_group_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_insert_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_group_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_group_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_group_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_select_group_belong */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_group_belong_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_group_belong_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_group_belong_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_group_agents */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_group_agents_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_group_agents_group_missing, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_group_agents_last_id_missing, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_group_agents_last_id_value_missing, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_group_agents_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_group_agents_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_delete_group */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_group_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_group_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_group_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_select_groups */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_groups_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_groups_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_sync_agent_info_get */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_get_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_get_last_id_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_get_size_limit, test_setup, test_teardown),
        /* Tests wdb_parse_global_sync_agent_info_set */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_id_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_del_label_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_set_label_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_set_agent_groups */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_groups_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_groups_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_groups_missing_field, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_groups_invalid_mode, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_groups_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_groups_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_sync_agent_groups_get */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_without_condition_field_succes, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_invalid_last_id_data_type, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_invalid_last_id_negative, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_invalid_condition_data_type, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_invalid_set_synced_data_type, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_invalid_get_hash_data_type, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_invalid_agent_registration_delta_data_type, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_invalid_agent_registration_delta_negative, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_null_response, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_groups_get_invalid_response, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_groups_integrity */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_groups_integrity_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_groups_integrity_hash_length_expected_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_groups_integrity_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_groups_integrity_success_syncreq, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_groups_integrity_success_synced, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_groups_integrity_success_hash_mismatch, test_setup, test_teardown),
        /* Tests wdb_parse_global_disconnect_agents */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_disconnect_agents_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_disconnect_agents_last_id_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_disconnect_agents_keepalive_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_disconnect_agents_sync_status_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_disconnect_agents_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_all_agents */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_all_agents_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_all_agents_argument_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_all_agents_argument2_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_all_agents_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_all_agents_context_argument2_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_all_agents_context_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_agent_info */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_agent_info_by_connection_status_and_node */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_by_connection_status_and_node_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_by_connection_status_and_node_syntax_error2, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_by_connection_status_and_node_syntax_error3, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_by_connection_status_and_node_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_by_connection_status_and_node_success, test_setup, test_teardown),
        /* Tests wdb_parse_reset_agents_connection */
        cmocka_unit_test_setup_teardown(test_wdb_parse_reset_agents_connection_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_reset_agents_connection_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_reset_agents_connection_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_agent_info */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agents_by_connection_status_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agents_by_connection_status_status_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agents_by_connection_status_last_id_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agents_by_connection_status_limit_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agents_by_connection_status_limit_succes, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agents_by_connection_status_query_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agents_by_connection_status_query_fail, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_backup */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_backup_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_backup_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_restore_backup */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_restore_backup_invalid_syntax, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_restore_backup_success_missing_snapshot, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_restore_backup_success_pre_restore_true, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_restore_backup_success_pre_restore_false, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_restore_backup_success_pre_restore_missing, test_setup, test_teardown),
        /* Tests wdb_parse_global_vacuum */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_vacuum_commit_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_vacuum_vacuum_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_vacuum_success_get_db_state_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_vacuum_success_update_vacuum_data_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_vacuum_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_fragmentation */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_fragmentation_db_state_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_fragmentation_free_pages_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_fragmentation_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_distinct_agent_groups */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_distinct_agent_groups_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_distinct_agent_groups_result_null, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_distinct_agent_groups_success_with_last_hash, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_distinct_agent_groups_result_null_with_last_hash, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_delete_db_file, test_setup, test_teardown),
        /* Tests wdb_parse_global_recalculate_agent_group_hashes */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_recalculate_agent_group_hashes_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_recalculate_agent_group_hashes_success, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
