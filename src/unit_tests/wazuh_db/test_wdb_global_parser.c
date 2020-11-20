
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "hash_op.h"
#include "os_err.h"
#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "wazuhdb_op.h"

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("000",init_data->wdb->id);
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

void test_wdb_parse_global_open_global_fail(void **state)
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

void test_wdb_parse_global_no_space(void **state)
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

void test_wdb_parse_global_substr_fail(void **state)
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

void test_wdb_parse_global_sql_error(void **state)
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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_actor_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "error ";

    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid DB query actor: error");

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg,
    "Global query: update-agent-data {\"id\":1,\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\"}");

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

    will_return(__wrap_wdb_global_update_agent_version, OS_INVALID);

    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    ret = wdb_parse(query, data->output);

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
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg,
    "Global query: update-agent-data {\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\"}");

    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when updating agent version.");

    ret = wdb_parse(query, data->output);

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
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg,
    "Global query: update-agent-data {\"id\":1,\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"connection_status\":\"active\",\"sync_status\":\"syncreq\"}");

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
    will_return(__wrap_wdb_global_update_agent_version, OS_SUCCESS);

    expect_value(__wrap_wdb_global_del_agent_labels, id, 1);
    will_return(__wrap_wdb_global_del_agent_labels, OS_SUCCESS);

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok [{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]");
    assert_int_equal(ret, OS_SUCCESS);

}

/* Tests wdb_parse_global_set_agent_labels */

void test_wdb_parse_global_set_agent_labels_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-labels";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-labels");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for set-labels.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: set-labels");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'set-labels'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_set_agent_labels_id_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-labels ";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-labels ");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query error near: ");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near ''");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_set_agent_labels_remove_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-labels 1 key1:test_key1\nkey2:test_key2";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-labels 1 key1:test_key1\nkey2:test_key2");
    expect_value(__wrap_wdb_global_del_agent_labels, id, 1);
    will_return(__wrap_wdb_global_del_agent_labels, OS_INVALID);

    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_set_agent_labels_set_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-labels 1 key1:test_key1\nkey2:test_key2";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-labels 1 key1:test_key1\nkey2:test_key2");
    expect_value(__wrap_wdb_global_del_agent_labels, id, 1);
    will_return(__wrap_wdb_global_del_agent_labels, OS_SUCCESS);
    expect_value(__wrap_wdb_global_set_agent_label, id, 1);
    expect_string(__wrap_wdb_global_set_agent_label, key, "key1");
    expect_string(__wrap_wdb_global_set_agent_label, value, "test_key1");
    will_return(__wrap_wdb_global_set_agent_label, OS_INVALID);

    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_set_agent_labels_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-labels 1 key1:test_key1\nkey2:test_key2\nkey3test_key3\nkey4:test_key4";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-labels 1 key1:test_key1\nkey2:test_key2\nkey3test_key3\nkey4:test_key4");
    expect_value(__wrap_wdb_global_del_agent_labels, id, 1);
    will_return(__wrap_wdb_global_del_agent_labels, OS_SUCCESS);

    expect_value(__wrap_wdb_global_set_agent_label, id, 1);
    expect_string(__wrap_wdb_global_set_agent_label, key, "key1");
    expect_string(__wrap_wdb_global_set_agent_label, value, "test_key1");
    will_return(__wrap_wdb_global_set_agent_label, OS_SUCCESS);
    expect_value(__wrap_wdb_global_set_agent_label, id, 1);
    expect_string(__wrap_wdb_global_set_agent_label, key, "key2");
    expect_string(__wrap_wdb_global_set_agent_label, value, "test_key2");
    will_return(__wrap_wdb_global_set_agent_label, OS_SUCCESS);
    expect_value(__wrap_wdb_global_set_agent_label, id, 1);
    expect_string(__wrap_wdb_global_set_agent_label, key, "key4");
    expect_string(__wrap_wdb_global_set_agent_label, value, "test_key4");
    will_return(__wrap_wdb_global_set_agent_label, OS_SUCCESS);

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_set_agent_labels_success_only_remove(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-labels 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: set-labels 1");
    expect_value(__wrap_wdb_global_del_agent_labels, id, 1);
    will_return(__wrap_wdb_global_del_agent_labels, OS_SUCCESS);

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok");
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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"id\":1,\"connection_status\":null'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_connection_status_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_value(__wrap_wdb_global_update_agent_connection_status, id, 1);
    expect_string(__wrap_wdb_global_update_agent_connection_status, connection_status, "active");
    will_return(__wrap_wdb_global_update_agent_connection_status, OS_INVALID);

    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\"}");
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_connection_status_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_value(__wrap_wdb_global_update_agent_connection_status, id, 1);
    expect_string(__wrap_wdb_global_update_agent_connection_status, connection_status, "active");
    will_return(__wrap_wdb_global_update_agent_connection_status, OS_SUCCESS);

    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"syncreq\"}");

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok {\"name\":\"test_name\"}");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_delete_agent_belong */

void test_wdb_parse_global_delete_agent_belong_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-agent-belong";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-agent-belong");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for delete-agent-belong.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: delete-agent-belong");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'delete-agent-belong'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_delete_agent_belong_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-agent-belong 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-agent-belong 1");
    expect_value(__wrap_wdb_global_delete_agent_belong, id, 1);
    will_return(__wrap_wdb_global_delete_agent_belong, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Error deleting agent from belongs table in global.db.");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Error deleting agent from belongs table in global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_delete_agent_belong_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-agent-belong 1";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-agent-belong 1");
    expect_value(__wrap_wdb_global_delete_agent_belong, id, 1);
    will_return(__wrap_wdb_global_delete_agent_belong, OS_SUCCESS);

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok");
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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok {\"id\":1}");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_update_agent_group */

void test_wdb_parse_global_update_agent_group_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-group");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for update-agent-group.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: update-agent-group");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'update-agent-group'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_group_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-group {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-group {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when updating agent group.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_group_invalid_data(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-group {\"group\":null}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-group {\"group\":null}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when updating agent group.");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"group\":null}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_group_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-group {\"id\":1,\"group\":\"test_group\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-group {\"id\":1,\"group\":\"test_group\"}");
    expect_value(__wrap_wdb_global_update_agent_group, id, 1);
    expect_string(__wrap_wdb_global_update_agent_group, group, "test_group");
    will_return(__wrap_wdb_global_update_agent_group, OS_INVALID);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_group_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-group {\"id\":1,\"group\":\"test_group\"}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-group {\"id\":1,\"group\":\"test_group\"}");
    expect_value(__wrap_wdb_global_update_agent_group, id, 1);
    expect_string(__wrap_wdb_global_update_agent_group, group, "test_group");
    will_return(__wrap_wdb_global_update_agent_group, OS_SUCCESS);

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok");
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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_insert_agent_belong */

void test_wdb_parse_global_insert_agent_belong_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent-belong";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent-belong");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for insert-agent-belong.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: insert-agent-belong");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'insert-agent-belong'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_insert_agent_belong_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent-belong {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent-belong {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when inserting agent to belongs table.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_insert_agent_belong_invalid_data(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent-belong {\"id_group\":1,\"id_agent\":null}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent-belong {\"id_group\":1,\"id_agent\":null}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when inserting agent to belongs table.");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"id_group\":1,\"id_agent\":null}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_insert_agent_belong_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent-belong {\"id_group\":1,\"id_agent\":2}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent-belong {\"id_group\":1,\"id_agent\":2}");
    expect_value(__wrap_wdb_global_insert_agent_belong, id_group, 1);
    expect_value(__wrap_wdb_global_insert_agent_belong, id_agent, 2);
    will_return(__wrap_wdb_global_insert_agent_belong, OS_INVALID);
    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_insert_agent_belong_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent-belong {\"id_group\":1,\"id_agent\":2}";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: insert-agent-belong {\"id_group\":1,\"id_agent\":2}");
    expect_value(__wrap_wdb_global_insert_agent_belong, id_group, 1);
    expect_value(__wrap_wdb_global_insert_agent_belong, id_agent, 2);
    will_return(__wrap_wdb_global_insert_agent_belong, OS_SUCCESS);

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_delete_group_belong */

void test_wdb_parse_global_delete_group_belong_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-group-belong";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-group-belong");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for delete-group-belong.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: delete-group-belong");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'delete-group-belong'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_delete_group_belong_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-group-belong test_group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-group-belong test_group");
    expect_string(__wrap_wdb_global_delete_group_belong, group_name, "test_group");
    will_return(__wrap_wdb_global_delete_group_belong, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Error deleting group from belongs table in global.db.");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Error deleting group from belongs table in global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_delete_group_belong_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global delete-group-belong test_group";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: delete-group-belong test_group");
    expect_string(__wrap_wdb_global_delete_group_belong, group_name, "test_group");
    will_return(__wrap_wdb_global_delete_group_belong, OS_SUCCESS);

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok");
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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok {\"id\":1,\"id\":2}");
    assert_int_equal(ret, OS_SUCCESS);
}

/* Tests wdb_parse_global_select_agent_keepalive */

void test_wdb_parse_global_select_agent_keepalive_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-keepalive";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-keepalive");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for select-keepalive.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: select-keepalive");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'select-keepalive'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_select_agent_keepalive_syntax_error2(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-keepalive test_name";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-keepalive test_name");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query error near: test_name");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'test_name'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_select_agent_keepalive_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-keepalive test_name 0.0.0.0";

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-keepalive test_name 0.0.0.0");
    expect_string(__wrap_wdb_global_select_agent_keepalive, name, "test_name");
    expect_string(__wrap_wdb_global_select_agent_keepalive, ip, "0.0.0.0");
    will_return(__wrap_wdb_global_select_agent_keepalive, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "Error getting agent keepalive from global.db.");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Error getting agent keepalive from global.db.");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_select_agent_keepalive_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global select-keepalive test_name 0.0.0.0";
    cJSON *j_object = NULL;

    j_object = cJSON_CreateObject();
    cJSON_AddNumberToObject(j_object, "keepalive", 1000);

    will_return(__wrap_wdb_open_global, data->wdb);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: select-keepalive test_name 0.0.0.0");
    expect_string(__wrap_wdb_global_select_agent_keepalive, name, "test_name");
    expect_string(__wrap_wdb_global_select_agent_keepalive, ip, "0.0.0.0");
    will_return(__wrap_wdb_global_select_agent_keepalive, j_object);

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok {\"keepalive\":1000}");
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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok {SYNC INFO}");
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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok");
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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid arguments 'last_id' not found.");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid arguments 'last_id' not found");
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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok [{\"id\":10}]");
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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid arguments 'connection_status' not found");
    assert_int_equal(ret, OS_INVALID);
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

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok [{\"id\":10}]");
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
        /* Tests wdb_parse_global_set_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_id_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_remove_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_set_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_success_only_remove, test_setup, test_teardown),
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
        /* Tests wdb_parse_global_delete_agent_belong */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_agent_belong_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_agent_belong_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_agent_belong_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_find_agent */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_agent_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_agent_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_agent_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_agent_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_agent_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_update_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_group_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_group_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_group_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_group_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_group_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_find_group */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_group_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_group_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_find_group_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_insert_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_group_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_group_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_group_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_insert_agent_belong */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_belong_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_belong_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_belong_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_belong_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_belong_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_delete_group_belong */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_group_belong_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_group_belong_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_group_belong_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_delete_group */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_group_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_group_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_delete_group_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_select_groups */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_groups_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_groups_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_select_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_agent_keepalive_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_agent_keepalive_syntax_error2, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_agent_keepalive_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_select_agent_keepalive_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_sync_agent_info_get */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_get_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_get_last_id_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_sync_agent_info_set */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_id_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_del_label_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_set_label_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_sync_agent_info_set_success, test_setup, test_teardown),
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
        /* Tests wdb_parse_global_get_agent_info */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_info_success, test_setup, test_teardown),
        /* Tests wdb_parse_reset_agents_connection */
        cmocka_unit_test_setup_teardown(test_wdb_parse_reset_agents_connection_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_reset_agents_connection_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_reset_agents_connection_success, test_setup, test_teardown),
        /* Tests wdb_parse_global_get_agent_info */
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agents_by_connection_status_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agents_by_connection_status_status_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agents_by_connection_status_query_success, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
