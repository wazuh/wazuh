
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

#include "wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_global_wrappers.h"
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

void test_wdb_parse_global_sql_fail(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global sql TEST QUERY";

    will_return(__wrap_wdb_open_global, data->socket);
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

void test_wdb_parse_global_insert_agent_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global insert-agent";

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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

void test_wdb_parse_global_update_agent_name_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-name";

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-name {\"id\":1,\"name\":\"test_name\"}");
    expect_value(__wrap_wdb_global_update_agent_name, id, 1);
    expect_string(__wrap_wdb_global_update_agent_name, name, "test_name");
    will_return(__wrap_wdb_global_update_agent_name, OS_SUCCESS);

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_update_agent_version_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-version";

    will_return(__wrap_wdb_open_global, data->socket);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-version");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid DB query syntax for update-agent-version.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB query error near: update-agent-version");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid DB query syntax, near 'update-agent-version'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_version_invalid_json(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-version {INVALID_JSON}";

    will_return(__wrap_wdb_open_global, data->socket);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: update-agent-version {INVALID_JSON}");
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON syntax when updating agent version.");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB JSON error near: NVALID_JSON}");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid JSON syntax, near '{INVALID_JSON}'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_version_query_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-version {\"id\":1,\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"sync_status\":1}";

    will_return(__wrap_wdb_open_global, data->socket);
    expect_string(__wrap__mdebug2, formatted_msg, 
    "Global query: update-agent-version {\"id\":1,\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"sync_status\":1}");

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
    expect_value(__wrap_wdb_global_update_agent_version, sync_status, WDB_SYNC_REQ);

    will_return(__wrap_wdb_global_update_agent_version, OS_INVALID);

    will_return_count(__wrap_sqlite3_errmsg, "ERROR MESSAGE", -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db: ERROR MESSAGE");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Cannot execute Global database query; ERROR MESSAGE");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_version_invalid_data(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-version {\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"sync_status\":1}";

    will_return(__wrap_wdb_open_global, data->socket);
    expect_string(__wrap__mdebug2, formatted_msg, 
    "Global query: update-agent-version {\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"sync_status\":1}");

    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Invalid JSON data when updating agent version.");

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "err Invalid JSON data, near '{\"os_name\":\"test_name\",\"os_versi'");
    assert_int_equal(ret, OS_INVALID);
}

void test_wdb_parse_global_update_agent_version_success(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global update-agent-version {\"id\":1,\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"sync_status\":1}";

    will_return(__wrap_wdb_open_global, data->socket);
    expect_string(__wrap__mdebug2, formatted_msg, 
    "Global query: update-agent-version {\"id\":1,\"os_name\":\"test_name\",\"os_version\":\"test_version\",\
    \"os_major\":\"test_major\",\"os_minor\":\"test_minor\",\"os_codename\":\"test_codename\",\"os_platform\":\"test_platform\",\
    \"os_build\":\"test_build\",\"os_uname\":\"test_uname\",\"os_arch\":\"test_arch\",\"version\":\"test_version\",\"config_sum\":\
    \"test_config\",\"merged_sum\":\"test_merged\",\"manager_host\":\"test_manager\",\"node_name\":\"test_node\",\"agent_ip\":\"test_ip\",\
    \"sync_status\":1}");

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
    expect_value(__wrap_wdb_global_update_agent_version, sync_status, WDB_SYNC_REQ);
    will_return(__wrap_wdb_global_update_agent_version, OS_SUCCESS);

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, OS_SUCCESS);
}

void test_wdb_parse_global_get_agent_labels_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global get-labels";

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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
    cJSON *object = NULL;

    root = cJSON_CreateArray();
    object = cJSON_CreateObject();
    cJSON_AddNumberToObject(object, "id", 1);
    cJSON_AddStringToObject(object, "key", "test_key");
    cJSON_AddStringToObject(object, "value", "test_value");
    cJSON_AddItemToArray(root, object);

    will_return(__wrap_wdb_open_global, data->socket);
    expect_string(__wrap__mdebug2, formatted_msg, "Global query: get-labels 1");
    expect_value(__wrap_wdb_global_get_agent_labels, id, 1);
    will_return(__wrap_wdb_global_get_agent_labels, root);

    ret = wdb_parse(query, data->output);

    assert_string_equal(data->output, "ok [{\"id\":1,\"key\":\"test_key\",\"value\":\"test_value\"}]");
    assert_int_equal(ret, OS_SUCCESS);

}

void test_wdb_parse_global_set_agent_labels_syntax_error(void **state)
{
    int ret = 0;
    test_struct_t *data  = (test_struct_t *)*state;
    char query[OS_BUFFER_SIZE] = "global set-labels";

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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

    will_return(__wrap_wdb_open_global, data->socket);
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
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_compliant_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_insert_agent_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_name_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_name_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_name_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_name_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_name_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_version_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_version_invalid_json, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_version_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_version_invalid_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_update_agent_version_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_labels_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_labels_query_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_get_agent_labels_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_syntax_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_id_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_remove_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_set_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_global_set_agent_labels_success, test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
