/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * July 5, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>

#include "../wazuh_db/helpers/wdb_global_helpers.h"
#include "wazuhdb_op.h"

#include "../wrappers/posix/dirent_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/rbtree_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/libc/string_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"

extern int test_mode;
int set_payload = 0;

char test_payload[OS_MAXSTR] = { 0 };

/* redefinitons/wrapping */

time_t __wrap_time(time_t *__timer) {
    *__timer = 1;
    return 1;
}

int __wrap_wdb_create_profile(const char *path) {
    check_expected(path);

    return mock_type(int);
}

uid_t __wrap_Privsep_GetUser(const char *name) {
    check_expected(name);

    return mock_type(uid_t);
}

gid_t __wrap_Privsep_GetGroup(const char *name) {
    check_expected(name);

    return mock_type(gid_t);
}

/* test struc definition*/
typedef struct test_struct {
    char** groups_array;
    char* data_in_str;
    char groups_csv[256];
    char mode[256];
    char sync_status[256];
    char query_str[256];
    char response[256];
    int id;
    int socket;
} test_struct_t;

/* setup/teardown */

int setup_wdb_global_helpers(void **state) {
    test_mode = 1;

    return 0;
}

int setup_wdb_global_helpers_add_agent(void **state) {
    test_mode = 1;

    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);

    init_data->groups_array = NULL;
    init_data->data_in_str = NULL;
    strcpy(init_data->groups_csv,"default,Group1,Group2");
    strcpy(init_data->mode,"override");
    strcpy(init_data->sync_status,"synced");
    strcpy(init_data->response,"ok");
    init_data->id = 1;
    init_data->socket = -1;

    strcpy(init_data->query_str,"global set-agent-groups {\"mode\":\"mode_value\",\"sync_status\":\
    \"sync_status_value\",\"data\":[{\"id\":0,\"groups\":[\"default\",\"Group1\",\"Group2\"]}]}");
    os_strdup("{\"mode\":\"mode_value\",\"sync_status\":\
    \"sync_status_value\",\"data\":[{\"id\":0,\"groups\":[\"default\",\"Group1\",\"Group2\"]}]}", init_data->data_in_str);

    // spliting string
    init_data->groups_array = w_string_split(init_data->groups_csv, ",", 0);

    *state = init_data;
    return 0;
}

int teardown_wdb_global_helpers_add_agent(void **state) {
    test_mode = 0;

    test_struct_t *data  = (test_struct_t *)*state;
    free_strarray(data->groups_array);
    os_free(data);

    return 0;
}

int teardown_wdb_global_helpers(void **state) {
    test_mode = 0;
    errno = 0;
    return 0;
}

/* Tests wdb_insert_agent */

void test_wdb_insert_agent_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";
    const char *ip = "192.168.0.101";
    const char *register_ip = "any";
    const char *internal_key = "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301";
    const char *group = "default";
    int keep_date = 0;

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_insert_agent_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";
    const char *ip = "192.168.0.101";
    const char *register_ip = "any";
    const char *internal_key = "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301";
    const char *group = "default";
    int keep_date = 0;

    const char *json_str = strdup("{\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}");
    const char *query_str = "global insert-agent {\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agent1");
    expect_string(__wrap_cJSON_AddStringToObject, name, "ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "192.168.0.101");
    expect_string(__wrap_cJSON_AddStringToObject, name, "register_ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "any");
    expect_string(__wrap_cJSON_AddStringToObject, name, "internal_key");
    expect_string(__wrap_cJSON_AddStringToObject, string, "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_string(__wrap_cJSON_AddStringToObject, string, "default");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "date_add");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global insert-agent {\"id\":1,\
\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}");

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_insert_agent_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";
    const char *ip = "192.168.0.101";
    const char *register_ip = "any";
    const char *internal_key = "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301";
    const char *group = "default";
    int keep_date = 0;

    const char *json_str = strdup("{\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}");
    const char *query_str = "global insert-agent {\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agent1");
    expect_string(__wrap_cJSON_AddStringToObject, name, "ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "192.168.0.101");
    expect_string(__wrap_cJSON_AddStringToObject, name, "register_ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "any");
    expect_string(__wrap_cJSON_AddStringToObject, name, "internal_key");
    expect_string(__wrap_cJSON_AddStringToObject, string, "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_string(__wrap_cJSON_AddStringToObject, string, "default");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "date_add");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global insert-agent {\"id\":1,\
\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}");

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_insert_agent_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";
    const char *ip = "192.168.0.101";
    const char *register_ip = "any";
    const char *internal_key = "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301";
    const char *group = "default";
    int keep_date = 0;

    const char *json_str = strdup("{\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}");
    const char *query_str = "global insert-agent {\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agent1");
    expect_string(__wrap_cJSON_AddStringToObject, name, "ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "192.168.0.101");
    expect_string(__wrap_cJSON_AddStringToObject, name, "register_ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "any");
    expect_string(__wrap_cJSON_AddStringToObject, name, "internal_key");
    expect_string(__wrap_cJSON_AddStringToObject, string, "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_string(__wrap_cJSON_AddStringToObject, string, "default");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "date_add");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_insert_agent_success(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";
    const char *ip = "192.168.0.101";
    const char *register_ip = "any";
    const char *internal_key = "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301";
    const char *group = "default";
    int keep_date = 0;

    const char *json_str = strdup("{\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}");
    const char *query_str = "global insert-agent {\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agent1");
    expect_string(__wrap_cJSON_AddStringToObject, name, "ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "192.168.0.101");
    expect_string(__wrap_cJSON_AddStringToObject, name, "register_ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "any");
    expect_string(__wrap_cJSON_AddStringToObject, name, "internal_key");
    expect_string(__wrap_cJSON_AddStringToObject, string, "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_string(__wrap_cJSON_AddStringToObject, string, "default");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "date_add");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

void test_wdb_insert_agent_success_keep_date(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";
    const char *ip = "192.168.0.101";
    const char *register_ip = "any";
    const char *internal_key = "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301";
    const char *group = "default";
    int keep_date = 1;
    struct tm test_time;
    time_t date_returned = 0;

    const char *json_str = strdup("{\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1577851261}");
    const char *query_str = "global insert-agent {\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1577851261}";
    const char *response = "ok";

    // Opening destination database file
    expect_string(__wrap_wfopen, path, "queue/agents-timestamp");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    // Getting data
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "001 agent1 any 2020-01-01 01:01:01");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, OS_SUCCESS);

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    // Transforming the date 2020-01-01 01:01:01 to a number
    test_time.tm_year = 2020-1900;
    test_time.tm_mon = 1-1;
    test_time.tm_mday = 1;
    test_time.tm_hour = 1;
    test_time.tm_min = 1;
    test_time.tm_sec = 1;
    test_time.tm_isdst = -1;

    date_returned = mktime(&test_time);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agent1");
    expect_string(__wrap_cJSON_AddStringToObject, name, "ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "192.168.0.101");
    expect_string(__wrap_cJSON_AddStringToObject, name, "register_ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "any");
    expect_string(__wrap_cJSON_AddStringToObject, name, "internal_key");
    expect_string(__wrap_cJSON_AddStringToObject, string, "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_string(__wrap_cJSON_AddStringToObject, string, "default");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "date_add");
    expect_value(__wrap_cJSON_AddNumberToObject, number, date_returned);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_update_agent_name */

void test_wdb_update_agent_name_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_name(id, name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_name_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";

    const char *json_str = strdup("{\"id\":1,\"name\":\"agent1\"}");
    const char *query_str = "global update-agent-name {\"id\":1,\"name\":\"agent1\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agent1");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-name {\"id\":1,\"name\":\"agent1\"}");

    ret = wdb_update_agent_name(id, name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_name_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";

    const char *json_str = strdup("{\"id\":1,\"name\":\"agent1\"}");
    const char *query_str = "global update-agent-name {\"id\":1,\"name\":\"agent1\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agent1");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-name {\"id\":1,\"name\":\"agent1\"}");

    ret = wdb_update_agent_name(id, name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_name_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";

    const char *json_str = strdup("{\"id\":1,\"name\":\"agent1\"}");
    const char *query_str = "global update-agent-name {\"id\":1,\"name\":\"agent1\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agent1");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_update_agent_name(id, name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_name_success(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";

    const char *json_str = strdup("{\"id\":1,\"name\":\"agent1\"}");
    const char *query_str = "global update-agent-name {\"id\":1,\"name\":\"agent1\"}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agent1");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_update_agent_name(id, name, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_update_agent_data */

void test_wdb_update_agent_data_invalid_data(void **state)
{
    int ret = 0;
    agent_info_data *agent_data = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid data provided to set in global.db.");

    ret = wdb_update_agent_data(agent_data, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_data_error_json(void **state)
{
    int ret = 0;
    agent_info_data *agent_data = NULL;

    os_calloc(1, sizeof(agent_info_data), agent_data);
    os_calloc(1, sizeof(os_data), agent_data->osd);

    agent_data->id = 1;
    os_strdup("osname", agent_data->osd->os_name);
    os_strdup("osversion", agent_data->osd->os_version);
    os_strdup("osmajor", agent_data->osd->os_major);
    os_strdup("osminor", agent_data->osd->os_minor);
    os_strdup("oscodename", agent_data->osd->os_codename);
    os_strdup("osplatform", agent_data->osd->os_platform);
    os_strdup("osbuild", agent_data->osd->os_build);
    os_strdup("osuname", agent_data->osd->os_uname);
    os_strdup("osarch", agent_data->osd->os_arch);
    os_strdup("version", agent_data->version);
    os_strdup("csum", agent_data->config_sum);
    os_strdup("msum", agent_data->merged_sum);
    os_strdup("managerhost", agent_data->manager_host);
    os_strdup("nodename", agent_data->node_name);
    os_strdup("agentip", agent_data->agent_ip);
    os_strdup("\"label1\":value1\n\"label2\":value2", agent_data->labels);
    os_strdup("active", agent_data->connection_status);
    os_strdup("syncreq", agent_data->sync_status);

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_data(agent_data, NULL);

    assert_int_equal(OS_INVALID, ret);

    wdb_free_agent_info_data(agent_data);
}

void test_wdb_update_agent_data_error_socket(void **state)
{
    int ret = 0;
    agent_info_data *agent_data = NULL;

    os_calloc(1, sizeof(agent_info_data), agent_data);
    os_calloc(1, sizeof(os_data), agent_data->osd);

    agent_data->id = 1;
    os_strdup("osname", agent_data->osd->os_name);
    os_strdup("osversion", agent_data->osd->os_version);
    os_strdup("osmajor", agent_data->osd->os_major);
    os_strdup("osminor", agent_data->osd->os_minor);
    os_strdup("oscodename", agent_data->osd->os_codename);
    os_strdup("osplatform", agent_data->osd->os_platform);
    os_strdup("osbuild", agent_data->osd->os_build);
    os_strdup("osuname", agent_data->osd->os_uname);
    os_strdup("osarch", agent_data->osd->os_arch);
    os_strdup("version", agent_data->version);
    os_strdup("csum", agent_data->config_sum);
    os_strdup("msum", agent_data->merged_sum);
    os_strdup("managerhost", agent_data->manager_host);
    os_strdup("nodename", agent_data->node_name);
    os_strdup("agentip", agent_data->agent_ip);
    os_strdup("\"label1\":value1\n\"label2\":value2", agent_data->labels);
    os_strdup("active", agent_data->connection_status);
    os_strdup("syncreq", agent_data->sync_status);
    os_strdup("synced", agent_data->group_config_status);

    const char *json_str = strdup("{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\
\"group_config_status\":\"synced\"}");
    const char *query_str = "global update-agent-data {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\
\"group_config_status\":\"synced\"}";

    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "version");
    expect_string(__wrap_cJSON_AddStringToObject, name, "config_sum");
    expect_string(__wrap_cJSON_AddStringToObject, string, "csum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "merged_sum");
    expect_string(__wrap_cJSON_AddStringToObject, string, "msum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "manager_host");
    expect_string(__wrap_cJSON_AddStringToObject, string, "managerhost");
    expect_string(__wrap_cJSON_AddStringToObject, name, "node_name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "nodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "agent_ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agentip");
    expect_string(__wrap_cJSON_AddStringToObject, name, "labels");
    expect_string(__wrap_cJSON_AddStringToObject, string, "\"label1\":value1\n\"label2\":value2");
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "syncreq");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group_config_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osversion");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_major");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osmajor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_minor");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osminor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_codename");
    expect_string(__wrap_cJSON_AddStringToObject, string, "oscodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_platform");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osplatform");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_build");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osbuild");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_uname");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osuname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_arch");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osarch");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-data \
{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\
\"group_config_status\":\"synced\"}");

    ret = wdb_update_agent_data(agent_data, NULL);

    assert_int_equal(OS_INVALID, ret);

    wdb_free_agent_info_data(agent_data);
}

void test_wdb_update_agent_data_error_sql_execution(void **state)
{
    int ret = 0;
    agent_info_data *agent_data = NULL;

    os_calloc(1, sizeof(agent_info_data), agent_data);
    os_calloc(1, sizeof(os_data), agent_data->osd);

    agent_data->id = 1;
    os_strdup("osname", agent_data->osd->os_name);
    os_strdup("osversion", agent_data->osd->os_version);
    os_strdup("osmajor", agent_data->osd->os_major);
    os_strdup("osminor", agent_data->osd->os_minor);
    os_strdup("oscodename", agent_data->osd->os_codename);
    os_strdup("osplatform", agent_data->osd->os_platform);
    os_strdup("osbuild", agent_data->osd->os_build);
    os_strdup("osuname", agent_data->osd->os_uname);
    os_strdup("osarch", agent_data->osd->os_arch);
    os_strdup("version", agent_data->version);
    os_strdup("csum", agent_data->config_sum);
    os_strdup("msum", agent_data->merged_sum);
    os_strdup("managerhost", agent_data->manager_host);
    os_strdup("nodename", agent_data->node_name);
    os_strdup("agentip", agent_data->agent_ip);
    os_strdup("\"label1\":value1\n\"label2\":value2", agent_data->labels);
    os_strdup("active", agent_data->connection_status);
    os_strdup("syncreq", agent_data->sync_status);
    os_strdup("synced", agent_data->group_config_status);

    const char *json_str = strdup("{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\
\"group_config_status\":\"synced\"}");
    const char *query_str = "global update-agent-data {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\
\"group_config_status\":\"synced\"}";

    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "version");
    expect_string(__wrap_cJSON_AddStringToObject, name, "config_sum");
    expect_string(__wrap_cJSON_AddStringToObject, string, "csum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "merged_sum");
    expect_string(__wrap_cJSON_AddStringToObject, string, "msum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "manager_host");
    expect_string(__wrap_cJSON_AddStringToObject, string, "managerhost");
    expect_string(__wrap_cJSON_AddStringToObject, name, "node_name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "nodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "agent_ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agentip");
    expect_string(__wrap_cJSON_AddStringToObject, name, "labels");
    expect_string(__wrap_cJSON_AddStringToObject, string, "\"label1\":value1\n\"label2\":value2");
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "syncreq");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group_config_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osversion");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_major");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osmajor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_minor");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osminor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_codename");
    expect_string(__wrap_cJSON_AddStringToObject, string, "oscodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_platform");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osplatform");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_build");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osbuild");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_uname");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osuname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_arch");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osarch");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-data \
{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\
\"group_config_status\":\"synced\"}");

    ret = wdb_update_agent_data(agent_data, NULL);

    assert_int_equal(OS_INVALID, ret);

    wdb_free_agent_info_data(agent_data);
}

void test_wdb_update_agent_data_error_result(void **state)
{
    int ret = 0;
    agent_info_data *agent_data = NULL;

    os_calloc(1, sizeof(agent_info_data), agent_data);
    os_calloc(1, sizeof(os_data), agent_data->osd);

    agent_data->id = 1;
    os_strdup("osname", agent_data->osd->os_name);
    os_strdup("osversion", agent_data->osd->os_version);
    os_strdup("osmajor", agent_data->osd->os_major);
    os_strdup("osminor", agent_data->osd->os_minor);
    os_strdup("oscodename", agent_data->osd->os_codename);
    os_strdup("osplatform", agent_data->osd->os_platform);
    os_strdup("osbuild", agent_data->osd->os_build);
    os_strdup("osuname", agent_data->osd->os_uname);
    os_strdup("osarch", agent_data->osd->os_arch);
    os_strdup("version", agent_data->version);
    os_strdup("csum", agent_data->config_sum);
    os_strdup("msum", agent_data->merged_sum);
    os_strdup("managerhost", agent_data->manager_host);
    os_strdup("nodename", agent_data->node_name);
    os_strdup("agentip", agent_data->agent_ip);
    os_strdup("\"label1\":value1\n\"label2\":value2", agent_data->labels);
    os_strdup("active", agent_data->connection_status);
    os_strdup("syncreq", agent_data->sync_status);
    os_strdup("synced", agent_data->group_config_status);

    const char *json_str = strdup("{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\
\"group_config_status\":\"synced\"}");
    const char *query_str = "global update-agent-data {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\
\"group_config_status\":\"synced\"}";

    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "version");
    expect_string(__wrap_cJSON_AddStringToObject, name, "config_sum");
    expect_string(__wrap_cJSON_AddStringToObject, string, "csum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "merged_sum");
    expect_string(__wrap_cJSON_AddStringToObject, string, "msum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "manager_host");
    expect_string(__wrap_cJSON_AddStringToObject, string, "managerhost");
    expect_string(__wrap_cJSON_AddStringToObject, name, "node_name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "nodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "agent_ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agentip");
    expect_string(__wrap_cJSON_AddStringToObject, name, "labels");
    expect_string(__wrap_cJSON_AddStringToObject, string, "\"label1\":value1\n\"label2\":value2");
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "syncreq");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group_config_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osversion");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_major");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osmajor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_minor");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osminor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_codename");
    expect_string(__wrap_cJSON_AddStringToObject, string, "oscodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_platform");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osplatform");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_build");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osbuild");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_uname");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osuname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_arch");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osarch");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_update_agent_data(agent_data, NULL);

    assert_int_equal(OS_INVALID, ret);

    wdb_free_agent_info_data(agent_data);
}

void test_wdb_update_agent_data_success(void **state)
{
    int ret = 0;
    agent_info_data *agent_data = NULL;

    os_calloc(1, sizeof(agent_info_data), agent_data);
    os_calloc(1, sizeof(os_data), agent_data->osd);

    agent_data->id = 1;
    os_strdup("osname", agent_data->osd->os_name);
    os_strdup("osversion", agent_data->osd->os_version);
    os_strdup("osmajor", agent_data->osd->os_major);
    os_strdup("osminor", agent_data->osd->os_minor);
    os_strdup("oscodename", agent_data->osd->os_codename);
    os_strdup("osplatform", agent_data->osd->os_platform);
    os_strdup("osbuild", agent_data->osd->os_build);
    os_strdup("osuname", agent_data->osd->os_uname);
    os_strdup("osarch", agent_data->osd->os_arch);
    os_strdup("version", agent_data->version);
    os_strdup("csum", agent_data->config_sum);
    os_strdup("msum", agent_data->merged_sum);
    os_strdup("managerhost", agent_data->manager_host);
    os_strdup("nodename", agent_data->node_name);
    os_strdup("agentip", agent_data->agent_ip);
    os_strdup("\"label1\":value1\n\"label2\":value2", agent_data->labels);
    os_strdup("active", agent_data->connection_status);
    os_strdup("syncreq", agent_data->sync_status);
    os_strdup("synced", agent_data->group_config_status);

    const char *json_str = strdup("{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\
\"group_config_status\":\"synced\"}");
    const char *query_str = "global update-agent-data {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"connection_status\":\"active\",\"sync_status\":\"syncreq\",\
\"group_config_status\":\"synced\"}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "version");
    expect_string(__wrap_cJSON_AddStringToObject, name, "config_sum");
    expect_string(__wrap_cJSON_AddStringToObject, string, "csum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "merged_sum");
    expect_string(__wrap_cJSON_AddStringToObject, string, "msum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "manager_host");
    expect_string(__wrap_cJSON_AddStringToObject, string, "managerhost");
    expect_string(__wrap_cJSON_AddStringToObject, name, "node_name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "nodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "agent_ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, "agentip");
    expect_string(__wrap_cJSON_AddStringToObject, name, "labels");
    expect_string(__wrap_cJSON_AddStringToObject, string, "\"label1\":value1\n\"label2\":value2");
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "syncreq");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group_config_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_name");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osversion");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_major");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osmajor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_minor");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osminor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_codename");
    expect_string(__wrap_cJSON_AddStringToObject, string, "oscodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_platform");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osplatform");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_build");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osbuild");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_uname");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osuname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_arch");
    expect_string(__wrap_cJSON_AddStringToObject, string, "osarch");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_update_agent_data(agent_data, NULL);

    assert_int_equal(OS_SUCCESS, ret);

    wdb_free_agent_info_data(agent_data);
}

/* Tests wdb_get_agent_info */

void test_wdb_get_agent_info_error_no_json_response(void **state) {
    cJSON *root = NULL;
    int id = 1;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent's 1 information.");

    root = wdb_get_agent_info(id, NULL);

    assert_null(root);
}

void test_wdb_get_agent_info_success(void **state) {
    cJSON *root = NULL;
    int id = 1;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, (cJSON *)1);

    root = wdb_get_agent_info(id, NULL);

    assert_ptr_equal(1, root);
}

/* Tests wdb_get_agent_info_by_connection_status_and_node */

void test_wdb_get_agent_info_by_connection_status_and_node_error_no_json_response(void **state) {
    cJSON *root = NULL;
    int id = 1;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent's 1 filtered information.");

    root = wdb_get_agent_info(id, NULL);

    assert_null(root);
}

void test_wdb_get_agent_info_by_connection_status_and_node_success(void **state) {
    cJSON *root = NULL;
    int id = 1;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, (cJSON *)1);

    root = wdb_get_agent_info(id, NULL);

    assert_ptr_equal(1, root);
}

/* Tests wdb_get_agent_labels */

void test_wdb_get_agent_labels_error_no_json_response(void **state) {
    cJSON *root = NULL;
    int id = 1;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent's 1 labels.");

    root = wdb_get_agent_labels(id, NULL);

    assert_null(root);
}

void test_wdb_get_agent_labels_success(void **state) {
    cJSON *root = NULL;
    int id = 1;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, (cJSON *)1);

    root = wdb_get_agent_labels(id, NULL);

    assert_ptr_equal(1, root);
}

/* Tests wdb_update_agent_keepalive */

void test_wdb_update_agent_keepalive_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_keepalive(id, connection_status, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}");
    const char *query_str = "global update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}");

    ret = wdb_update_agent_keepalive(id, connection_status, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}");
    const char *query_str = "global update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}");

    ret = wdb_update_agent_keepalive(id, connection_status, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}");
    const char *query_str = "global update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_update_agent_keepalive(id, connection_status, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_success(void **state)
{
    int ret = 0;
    int id = 1;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}");
    const char *query_str = "global update-keepalive {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\"}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_update_agent_keepalive(id, connection_status, sync_status, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_update_agent_connection_status */

void test_wdb_update_agent_connection_status_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_connection_status(id, connection_status, sync_status, NULL, 0);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_connection_status_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}");
    const char *query_str = "global update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "status_code");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}");

    ret = wdb_update_agent_connection_status(id, connection_status, sync_status, NULL, 0);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_connection_status_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}");
    const char *query_str = "global update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "status_code");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}");

    ret = wdb_update_agent_connection_status(id, connection_status, sync_status, NULL, 0);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_connection_status_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}");
    const char *query_str = "global update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "status_code");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_update_agent_connection_status(id, connection_status, sync_status, NULL, 0);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_connection_status_success(void **state)
{
    int ret = 0;
    int id = 1;
    const char *connection_status = "active";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}");
    const char *query_str = "global update-connection-status {\"id\":1,\"connection_status\":\"active\",\"sync_status\":\"synced\",\"status_code\":0}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "connection_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "active");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "status_code");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_update_agent_connection_status(id, connection_status, sync_status, NULL, 0);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_update_agent_status_code */

void test_wdb_update_agent_status_code_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_status_code(id, 0, version, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_status_code_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"status_code\":-1,\"version\":\"Wazuh v4.5.0\",\"sync_status\":\"synced\"}");
    const char *query_str = "global update-status-code {\"id\":1,\"status_code\":-1,\"version\":\"Wazuh v4.5.0\",\"sync_status\":\"synced\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "status_code");
    expect_value(__wrap_cJSON_AddNumberToObject, number, INVALID_VERSION);
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Wazuh v4.5.0");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-status-code {\"id\":1,\"status_code\":-1,\"version\":\"Wazuh v4.5.0\",\"sync_status\":\"synced\"}");

    ret = wdb_update_agent_status_code(id, INVALID_VERSION, version, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_status_code_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"status_code\":-1,\"version\":\"Wazuh v4.5.0\",\"sync_status\":\"synced\"}");
    const char *query_str = "global update-status-code {\"id\":1,\"status_code\":-1,\"version\":\"Wazuh v4.5.0\",\"sync_status\":\"synced\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "status_code");
    expect_value(__wrap_cJSON_AddNumberToObject, number, INVALID_VERSION);
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Wazuh v4.5.0");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-status-code {\"id\":1,\"status_code\":-1,\"version\":\"Wazuh v4.5.0\",\"sync_status\":\"synced\"}");

    ret = wdb_update_agent_status_code(id, INVALID_VERSION, version, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_status_code_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"status_code\":-1,\"version\":\"Wazuh v4.5.0\",\"sync_status\":\"synced\"}");
    const char *query_str = "global update-status-code {\"id\":1,\"status_code\":-1,\"version\":\"Wazuh v4.5.0\",\"sync_status\":\"synced\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "status_code");
    expect_value(__wrap_cJSON_AddNumberToObject, number, INVALID_VERSION);
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Wazuh v4.5.0");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_update_agent_status_code(id, INVALID_VERSION, version, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_status_code_success(void **state)
{
    int ret = 0;
    int id = 1;
    const char *version = "v4.5.0";
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"status_code\":-1,\"version\":\"Wazuh v4.5.0\",\"sync_status\":\"synced\"}");
    const char *query_str = "global update-status-code {\"id\":1,\"status_code\":-1,\"version\":\"Wazuh v4.5.0\",\"sync_status\":\"synced\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "status_code");
    expect_value(__wrap_cJSON_AddNumberToObject, number, INVALID_VERSION);
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_string(__wrap_cJSON_AddStringToObject, string, "Wazuh v4.5.0");
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "synced");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_update_agent_status_code(id, INVALID_VERSION, version, sync_status, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_get_agent_name */

void test_wdb_get_agent_name_error_no_json_response(void **state) {
    int id = 1;
    char *name = NULL;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent's 1 name.");

    name = wdb_get_agent_name(id, NULL);

    assert_null(name);
}

void test_wdb_get_agent_name_success(void **state) {
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;
    int id = 1;
    char *name = NULL;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("agent1");
    __real_cJSON_AddItemToObject(row, "name", str);
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

    name = wdb_get_agent_name(id, NULL);

    assert_string_equal("agent1", name);

    __real_cJSON_Delete(root);
    os_free(name);
}

void test_wdb_get_agent_name_not_found(void **state) {
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;
    int id = 1;
    char *name = NULL;

    root = __real_cJSON_CreateArray();
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

    name = wdb_get_agent_name(id, NULL);

    assert_string_equal("", name);

    __real_cJSON_Delete(root);
    os_free(name);
}

/* Tests wdb_remove_agent */

void test_wdb_remove_agent_remove_db_error(void **state)
{
    int ret = 0;
    int id = 1;

    char *query_str = "global delete-agent 1";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    // Error on removing DB files
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_remove_agent(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_agent_error_socket(void **state)
{
    int ret = 0;
    int id = 1;

    char *query_str = "global delete-agent 1";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-agent 1");

    ret = wdb_remove_agent(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_agent_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;

    char *query_str = "global delete-agent 1";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-agent 1");

    ret = wdb_remove_agent(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_agent_error_result(void **state)
{
    int ret = 0;
    int id = 1;

    char *query_str = "global delete-agent 1";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_remove_agent(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_agent_success(void **state)
{
    int ret = 0;
    int id = 1;

    char *query_str = "global delete-agent 1";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_remove_agent(id, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_get_agent_group */

void test_wdb_get_agent_group_error_no_json_response(void **state) {
    int id = 1;
    char *name = NULL;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent's 1 group.");

    name = wdb_get_agent_group(id, NULL);

    assert_null(name);
}

void test_wdb_get_agent_group_success(void **state) {
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;
    int id = 1;
    char *name = NULL;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("default");
    __real_cJSON_AddItemToObject(row, "group", str);
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

    name = wdb_get_agent_group(id, NULL);

    assert_string_equal("default", name);

    __real_cJSON_Delete(root);
    os_free(name);
}

/* Tests wdb_find_agent */

void test_wdb_find_agent_error_invalid_parameters(void **state)
{
    int ret = 0;
    char *name = NULL;
    char *ip = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "Empty agent name or ip when trying to get agent ID.");

    ret = wdb_find_agent(name, ip, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_find_agent_error_json_input(void **state)
{
    int ret = 0;
    char *name = "agent1";
    char *ip = "any";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_find_agent(name, ip, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_find_agent_error_json_output(void **state)
{
    int ret = 0;
    const char *name_str = "agent1";
    const char *ip_str = "any";

    const char *json_str = strdup("{\"name\":\"agent1\",\"ip\":\"any\"}");

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, name_str);
    expect_string(__wrap_cJSON_AddStringToObject, name, "ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, ip_str);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    // Handling result
    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB for agent ID.");

    ret = wdb_find_agent(name_str, ip_str, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_find_agent_success(void **state)
{
    int ret = 0;
    const char *name_str = "agent1";
    const char *ip_str = "any";
    cJSON *root = NULL;
    cJSON *row = NULL;

    const char *json_str = strdup("{\"name\":\"agent1\",\"ip\":\"any\"}");

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    __real_cJSON_AddNumberToObject(row, "id", 1);
    __real_cJSON_AddItemToArray(root, row);

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_string(__wrap_cJSON_AddStringToObject, string, name_str);
    expect_string(__wrap_cJSON_AddStringToObject, name, "ip");
    expect_string(__wrap_cJSON_AddStringToObject, string, ip_str);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, __real_cJSON_GetObjectItem(root->child, "id"));

    expect_function_call(__wrap_cJSON_Delete);

    ret = wdb_find_agent(name_str, ip_str, NULL);

    assert_int_equal(1, ret);

    __real_cJSON_Delete(root);
}

/* Tests wdb_get_all_agents */

void test_wdb_get_all_agents_wdbc_query_error(void **state) {
    const char *query_str = "global get-all-agents last_id 0";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    int *array = wdb_get_all_agents(false, NULL);

    assert_null(array);
}

void test_wdb_get_all_agents_wdbc_parse_error(void **state) {
    const char *query_str = "global get-all-agents last_id 0";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    int *array = wdb_get_all_agents(false, NULL);

    assert_null(array);
}

void test_wdb_get_all_agents_success(void **state) {
    const char *query_str = "global get-all-agents last_id 0";

// Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1},{\"id\":2},{\"id\":3}]");
    cJSON* test_json = __real_cJSON_Parse(test_payload+3);
    cJSON* id1 = cJSON_CreateNumber(1);
    cJSON* id2 = cJSON_CreateNumber(2);
    cJSON* id3 = cJSON_CreateNumber(3);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, test_payload);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, test_json);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id2);
    will_return(__wrap_cJSON_GetObjectItem, id3);
    expect_function_call(__wrap_cJSON_Delete);

    int *array = wdb_get_all_agents(false, NULL);

    assert_non_null(array);
    assert_int_equal(1, array[0]);
    assert_int_equal(2, array[1]);
    assert_int_equal(3, array[2]);
    assert_int_equal(-1, array[3]);

    os_free(array);
    __real_cJSON_Delete(test_json);
    __real_cJSON_Delete(id1);
    __real_cJSON_Delete(id2);
    __real_cJSON_Delete(id3);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

/* Tests wdb_get_all_agents_rbtree */

void test_wdb_get_all_agents_rbtree_wdbc_query_error(void **state) {
    const char *query_str = "global get-all-agents last_id 0";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get agent's IDs.");

    rb_tree *tree = wdb_get_all_agents_rbtree(false, NULL);

    assert_null(tree);
}

void test_wdb_get_all_agents_rbtree_wdbc_parse_error(void **state) {
    const char *query_str = "global get-all-agents last_id 0";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get agent's IDs.");

    rb_tree *tree = wdb_get_all_agents_rbtree(false, NULL);

    assert_null(tree);
}

void test_wdb_get_all_agents_rbtree_success(void **state) {
    const char *query_str = "global get-all-agents last_id 0";

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1},{\"id\":2},{\"id\":3}]");
    cJSON* test_json = __real_cJSON_Parse(test_payload+3);
    cJSON* id1 = cJSON_CreateNumber(1);
    cJSON* id2 = cJSON_CreateNumber(2);
    cJSON* id3 = cJSON_CreateNumber(3);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, test_payload);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, test_json);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id2);
    will_return(__wrap_cJSON_GetObjectItem, id3);
    expect_function_call(__wrap_cJSON_Delete);

    rb_tree *tree = wdb_get_all_agents_rbtree(false, NULL);

    assert_non_null(tree);

    rbtree_destroy(tree);
    __real_cJSON_Delete(test_json);
    __real_cJSON_Delete(id1);
    __real_cJSON_Delete(id2);
    __real_cJSON_Delete(id3);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

/* Tests wdb_find_group */

void test_wdb_find_group_error_no_json_response(void **state) {
    int id = 0;
    char *name = "test_group";

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent group id.");

    id = wdb_find_group(name, NULL);

    assert_int_equal(OS_INVALID, id);
}

void test_wdb_find_group_success(void **state) {
    int id = 0;
    char *name = "test_group";

    cJSON *root = __real_cJSON_CreateArray();
    cJSON *row = __real_cJSON_CreateObject();
    __real_cJSON_AddNumberToObject(row, "id", 1);
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, __real_cJSON_GetObjectItem(root->child, "id"));

    expect_function_call(__wrap_cJSON_Delete);

    id = wdb_find_group(name, NULL);

    assert_int_equal(1, id);

    __real_cJSON_Delete(root);
}

/* Tests wdb_insert_group */

void test_wdb_insert_group_error_socket(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global insert-agent-group test_group";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global insert-agent-group test_group");

    ret = wdb_insert_group(name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_insert_group_error_sql_execution(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global insert-agent-group test_group";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global insert-agent-group test_group");

    ret = wdb_insert_group(name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_insert_group_error_result(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global insert-agent-group test_group";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_insert_group(name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_insert_group_success(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global insert-agent-group test_group";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_insert_group(name, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_remove_group_db */

void test_wdb_remove_group_db_generic_error_sql_execution(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group test_group";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_TIMEOUT);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-group test_group");

    ret = wdb_remove_group_db(name, NULL);
    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_group_db_error_sql_execution(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group test_group";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-group test_group");

    ret = wdb_remove_group_db(name, NULL);
    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_group_db_error_result(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group test_group";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_remove_group_db(name, NULL);
    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_group_db_success(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group test_group";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_remove_group_db(name, NULL);
    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_update_groups */

void test_wdb_update_groups_error_json(void **state) {
    int ret = 0;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to update groups.");

    ret = wdb_update_groups(SHAREDCFG_DIR, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_groups_error_max_path(void **state) {
    cJSON *root = NULL;
    cJSON *row1 = NULL;
    cJSON *row2 = NULL;
    cJSON *str1 = NULL;
    cJSON *str2 = NULL;
    char *very_long_name = NULL;

    // Generating a very long group name
    os_calloc(PATH_MAX+1, sizeof(char), very_long_name);
    for (int i = 0; i < PATH_MAX; ++i) {*(very_long_name + i) = 'A';}

    root = __real_cJSON_CreateArray();
    row1 = __real_cJSON_CreateObject();
    str1 = __real_cJSON_CreateString(very_long_name);
    __real_cJSON_AddItemToObject(row1, "name", str1);
    __real_cJSON_AddItemToArray(root, row1);
    row2 = __real_cJSON_CreateObject();
    str2 = __real_cJSON_CreateString("test_group");
    __real_cJSON_AddItemToObject(row2, "name", str2);
    __real_cJSON_AddItemToArray(root, row2);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str1);
    will_return(__wrap_cJSON_GetObjectItem, str2);

    expect_function_call(__wrap_cJSON_Delete);

    expect_string(__wrap__merror, formatted_msg, "At wdb_update_groups(): path too long.");

    // Opening directory
    will_return(__wrap_opendir, 1);
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "error");
    expect_string(__wrap__merror, formatted_msg, "Couldn't open directory 'etc/shared': error.");

    wdb_update_groups(SHAREDCFG_DIR, NULL);

    __real_cJSON_Delete(root);
    os_free(very_long_name);
}

void test_wdb_update_groups_removing_group_db(void **state) {
    int ret = 0;
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("test_group");
    __real_cJSON_AddItemToObject(row, "name", str);
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

    // Opening directory
    will_return(__wrap_opendir, 0);

    //// Call to wdb_remove_group_db
    const char *query_str = "global delete-group test_group";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Opening directory
    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, 0);

    ret = wdb_update_groups(SHAREDCFG_DIR, NULL);

    assert_int_equal(OS_SUCCESS, ret);

    __real_cJSON_Delete(root);
}

void test_wdb_update_groups_error_adding_new_groups(void **state) {
    int ret = 0;
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("test_group");
    __real_cJSON_AddItemToObject(row, "name", str);
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

    // Opening directory
    will_return(__wrap_opendir, 1);

    // Adding new groups
    will_return(__wrap_opendir, 0);
    will_return(__wrap_strerror, "error");
    expect_string(__wrap__merror, formatted_msg, "Couldn't open directory 'etc/shared': error.");

    ret = wdb_update_groups(SHAREDCFG_DIR, NULL);

    assert_int_equal(OS_INVALID, ret);

    __real_cJSON_Delete(root);
}

void test_wdb_update_groups_success(void **state) {
    int ret = 0;
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("test_group");
    __real_cJSON_AddItemToObject(row, "name", str);
    __real_cJSON_AddItemToArray(root, row);

    struct dirent *dir_ent = NULL;
    os_calloc(1, sizeof(struct dirent), dir_ent);
    strncpy(dir_ent->d_name, "test_group\0", 11);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

    // Opening directory
    will_return(__wrap_opendir, 1);

    // Adding new groups
    will_return(__wrap_opendir, 1);
    will_return(__wrap_readdir, dir_ent);
    expect_string(__wrap_IsDir, file, "etc/shared/test_group");
    will_return(__wrap_IsDir, 0);

    //// Call to wdb_find_group
    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent group id.");

    //// Call to wdb_insert_group
    const char *query_str = "global insert-agent-group test_group";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    will_return(__wrap_readdir, NULL);

    ret = wdb_update_groups(SHAREDCFG_DIR, NULL);

    assert_int_equal(OS_SUCCESS, ret);

    __real_cJSON_Delete(root);
    os_free(dir_ent);
}

/* Tests get_agent_date_added */

void test_get_agent_date_added_error_open_file(void **state) {
    time_t date_add = 0;
    int agent_id = 1;

    // Opening destination database file
    expect_string(__wrap_wfopen, path, "queue/agents-timestamp");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 0);

    date_add = get_agent_date_added(agent_id);

    assert_int_equal(0, date_add);
}

void test_get_agent_date_added_error_no_data(void **state) {
    time_t date_add = 0;
    int agent_id = 1;

    // Opening destination database file
    expect_string(__wrap_wfopen, path, "queue/agents-timestamp");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    // Getting data
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "001 agent1");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, OS_SUCCESS);

    date_add = get_agent_date_added(agent_id);

    assert_int_equal(0, date_add);
}

void test_get_agent_date_added_error_no_date(void **state) {
    time_t date_add = 0;
    int agent_id = 1;

    // Opening destination database file
    expect_string(__wrap_wfopen, path, "queue/agents-timestamp");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    // Getting data
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "001 agent1 any");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, OS_SUCCESS);

    date_add = get_agent_date_added(agent_id);

    assert_int_equal(0, date_add);
}

void test_get_agent_date_added_error_invalid_date(void **state) {
    time_t date_add = 0;
    int agent_id = 1;

    // Opening destination database file
    expect_string(__wrap_wfopen, path, "queue/agents-timestamp");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    // Getting data
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "001 agent1 any 2020:01:01 01-01-01");

    expect_string(__wrap__merror, formatted_msg, "Invalid date format in file 'queue/agents-timestamp' for agent '1'");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, OS_SUCCESS);

    date_add = get_agent_date_added(agent_id);

    assert_int_equal(0, date_add);
}

void test_get_agent_date_added_success(void **state) {
    time_t date_add = 0;
    int agent_id = 1;
    struct tm test_time;
    time_t date_returned = 0;

    // Opening destination database file
    expect_string(__wrap_wfopen, path, "queue/agents-timestamp");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, 1);

    // Getting data
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "001 agent1 any 2020-08-01 01:01:01");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, OS_SUCCESS);

    date_add = get_agent_date_added(agent_id);

    // The date_returned variable is the date 2020-01-01 01:01:01 transformed to INT
    test_time.tm_year = 2020-1900;
    test_time.tm_mon = 8-1;
    test_time.tm_mday = 1;
    test_time.tm_hour = 1;
    test_time.tm_min = 1;
    test_time.tm_sec = 1;
    test_time.tm_isdst = -1;

    date_returned = mktime(&test_time);

    assert_int_equal(date_returned, date_add);
}

/* Tests wdb_reset_agents_connection */

void test_wdb_reset_agents_connection_error_socket(void **state)
{
    int ret = 0;
    const char *sync_status = "synced";
    const char *query_str = "global reset-agents-connection synced";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global reset-agents-connection synced");

    ret = wdb_reset_agents_connection(sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_reset_agents_connection_error_sql_execution(void **state)
{
    int ret = 0;
    const char *sync_status = "synced";
    const char *query_str = "global reset-agents-connection synced";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global reset-agents-connection synced");

    ret = wdb_reset_agents_connection(sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_reset_agents_connection_error_result(void **state)
{
    int ret = 0;
    const char *sync_status = "synced";
    const char *query_str = "global reset-agents-connection synced";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_reset_agents_connection(sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_reset_agents_connection_success(void **state)
{
    int ret = 0;
    const char *sync_status = "synced";
    const char *query_str = "global reset-agents-connection synced";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_reset_agents_connection(sync_status, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_get_agents_by_connection_status */

void test_wdb_get_agents_by_connection_status_query_error(void **state)
{
    const char *query_str = "global get-agents-by-connection-status 0 active";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    int *array = wdb_get_agents_by_connection_status("active", NULL);

    assert_null(array);
}

void test_wdb_get_agents_ids_of_current_node_query_error(void **state)
{
    const char *query_str = "global get-agents-by-connection-status 0 active node01 -1";
    const char *response = "err";
    char *cluster_node_name = NULL;
    cluster_node_name = strdup("node01");

    // Calling Wazuh DB
    will_return(__wrap_get_node_name, cluster_node_name);
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    int *array = wdb_get_agents_ids_of_current_node("active", NULL, 0, -1);

    assert_null(array);
}

void test_wdb_get_agents_by_connection_status_parse_error(void **state)
{
    const char *query_str = "global get-agents-by-connection-status 0 active";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    int *array = wdb_get_agents_by_connection_status("active", NULL);

    assert_null(array);
}

void test_wdb_get_agents_ids_of_current_node_parse_error(void **state)
{
    const char *query_str = "global get-agents-by-connection-status 0 active node01 -1";
    const char *response = "err";
    char *cluster_node_name = NULL;
    cluster_node_name = strdup("node01");

    // Calling Wazuh DB
    will_return(__wrap_get_node_name, cluster_node_name);
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    int *array = wdb_get_agents_ids_of_current_node("active", NULL, 0, -1);

    assert_null(array);
}

void test_wdb_get_agents_by_connection_status_success(void **state)
{
    const char *query_str = "global get-agents-by-connection-status 0 active";

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1},{\"id\":2},{\"id\":3}]");
    cJSON* test_json = __real_cJSON_Parse(test_payload+3);
    cJSON* id1 = cJSON_CreateNumber(1);
    cJSON* id2 = cJSON_CreateNumber(2);
    cJSON* id3 = cJSON_CreateNumber(3);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, test_payload);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, test_json);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id2);
    will_return(__wrap_cJSON_GetObjectItem, id3);
    expect_function_call(__wrap_cJSON_Delete);

    int *array = wdb_get_agents_by_connection_status("active", NULL);

    assert_non_null(array);
    assert_int_equal(1, array[0]);
    assert_int_equal(2, array[1]);
    assert_int_equal(3, array[2]);
    assert_int_equal(-1, array[3]);

    os_free(array);
    __real_cJSON_Delete(test_json);
    __real_cJSON_Delete(id1);
    __real_cJSON_Delete(id2);
    __real_cJSON_Delete(id3);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

void test_wdb_get_agents_ids_of_current_node_success(void **state)
{
    const char *query_str = "global get-agents-by-connection-status 0 active node01 -1";
    char *cluster_node_name = NULL;
    cluster_node_name = strdup("node01");

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1},{\"id\":2},{\"id\":3}]");
    cJSON* test_json = __real_cJSON_Parse(test_payload+3);
    cJSON* id1 = cJSON_CreateNumber(1);
    cJSON* id2 = cJSON_CreateNumber(2);
    cJSON* id3 = cJSON_CreateNumber(3);

    // Calling Wazuh DB
    will_return(__wrap_get_node_name, cluster_node_name);
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, test_payload);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, test_json);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id2);
    will_return(__wrap_cJSON_GetObjectItem, id3);
    expect_function_call(__wrap_cJSON_Delete);

    int *array = wdb_get_agents_ids_of_current_node("active", NULL, 0, -1);

    assert_non_null(array);
    assert_int_equal(1, array[0]);
    assert_int_equal(2, array[1]);
    assert_int_equal(3, array[2]);
    assert_int_equal(-1, array[3]);

    os_free(array);
    __real_cJSON_Delete(test_json);
    __real_cJSON_Delete(id1);
    __real_cJSON_Delete(id2);
    __real_cJSON_Delete(id3);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

/* Tests wdb_disconnect_agents */

void test_wdb_disconnect_agents_wdbc_query_error(void **state) {
    const char *query_str = "global disconnect-agents 0 100 syncreq";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    int *array = wdb_disconnect_agents(100, "syncreq", NULL);

    assert_null(array);
}

void test_wdb_disconnect_agents_wdbc_parse_error(void **state) {
    const char *query_str = "global disconnect-agents 0 100 syncreq";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    int *array = wdb_disconnect_agents(100, "syncreq", NULL);

    assert_null(array);
}

void test_wdb_disconnect_agents_success(void **state) {
    const char *query_str = "global disconnect-agents 0 100 syncreq";

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1},{\"id\":2},{\"id\":3}]");
    cJSON* test_json = __real_cJSON_Parse(test_payload+3);
    cJSON* id1 = cJSON_CreateNumber(1);
    cJSON* id2 = cJSON_CreateNumber(2);
    cJSON* id3 = cJSON_CreateNumber(3);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, test_payload);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, test_json);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    will_return(__wrap_cJSON_GetObjectItem, id2);
    will_return(__wrap_cJSON_GetObjectItem, id3);
    expect_function_call(__wrap_cJSON_Delete);

    int *array = wdb_disconnect_agents(100, "syncreq", NULL);

    assert_non_null(array);
    assert_int_equal(1, array[0]);
    assert_int_equal(2, array[1]);
    assert_int_equal(3, array[2]);
    assert_int_equal(-1, array[3]);

    os_free(array);
    __real_cJSON_Delete(test_json);
    __real_cJSON_Delete(id1);
    __real_cJSON_Delete(id2);
    __real_cJSON_Delete(id3);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

/* Tests wdb_parse_chunk_to_int */

void test_wdb_parse_chunk_to_int_ok(void **state) {
    int* array = NULL;
    int last_item = 0;
    int last_len = 0;

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1}]");
    cJSON* test_json = __real_cJSON_Parse(test_payload+3);
    cJSON* id1 = cJSON_CreateNumber(1);

    // Parsing result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, test_json);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    expect_function_call(__wrap_cJSON_Delete);

    wdbc_result status = wdb_parse_chunk_to_int(test_payload, &array, "id", &last_item, &last_len);

    assert_int_equal(WDBC_OK, status);
    assert_non_null(array);
    assert_int_equal(1, array[0]);

    os_free(array);
    __real_cJSON_Delete(test_json);
    __real_cJSON_Delete(id1);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

void test_wdb_parse_chunk_to_int_due(void **state) {
    int* array = NULL;
    int last_item = 0;
    int last_len = 0;

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "due [{\"id\":1}]");
    cJSON* test_json1 = __real_cJSON_Parse(test_payload+4);
    cJSON* id1 = cJSON_CreateNumber(1);

    // Parsing result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_DUE);
    will_return(__wrap_cJSON_Parse, test_json1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    expect_function_call(__wrap_cJSON_Delete);

    wdbc_result status = wdb_parse_chunk_to_int(test_payload, &array, "id", &last_item, &last_len);
    assert_int_equal(WDBC_DUE, status);

    // Setting second payload
    strcpy(test_payload, "ok [{\"id\":2}]");
    cJSON* test_json2 = __real_cJSON_Parse(test_payload+3);
    cJSON* id2 = cJSON_CreateNumber(2);
    // Parsing result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, test_json2);
    will_return(__wrap_cJSON_GetObjectItem, id2);
    expect_function_call(__wrap_cJSON_Delete);

    status = wdb_parse_chunk_to_int(test_payload, &array, "id", &last_item, &last_len);
    assert_int_equal(WDBC_OK, status);
    assert_non_null(array);
    assert_int_equal(1, array[0]);
    assert_int_equal(2, array[1]);
    assert_int_equal(-1, array[2]);

    os_free(array);
    __real_cJSON_Delete(test_json1);
    __real_cJSON_Delete(id1);
    __real_cJSON_Delete(test_json2);
    __real_cJSON_Delete(id2);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

void test_wdb_parse_chunk_to_int_err(void **state) {
    int* array = NULL;
    int last_item = 0;
    int last_len = 0;

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1}]");

    // Parsing result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, NULL);

    wdbc_result status = wdb_parse_chunk_to_int(test_payload, &array, "id", &last_item, &last_len);

    assert_int_equal(WDBC_ERROR, status);
    assert_null(array);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

/* Tests wdb_parse_chunk_to_rbtree */

void test_wdb_parse_chunk_to_rbtree_ok(void **state) {
    rb_tree* tree = (rb_tree*)1;
    int last_item = 0;

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1}]");
    cJSON* test_json = __real_cJSON_Parse(test_payload+3);
    cJSON* id1 = cJSON_CreateNumber(1);

    // Parsing result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, test_json);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    expect_function_call(__wrap_cJSON_Delete);

    wdbc_result status = wdb_parse_chunk_to_rbtree(test_payload, &tree, "id", &last_item);

    assert_int_equal(WDBC_OK, status);

    __real_cJSON_Delete(test_json);
    __real_cJSON_Delete(id1);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

void test_wdb_parse_chunk_to_rbtree_due(void **state) {
    rb_tree* tree = (rb_tree*)1;
    int last_item = 0;

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "due [{\"id\":1}]");
    cJSON* test_json1 = __real_cJSON_Parse(test_payload+4);
    cJSON* id1 = cJSON_CreateNumber(1);

    // Parsing result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_DUE);
    will_return(__wrap_cJSON_Parse, test_json1);
    will_return(__wrap_cJSON_GetObjectItem, id1);
    expect_function_call(__wrap_cJSON_Delete);

    wdbc_result status = wdb_parse_chunk_to_rbtree(test_payload, &tree, "id", &last_item);
    assert_int_equal(WDBC_DUE, status);

    // Setting second payload
    strcpy(test_payload, "ok [{\"id\":2}]");
    cJSON* test_json2 = __real_cJSON_Parse(test_payload+3);
    cJSON* id2 = cJSON_CreateNumber(2);
    // Parsing result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, test_json2);
    will_return(__wrap_cJSON_GetObjectItem, id2);
    expect_function_call(__wrap_cJSON_Delete);

    status = wdb_parse_chunk_to_rbtree(test_payload, &tree, "id", &last_item);
    assert_int_equal(WDBC_OK, status);

    __real_cJSON_Delete(test_json1);
    __real_cJSON_Delete(id1);
    __real_cJSON_Delete(test_json2);
    __real_cJSON_Delete(id2);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

void test_wdb_parse_chunk_to_rbtree_err(void **state) {
    rb_tree* tree = (rb_tree*)1;
    int last_item = 0;

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1}]");

    // Parsing result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);
    will_return(__wrap_cJSON_Parse, NULL);

    wdbc_result status = wdb_parse_chunk_to_rbtree(test_payload, &tree, "id", &last_item);

    assert_int_equal(WDBC_ERROR, status);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

void test_wdb_parse_chunk_to_rbtree_err_no_item(void **state) {
    rb_tree* tree = (rb_tree*)1;
    int last_item = 0;

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1}]");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid item.");

    wdbc_result status = wdb_parse_chunk_to_rbtree(test_payload, &tree, NULL, &last_item);

    assert_int_equal(WDBC_ERROR, status);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

void test_wdb_parse_chunk_to_rbtree_err_no_output(void **state) {
    rb_tree* tree = NULL;
    int last_item = 0;

    // Setting the payload
    set_payload = 1;
    strcpy(test_payload, "ok [{\"id\":1}]");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid RB tree.");

    wdbc_result status = wdb_parse_chunk_to_rbtree(test_payload, &tree, "id", &last_item);

    assert_int_equal(WDBC_ERROR, status);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

void test_wdb_set_agent_groups_csv_success(void **state) {
    int res;

    test_struct_t *data = (test_struct_t*)* state;

    // filling Json Object
    will_return(__wrap_cJSON_CreateObject, 1);
    will_return(__wrap_cJSON_AddStringToObject, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "mode");
    expect_string(__wrap_cJSON_AddStringToObject, string, data->mode);
    will_return(__wrap_cJSON_AddStringToObject, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, data->sync_status);
    expect_string(__wrap_cJSON_AddArrayToObject, name, "data");
    will_return(__wrap_cJSON_AddArrayToObject, 1);
    will_return(__wrap_cJSON_CreateObject, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, data->id);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    expect_string(__wrap_cJSON_AddArrayToObject, name, "groups");
    will_return(__wrap_cJSON_AddArrayToObject, 1);

    // Json array items loop
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[0]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[1]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[2]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, data->data_in_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, data->socket);
    expect_string(__wrap_wdbc_query_ex, query, data->query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, data->response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    res = wdb_set_agent_groups_csv(data->id, data->groups_csv, data->mode, data->sync_status, &(data->socket));

    assert_int_equal(OS_SUCCESS,res);
}

void test_wdb_set_agent_groups_error_no_mode(void **state) {
    char** groups_array = NULL;
    char* mode = NULL;
    char* sync_status = NULL;
    int id = 1;
    int socket = -1;
    int res;

    // Debug message
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid params to set the agent groups 01");

    res = wdb_set_agent_groups(id, groups_array, mode, sync_status, &socket);

    assert_int_equal(OS_INVALID,res);
}

void test_wdb_set_agent_groups_socket_error(void **state) {
    int res;

    test_struct_t *data = (test_struct_t*)* state;

    // filling Json Object
    will_return(__wrap_cJSON_CreateObject, 1);
    will_return(__wrap_cJSON_AddStringToObject, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "mode");
    expect_string(__wrap_cJSON_AddStringToObject, string, data->mode);
    will_return(__wrap_cJSON_AddStringToObject, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, data->sync_status);
    expect_string(__wrap_cJSON_AddArrayToObject, name, "data");
    will_return(__wrap_cJSON_AddArrayToObject, 1);
    will_return(__wrap_cJSON_CreateObject, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, data->id);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    expect_string(__wrap_cJSON_AddArrayToObject, name, "groups");
    will_return(__wrap_cJSON_AddArrayToObject, 1);

    // Json array items loop
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[0]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[1]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[2]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, data->data_in_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, data->socket);
    expect_string(__wrap_wdbc_query_ex, query, data->query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, data->response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Debug messages
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global set-agent-groups {\"mode\":\"mode_value\",\"sync_status\":\
    \"sync_status_value\",\"data\":[{\"id\":0,\"groups\":[\"default\",\"Group1\",\"Group2\"]}]}");

    res = wdb_set_agent_groups(data->id, data->groups_array, data->mode, data->sync_status, &(data->socket));

    assert_int_equal(OS_INVALID,res);
}

void test_wdb_set_agent_groups_query_error(void **state) {
    int res;

    test_struct_t *data = (test_struct_t*)* state;

    // filling Json Object
    will_return(__wrap_cJSON_CreateObject, 1);
    will_return(__wrap_cJSON_AddStringToObject, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "mode");
    expect_string(__wrap_cJSON_AddStringToObject, string, data->mode);
    will_return(__wrap_cJSON_AddStringToObject, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, data->sync_status);
    expect_string(__wrap_cJSON_AddArrayToObject, name, "data");
    will_return(__wrap_cJSON_AddArrayToObject, 1);
    will_return(__wrap_cJSON_CreateObject, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, data->id);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    expect_string(__wrap_cJSON_AddArrayToObject, name, "groups");
    will_return(__wrap_cJSON_AddArrayToObject, 1);

    // Json array items loop
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[0]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[1]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[2]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, data->data_in_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, data->socket);
    expect_string(__wrap_wdbc_query_ex, query, data->query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, data->response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    // Debug message
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    res = wdb_set_agent_groups(data->id, data->groups_array, data->mode, data->sync_status, &(data->socket));

    assert_int_equal(OS_INVALID,res);
}

void test_wdb_set_agent_groups_success(void **state) {
    int res;

    test_struct_t *data = (test_struct_t*)* state;

    // filling Json Object
    will_return(__wrap_cJSON_CreateObject, 1);
    will_return(__wrap_cJSON_AddStringToObject, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "mode");
    expect_string(__wrap_cJSON_AddStringToObject, string, data->mode);
    will_return(__wrap_cJSON_AddStringToObject, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, data->sync_status);
    expect_string(__wrap_cJSON_AddArrayToObject, name, "data");
    will_return(__wrap_cJSON_AddArrayToObject, 1);
    will_return(__wrap_cJSON_CreateObject, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, data->id);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    expect_string(__wrap_cJSON_AddArrayToObject, name, "groups");
    will_return(__wrap_cJSON_AddArrayToObject, 1);

    // Json array items loop
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[0]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[1]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);
    expect_string(__wrap_cJSON_CreateString, string, data->groups_array[2]);
    will_return(__wrap_cJSON_CreateString, 1);
    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, data->data_in_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, data->socket);
    expect_string(__wrap_wdbc_query_ex, query, data->query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, data->response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    res = wdb_set_agent_groups(data->id, data->groups_array, data->mode, data->sync_status, &(data->socket));

    assert_int_equal(OS_SUCCESS,res);
}

/* Tests wdb_get_distinct_agent_groups */

void test_wdb_get_distinct_agent_groups_error_no_json_response(void **state) {
    cJSON *root = NULL;
    const char *query_str = "global get-distinct-groups ";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateArray, NULL);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get agent's groups.");

    expect_function_call(__wrap_cJSON_Delete);

    root = wdb_get_distinct_agent_groups(NULL);

    assert_null(root);
}

void test_wdb_get_distinct_agent_groups_error_parse_chunk(void **state) {
    cJSON *root = NULL;
    const char *query_str = "global get-distinct-groups ";
    const char *response = "ok []";

    will_return(__wrap_cJSON_CreateArray, NULL);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid JSON array.");

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get agent's groups.");

    expect_function_call(__wrap_cJSON_Delete);

    root = wdb_get_distinct_agent_groups(NULL);

    assert_null(root);
}

void test_wdb_get_distinct_agent_groups_success(void **state) {
    cJSON *root = NULL;
    const char *query_str = "global get-distinct-groups ";
    const char *response = "ok [{\"group\":\"group3,group4\",\"group_hash\":\"abcdef\"}]";
    cJSON *str_obj = __real_cJSON_CreateString("abcdef");
    cJSON *parse_json = __real_cJSON_Parse("[{\"group\":\"group3,group4\",\"group_hash\":\"abcdef\"}]");

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    expect_string(__wrap_wdbc_parse_result, result, response);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    will_return(__wrap_cJSON_Parse, parse_json);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    will_return(__wrap_cJSON_GetObjectItem, str_obj);

    root = wdb_get_distinct_agent_groups(NULL);

    __real_cJSON_Delete(root);
    __real_cJSON_Delete(parse_json);
    __real_cJSON_Delete(str_obj);
}

void test_wdb_get_distinct_agent_groups_success_due_ok(void **state) {
    cJSON *root = NULL;
    const char *query_str1 = "global get-distinct-groups ";
    const char *query_str2 = "global get-distinct-groups ef48b4cd";
    const char *response1 = "ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]";
    const char *response2 = "ok [{\"group\":\"group3,group4\",\"group_hash\":\"abcdef\"}]";
    cJSON *str_obj1 = __real_cJSON_CreateString("ef48b4cd");
    cJSON *str_obj2 = __real_cJSON_CreateString("abcdef");
    cJSON *parse_json1 = __real_cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");
    cJSON *parse_json2 = __real_cJSON_Parse("[{\"group\":\"group3,group4\",\"group_hash\":\"abcdef\"}]");

    will_return(__wrap_cJSON_CreateArray, __real_cJSON_CreateArray());

    // Calling Wazuh DB 1
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str1);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response1);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    expect_string(__wrap_wdbc_parse_result, result, response1);
    will_return(__wrap_wdbc_parse_result, WDBC_DUE);

    will_return(__wrap_cJSON_Parse, parse_json1);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    will_return(__wrap_cJSON_GetObjectItem, str_obj1);

    // Calling Wazuh DB 2
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str2);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response2);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    expect_string(__wrap_wdbc_parse_result, result, response2);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    will_return(__wrap_cJSON_Parse, parse_json2);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    will_return(__wrap_cJSON_GetObjectItem, str_obj2);

    root = wdb_get_distinct_agent_groups(NULL);

    __real_cJSON_Delete(root);
    __real_cJSON_Delete(parse_json1);
    __real_cJSON_Delete(str_obj1);
    __real_cJSON_Delete(parse_json2);
    __real_cJSON_Delete(str_obj2);
}

/* Tests wdb_parse_chunk_to_json_by_string_item */

void test_wdb_parse_chunk_to_json_by_string_item_output_json_null(void **state) {
    char *input = "ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]";
    char *last_item_value;
    wdbc_result result;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid JSON array.");

    result = wdb_parse_chunk_to_json_by_string_item(input, NULL, "group_hash", &last_item_value);

    assert_int_equal(result, WDBC_ERROR);
}

void test_wdb_parse_chunk_to_json_by_string_item_item_null(void **state) {
    char *input = "ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]";
    cJSON *output_json = __real_cJSON_CreateArray();
    char *last_item_value;
    wdbc_result result;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid item.");

    result = wdb_parse_chunk_to_json_by_string_item(input, &output_json, NULL, &last_item_value);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(output_json);
}

void test_wdb_parse_chunk_to_json_by_string_item_output_json_no_array(void **state) {
    char *input = "ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]";
    cJSON *output_json = __real_cJSON_CreateString("wrong object");
    char *last_item_value;
    wdbc_result result;

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid JSON array.");

    result = wdb_parse_chunk_to_json_by_string_item(input, &output_json, "group_hash", &last_item_value);

    assert_int_equal(result, WDBC_ERROR);
    __real_cJSON_Delete(output_json);
}

void test_wdb_parse_chunk_to_json_by_string_item_parse_result_error(void **state) {
    char *input = NULL;
    os_strdup("ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]", input);
    cJSON *output_json = __real_cJSON_CreateArray();
    char *last_item_value;
    wdbc_result exc_result;

    expect_string(__wrap_wdbc_parse_result, result, input);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);

    exc_result = wdb_parse_chunk_to_json_by_string_item(input, &output_json, "group_hash", &last_item_value);

    assert_int_equal(exc_result, WDBC_ERROR);
    __real_cJSON_Delete(output_json);
    os_free(input);
}

void test_wdb_parse_chunk_to_json_by_string_item_cjson_parse_error(void **state) {
    char *input = NULL;
    os_strdup("ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]", input);
    cJSON *output_json = __real_cJSON_CreateArray();
    char *last_item_value;
    wdbc_result exc_result;

    expect_string(__wrap_wdbc_parse_result, result, input);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    will_return(__wrap_cJSON_Parse, NULL);

    exc_result = wdb_parse_chunk_to_json_by_string_item(input, &output_json, "group_hash", &last_item_value);

    assert_int_equal(exc_result, WDBC_ERROR);
    __real_cJSON_Delete(output_json);
    os_free(input);
}

void test_wdb_parse_chunk_to_json_by_string_item_empty_array(void **state) {
    char *input = NULL;
    os_strdup("ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]", input);
    cJSON *output_json = __real_cJSON_CreateArray();
    cJSON *parse_json = __real_cJSON_CreateArray();
    char *last_item_value;
    wdbc_result exc_result;

    expect_string(__wrap_wdbc_parse_result, result, input);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    will_return(__wrap_cJSON_Parse, parse_json);

    expect_function_call(__wrap_cJSON_Delete);

    exc_result = wdb_parse_chunk_to_json_by_string_item(input, &output_json, "group_hash", &last_item_value);

    assert_int_equal(exc_result, WDBC_OK);
    __real_cJSON_Delete(output_json);
    __real_cJSON_Delete(parse_json);
    os_free(input);
}

void test_wdb_parse_chunk_to_json_by_string_item_last_item_json_null(void **state) {
    char *input = NULL;
    os_strdup("ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]", input);
    cJSON *output_json = __real_cJSON_CreateArray();
    cJSON *parse_json = __real_cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");
    char *last_item_value = NULL;
    wdbc_result exc_result;

    expect_string(__wrap_wdbc_parse_result, result, input);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    will_return(__wrap_cJSON_Parse, parse_json);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    exc_result = wdb_parse_chunk_to_json_by_string_item(input, &output_json, "group_hash", &last_item_value);

    assert_int_equal(exc_result, WDBC_OK);
    assert_null(last_item_value);
    __real_cJSON_Delete(output_json);
    __real_cJSON_Delete(parse_json);
    os_free(input);
}

void test_wdb_parse_chunk_to_json_by_string_item_string_value_fail(void **state) {
    char *input = NULL;
    os_strdup("ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]", input);
    cJSON *output_json = __real_cJSON_CreateArray();
    cJSON *parse_json = __real_cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");
    char *last_item_value = NULL;
    wdbc_result exc_result;
    cJSON *int_obj = cJSON_CreateNumber(1);

    expect_string(__wrap_wdbc_parse_result, result, input);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    will_return(__wrap_cJSON_Parse, parse_json);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    will_return(__wrap_cJSON_GetObjectItem, int_obj);

    exc_result = wdb_parse_chunk_to_json_by_string_item(input, &output_json, "group_hash", &last_item_value);

    assert_int_equal(exc_result, WDBC_OK);
    assert_null(last_item_value);
    __real_cJSON_Delete(output_json);
    __real_cJSON_Delete(parse_json);
    __real_cJSON_Delete(int_obj);
    os_free(input);
}

void test_wdb_parse_chunk_to_json_by_string_last_item_value_null(void **state) {
    char *input = NULL;
    os_strdup("ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]", input);
    cJSON *output_json = __real_cJSON_CreateArray();
    cJSON *parse_json = __real_cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");
    char *last_item_value = NULL;
    wdbc_result exc_result;
    cJSON *str_obj = __real_cJSON_CreateString("ef48b4cd");

    expect_string(__wrap_wdbc_parse_result, result, input);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    will_return(__wrap_cJSON_Parse, parse_json);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    will_return(__wrap_cJSON_GetObjectItem, str_obj);

    exc_result = wdb_parse_chunk_to_json_by_string_item(input, &output_json, "group_hash", NULL);

    assert_int_equal(exc_result, WDBC_OK);
    assert_null(last_item_value);
    __real_cJSON_Delete(output_json);
    __real_cJSON_Delete(parse_json);
    __real_cJSON_Delete(str_obj);
    os_free(input);
}

void test_wdb_parse_chunk_to_json_by_string_item_success(void **state) {
    char *input = NULL;
    os_strdup("ok [{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]", input);
    cJSON *output_json = __real_cJSON_CreateArray();
    cJSON *parse_json = __real_cJSON_Parse("[{\"group\":\"group1,group2\",\"group_hash\":\"ef48b4cd\"}]");
    char *last_item_value;
    wdbc_result exc_result;
    cJSON *str_obj = __real_cJSON_CreateString("ef48b4cd");

    expect_string(__wrap_wdbc_parse_result, result, input);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    will_return(__wrap_cJSON_Parse, parse_json);

    expect_function_call(__wrap_cJSON_AddItemToArray);
    will_return(__wrap_cJSON_AddItemToArray, true);

    will_return(__wrap_cJSON_GetObjectItem, str_obj);

    exc_result = wdb_parse_chunk_to_json_by_string_item(input, &output_json, "group_hash", &last_item_value);

    assert_int_equal(exc_result, WDBC_OK);
    assert_string_equal(last_item_value, "ef48b4cd");
    __real_cJSON_Delete(output_json);
    __real_cJSON_Delete(parse_json);
    __real_cJSON_Delete(str_obj);
    os_free(input);
    os_free(last_item_value);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
        /* Tests wdb_insert_agent */
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_error_json, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_error_socket, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_error_result, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_success_keep_date, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_update_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_json, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_socket, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_result, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_update_agent_data */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_invalid_data, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_error_json, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_error_socket, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_error_result, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_get_agent_info */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_info_error_no_json_response, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_info_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_get_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_labels_error_no_json_response, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_labels_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_update_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_json, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_socket, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_result, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_update_agent_connection_status */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_connection_status_error_json, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_connection_status_error_socket, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_connection_status_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_connection_status_error_result, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_connection_status_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_update_agent_status_code */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_status_code_error_json, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_status_code_error_socket, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_status_code_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_status_code_error_result, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_status_code_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_get_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_name_error_no_json_response, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_name_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_name_not_found, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_remove_agent */
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_remove_db_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_error_socket, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_error_result, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_get_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_group_error_no_json_response, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_group_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_find_agent */
        cmocka_unit_test_setup_teardown(test_wdb_find_agent_error_invalid_parameters, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_find_agent_error_json_input, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_find_agent_error_json_output, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_find_agent_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_get_all_agents */
        cmocka_unit_test_setup_teardown(test_wdb_get_all_agents_wdbc_query_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_all_agents_wdbc_parse_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_all_agents_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_get_all_agents_rbtree */
        cmocka_unit_test_setup_teardown(test_wdb_get_all_agents_rbtree_wdbc_query_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_all_agents_rbtree_wdbc_parse_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_all_agents_rbtree_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_find_group */
        cmocka_unit_test_setup_teardown(test_wdb_find_group_error_no_json_response, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_find_group_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_insert_group */
        cmocka_unit_test_setup_teardown(test_wdb_insert_group_error_socket, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_group_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_group_error_result, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_insert_group_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_remove_group_db */
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_db_generic_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_db_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_db_error_result, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_db_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),

        cmocka_unit_test_setup_teardown(test_wdb_remove_group_db_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_update_groups */
        cmocka_unit_test_setup_teardown(test_wdb_update_groups_error_json, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_groups_error_max_path, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_groups_removing_group_db, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_groups_error_adding_new_groups, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_update_groups_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests get_agent_date_added */
        cmocka_unit_test_setup_teardown(test_get_agent_date_added_error_open_file, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_get_agent_date_added_error_no_data, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_get_agent_date_added_error_no_date, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_get_agent_date_added_error_invalid_date, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_get_agent_date_added_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_reset_agents_connection */
        cmocka_unit_test_setup_teardown(test_wdb_reset_agents_connection_error_socket, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_reset_agents_connection_error_sql_execution, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_reset_agents_connection_error_result, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_reset_agents_connection_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_get_agents_by_connection_status */
        cmocka_unit_test_setup_teardown(test_wdb_get_agents_by_connection_status_query_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_agents_by_connection_status_parse_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_agents_by_connection_status_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_get_agents_ids_of_current_node */
        cmocka_unit_test_setup_teardown(test_wdb_get_agents_ids_of_current_node_query_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_agents_ids_of_current_node_parse_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_agents_ids_of_current_node_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_disconnect_agents */
        cmocka_unit_test_setup_teardown(test_wdb_disconnect_agents_wdbc_query_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_disconnect_agents_wdbc_parse_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_disconnect_agents_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_parse_chunk_to_int */
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_int_ok, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_int_due, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_int_err, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_parse_chunk_to_rbtree */
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_rbtree_ok, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_rbtree_due, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_rbtree_err, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_rbtree_err_no_item, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_rbtree_err_no_output, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_set_agent_groups */
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_groups_csv_success, setup_wdb_global_helpers_add_agent, teardown_wdb_global_helpers_add_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_groups_success, setup_wdb_global_helpers_add_agent, teardown_wdb_global_helpers_add_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_groups_error_no_mode, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_groups_query_error, setup_wdb_global_helpers_add_agent, teardown_wdb_global_helpers_add_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_groups_socket_error, setup_wdb_global_helpers_add_agent, teardown_wdb_global_helpers_add_agent),
        /* Tests wdb_get_distinct_agent_groups */
        cmocka_unit_test_setup_teardown(test_wdb_get_distinct_agent_groups_error_no_json_response, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_distinct_agent_groups_error_parse_chunk, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_distinct_agent_groups_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_get_distinct_agent_groups_success_due_ok, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        /* Tests wdb_parse_chunk_to_json_by_string_item */
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_json_by_string_item_output_json_null, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_json_by_string_item_item_null, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_json_by_string_item_output_json_no_array, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_json_by_string_item_parse_result_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_json_by_string_item_cjson_parse_error, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_json_by_string_item_empty_array, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_json_by_string_item_last_item_json_null, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_json_by_string_item_string_value_fail, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_json_by_string_last_item_value_null, setup_wdb_global_helpers, teardown_wdb_global_helpers),
        cmocka_unit_test_setup_teardown(test_wdb_parse_chunk_to_json_by_string_item_success, setup_wdb_global_helpers, teardown_wdb_global_helpers),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
