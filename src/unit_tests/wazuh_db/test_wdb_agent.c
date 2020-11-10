/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "wazuh_db/wdb.h"
#include "wazuhdb_op.h"

#include "../wrappers/posix/dirent_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/libc/string_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/posix/stat_wrappers.h"

#define WDBQUERY_SIZE OS_BUFFER_SIZE
#define WDBOUTPUT_SIZE OS_MAXSTR

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

/* setup/teardown */

int setup_wdb_agent(void **state) {
    test_mode = 1;

    return 0;
}

int teardown_wdb_agent(void **state) {
    test_mode = 0;

    return 0;
}

/* Tests wdb_create_agent_db */

void test_wdb_create_agent_db_error_no_name(void **state)
{
    int ret = 0;
    int agent_id = 0;
    const char* agent_name = NULL;

    ret = wdb_create_agent_db(agent_id, agent_name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_create_agent_db_error_creating_source_profile(void **state)
{
    int ret = 0;
    int agent_id = 1;
    const char* agent_name = "agent1";

    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);
    // Creating profile
    expect_string(__wrap__mdebug1, formatted_msg, "Profile database not found, creating.");
    expect_string(__wrap_wdb_create_profile, path, "var/db/.template.db");
    will_return(__wrap_wdb_create_profile, OS_INVALID);

    ret = wdb_create_agent_db(agent_id, agent_name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_create_agent_db_error_reopening_source_profile(void **state)
{
    int ret = 0;
    int agent_id = 1;
    const char* agent_name = "agent1";

    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);
    // Creating profile
    expect_string(__wrap__mdebug1, formatted_msg, "Profile database not found, creating.");
    expect_string(__wrap_wdb_create_profile, path, "var/db/.template.db");
    will_return(__wrap_wdb_create_profile, OS_SUCCESS);
    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);
    expect_string(__wrap__merror, formatted_msg, "Couldn't open profile 'var/db/.template.db'.");

    ret = wdb_create_agent_db(agent_id, agent_name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_create_agent_db_error_opening_dest_profile(void **state)
{
    int ret = 0;
    int agent_id = 1;
    const char* agent_name = "agent1";

    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_fopen, path, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 0);
    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, OS_SUCCESS);
    expect_string(__wrap__merror, formatted_msg, "Couldn't create database 'var/db/agents/001-agent1.db'.");

    ret = wdb_create_agent_db(agent_id, agent_name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_create_agent_db_error_writing_profile(void **state)
{
    int ret = 0;
    int agent_id = 1;
    const char* agent_name = "agent1";

    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_fopen, path, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);
    will_return(__wrap_fwrite, 0);
    // Closing files
    expect_value(__wrap_fclose, _File, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return_always(__wrap_fclose, OS_SUCCESS);
    expect_string(__wrap__merror, formatted_msg, "Couldn't write/close file 'var/db/agents/001-agent1.db' completely.");

    ret = wdb_create_agent_db(agent_id, agent_name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_create_agent_db_error_getting_ids(void **state)
{
    int ret = 0;
    int agent_id = 1;
    const char* agent_name = "agent1";

    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_fopen, path, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);
    will_return(__wrap_fwrite, 10);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    // Closing files
    expect_value(__wrap_fclose, _File, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return_always(__wrap_fclose, OS_SUCCESS);
    // Getting IDs
    expect_string(__wrap_Privsep_GetUser, name, "root");
    will_return(__wrap_Privsep_GetUser, (uid_t) - 1);
    expect_string(__wrap_Privsep_GetGroup, name, "ossec");
    will_return(__wrap_Privsep_GetGroup, (gid_t) - 1);
    will_return(__wrap_strerror, "error");
    expect_string(__wrap__merror, formatted_msg, "(1203): Invalid user 'root' or group 'ossec' given: error (0)");

    ret = wdb_create_agent_db(agent_id, agent_name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_create_agent_db_error_changing_owner(void **state)
{
    int ret = 0;
    int agent_id = 1;
    const char* agent_name = "agent1";

    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_fopen, path, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);
    will_return(__wrap_fwrite, 10);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    // Closing files
    expect_value(__wrap_fclose, _File, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return_always(__wrap_fclose, OS_SUCCESS);
    // Getting IDs
    expect_string(__wrap_Privsep_GetUser, name, "root");
    will_return(__wrap_Privsep_GetUser, 0);
    expect_string(__wrap_Privsep_GetGroup, name, "ossec");
    will_return(__wrap_Privsep_GetGroup, 0);
    // Changing owner
    expect_string(__wrap_chown, __file, "var/db/agents/001-agent1.db");
    expect_value(__wrap_chown, __owner, 0);
    expect_value(__wrap_chown, __group, 0);
    will_return(__wrap_chown, OS_INVALID);
    will_return(__wrap_strerror, "error");
    expect_string(__wrap__merror, formatted_msg, "(1135): Could not chown object 'var/db/agents/001-agent1.db' due to [(0)-(error)].");

    ret = wdb_create_agent_db(agent_id, agent_name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_create_agent_db_error_changing_mode(void **state)
{
    int ret = 0;
    int agent_id = 1;
    const char* agent_name = "agent1";

    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_fopen, path, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);
    will_return(__wrap_fwrite, 10);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    // Closing files
    expect_value(__wrap_fclose, _File, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return_always(__wrap_fclose, OS_SUCCESS);
    // Getting IDs
    expect_string(__wrap_Privsep_GetUser, name, "root");
    will_return(__wrap_Privsep_GetUser, 0);
    expect_string(__wrap_Privsep_GetGroup, name, "ossec");
    will_return(__wrap_Privsep_GetGroup, 0);
    // Changing owner
    expect_string(__wrap_chown, __file, "var/db/agents/001-agent1.db");
    expect_value(__wrap_chown, __owner, 0);
    expect_value(__wrap_chown, __group, 0);
    will_return(__wrap_chown, OS_SUCCESS);
    // Changing mode
    expect_string(__wrap_chmod, path, "var/db/agents/001-agent1.db");
    will_return(__wrap_chmod, OS_INVALID);
    will_return(__wrap_strerror, "error");
    expect_string(__wrap__merror, formatted_msg, "(1127): Could not chmod object 'var/db/agents/001-agent1.db' due to [(0)-(error)].");

    ret = wdb_create_agent_db(agent_id, agent_name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_create_agent_db_success(void **state)
{
    int ret = 0;
    int agent_id = 1;
    const char* agent_name = "agent1";

    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_fopen, path, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);
    will_return(__wrap_fwrite, 10);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    // Closing files
    expect_value(__wrap_fclose, _File, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return_always(__wrap_fclose, OS_SUCCESS);
    // Getting IDs
    expect_string(__wrap_Privsep_GetUser, name, "root");
    will_return(__wrap_Privsep_GetUser, 0);
    expect_string(__wrap_Privsep_GetGroup, name, "ossec");
    will_return(__wrap_Privsep_GetGroup, 0);
    // Changing owner
    expect_string(__wrap_chown, __file, "var/db/agents/001-agent1.db");
    expect_value(__wrap_chown, __owner, 0);
    expect_value(__wrap_chown, __group, 0);
    will_return(__wrap_chown, OS_SUCCESS);
    // Changing mode
    expect_string(__wrap_chmod, path, "var/db/agents/001-agent1.db");
    will_return(__wrap_chmod, OS_SUCCESS);

    ret = wdb_create_agent_db(agent_id, agent_name);

    assert_int_equal(OS_SUCCESS, ret);
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

    // Handling result and creating agent database
    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_fopen, path, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);
    will_return(__wrap_fwrite, 10);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    // Closing files
    expect_value(__wrap_fclose, _File, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return_always(__wrap_fclose, OS_SUCCESS);
    // Getting IDs
    expect_string(__wrap_Privsep_GetUser, name, "root");
    will_return(__wrap_Privsep_GetUser, 0);
    expect_string(__wrap_Privsep_GetGroup, name, "ossec");
    will_return(__wrap_Privsep_GetGroup, 0);
    // Changing owner
    expect_string(__wrap_chown, __file, "var/db/agents/001-agent1.db");
    expect_value(__wrap_chown, __owner, 0);
    expect_value(__wrap_chown, __group, 0);
    will_return(__wrap_chown, OS_SUCCESS);
    // Changing mode
    expect_string(__wrap_chmod, path, "var/db/agents/001-agent1.db");
    will_return(__wrap_chmod, OS_SUCCESS);

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

    will_return(__wrap_isChroot, 0);

    // Opening destination database file
    expect_string(__wrap_fopen, path, "/var/ossec/queue/agents-timestamp");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

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
    test_time.tm_isdst = 0;

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

    // Handling result and creating agent database
    // Opening source database file
    expect_string(__wrap_fopen, path, "var/db/.template.db");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_fopen, path, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, "teststring");
    will_return(__wrap_fread, 10);
    will_return(__wrap_fwrite, 10);
    will_return(__wrap_fread, "");
    will_return(__wrap_fread, 0);
    // Closing files
    expect_value(__wrap_fclose, _File, 1);
    expect_value(__wrap_fclose, _File, 1);
    will_return_always(__wrap_fclose, OS_SUCCESS);
    // Getting IDs
    expect_string(__wrap_Privsep_GetUser, name, "root");
    will_return(__wrap_Privsep_GetUser, 0);
    expect_string(__wrap_Privsep_GetGroup, name, "ossec");
    will_return(__wrap_Privsep_GetGroup, 0);
    // Changing owner
    expect_string(__wrap_chown, __file, "var/db/agents/001-agent1.db");
    expect_value(__wrap_chown, __owner, 0);
    expect_value(__wrap_chown, __group, 0);
    will_return(__wrap_chown, OS_SUCCESS);
    // Changing mode
    expect_string(__wrap_chmod, path, "var/db/agents/001-agent1.db");
    will_return(__wrap_chmod, OS_SUCCESS);

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

void test_wdb_update_agent_data_error_json(void **state)
{
    int ret = 0;
    int id = 1;
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
    int id = 1;
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
    os_strdup("syncreq", agent_data->sync_status);

    const char *json_str = strdup("{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"sync_status\":\"syncreq\"}");
    const char *query_str = "global update-agent-data {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"sync_status\":\"syncreq\"}";

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
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "syncreq");
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
\"\"label1\":value1\n\"label2\":value2\",\"sync_status\":\"syncreq\"}");

    ret = wdb_update_agent_data(agent_data, NULL);

    assert_int_equal(OS_INVALID, ret);

    wdb_free_agent_info_data(agent_data);
}

void test_wdb_update_agent_data_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
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
    os_strdup("syncreq", agent_data->sync_status);

    const char *json_str = strdup("{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"sync_status\":\"syncreq\"}");
    const char *query_str = "global update-agent-data {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"sync_status\":\"syncreq\"}";

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
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "syncreq");
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
\"\"label1\":value1\n\"label2\":value2\",\"sync_status\":\"syncreq\"}");

    ret = wdb_update_agent_data(agent_data, NULL);

    assert_int_equal(OS_INVALID, ret);

    wdb_free_agent_info_data(agent_data);
}

void test_wdb_update_agent_data_error_result(void **state)
{
    int ret = 0;
    int id = 1;
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
    os_strdup("syncreq", agent_data->sync_status);

    const char *json_str = strdup("{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"sync_status\":\"syncreq\"}");
    const char *query_str = "global update-agent-data {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"sync_status\":\"syncreq\"}";

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
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "syncreq");
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
    int id = 1;
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
    os_strdup("syncreq", agent_data->sync_status);

    const char *json_str = strdup("{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"sync_status\":\"syncreq\"}");
    const char *query_str = "global update-agent-data {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"labels\":\
\"\"label1\":value1\n\"label2\":value2\",\"sync_status\":\"syncreq\"}";
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
    expect_string(__wrap_cJSON_AddStringToObject, name, "sync_status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "syncreq");
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

/* Tests wdb_set_agent_labels */

void test_wdb_set_agent_labels_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    char *labels = "key1:value1\nkey2:value2";

    char *query_str = "global set-labels 1 key1:value1\nkey2:value2";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, OS_BUFFER_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global set-labels 1 key1:value1\nkey2:value2");

    ret = wdb_set_agent_labels(id, labels, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_agent_labels_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    char *labels = "key1:value1\nkey2:value2";

    char *query_str = "global set-labels 1 key1:value1\nkey2:value2";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, OS_BUFFER_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global set-labels 1 key1:value1\nkey2:value2");

    ret = wdb_set_agent_labels(id, labels, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_agent_labels_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    char *labels = "key1:value1\nkey2:value2";

    char *query_str = "global set-labels 1 key1:value1\nkey2:value2";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, OS_BUFFER_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_ERROR);
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error reported in the result of the query");

    ret = wdb_set_agent_labels(id, labels, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_agent_labels_success(void **state)
{
    int ret = 0;
    int id = 1;
    char *labels = "key1:value1\nkey2:value2";

    char *query_str = "global set-labels 1 key1:value1\nkey2:value2";
    const char *response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, OS_BUFFER_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_set_agent_labels(id, labels, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_update_agent_keepalive */

void test_wdb_update_agent_keepalive_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    const char *sync_status = "synced";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_keepalive(id, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"sync_status\":\"synced\"}");
    const char *query_str = "global update-keepalive {\"id\":1,\"sync_status\":\"synced\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
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
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-keepalive {\"id\":1,\"sync_status\":\"synced\"}");

    ret = wdb_update_agent_keepalive(id, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"sync_status\":\"synced\"}");
    const char *query_str = "global update-keepalive {\"id\":1,\"sync_status\":\"synced\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
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
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-keepalive {\"id\":1,\"sync_status\":\"synced\"}");

    ret = wdb_update_agent_keepalive(id, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"sync_status\":\"synced\"}");
    const char *query_str = "global update-keepalive {\"id\":1,\"sync_status\":\"synced\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
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

    ret = wdb_update_agent_keepalive(id, sync_status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_success(void **state)
{
    int ret = 0;
    int id = 1;
    const char *sync_status = "synced";

    const char *json_str = strdup("{\"id\":1,\"sync_status\":\"synced\"}");
    const char *query_str = "global update-keepalive {\"id\":1,\"sync_status\":\"synced\"}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
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

    ret = wdb_update_agent_keepalive(id, sync_status, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_delete_agent_belongs */

void test_wdb_delete_agent_belongs_error_socket(void **state)
{
    int ret = 0;
    int id = 1;

    char *query_str = "global delete-agent-belong 1";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-agent-belong 1");

    ret = wdb_delete_agent_belongs(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_delete_agent_belongs_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;

    char *query_str = "global delete-agent-belong 1";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-agent-belong 1");

    ret = wdb_delete_agent_belongs(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_delete_agent_belongs_error_result(void **state)
{
    int ret = 0;
    int id = 1;

    char *query_str = "global delete-agent-belong 1";
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

    ret = wdb_delete_agent_belongs(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_delete_agent_belongs_success(void **state)
{
    int ret = 0;
    int id = 1;

    char *query_str = "global delete-agent-belong 1";
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

    ret = wdb_delete_agent_belongs(id, NULL);

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

/* Tests wdb_remove_agent_db */

void test_wdb_remove_agent_db_error_removing_db(void **state) {
    int ret = 0;
    int id = 1;
    char *name = "agent1";

    // Removing DB files
    will_return(__wrap_isChroot, 0);
    expect_string(__wrap_remove, filename, "var/db/agents/001-agent1.db");
    will_return(__wrap_remove, OS_INVALID);

    ret = wdb_remove_agent_db(id, name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_agent_db_error_removing_db_shm_wal(void **state) {
    int ret = 0;
    int id = 1;
    char *name = "agent1";

    // Removing DB files
    will_return_always(__wrap_isChroot, 0);
    expect_string(__wrap_remove, filename, "var/db/agents/001-agent1.db");
    will_return(__wrap_remove, OS_SUCCESS);

    expect_string(__wrap_remove, filename, "var/db/agents/001-agent1.db-shm");
    will_return(__wrap_remove, OS_INVALID);
    will_return(__wrap_strerror, "error");
    expect_string(__wrap__mdebug2, formatted_msg, "(1129): Could not unlink file 'var/db/agents/001-agent1.db-shm' due to [(0)-(error)].");

    expect_string(__wrap_remove, filename, "var/db/agents/001-agent1.db-wal");
    will_return(__wrap_remove, OS_INVALID);
    will_return(__wrap_strerror, "error");
    expect_string(__wrap__mdebug2, formatted_msg, "(1129): Could not unlink file 'var/db/agents/001-agent1.db-wal' due to [(0)-(error)].");

    ret = wdb_remove_agent_db(id, name);

    assert_int_equal(OS_SUCCESS, ret);
}

void test_wdb_remove_agent_db_success(void **state) {
    int ret = 0;
    int id = 1;
    char *name = "agent1";

    // Removing DB files
    will_return_always(__wrap_isChroot, 0);
    expect_string(__wrap_remove, filename, "var/db/agents/001-agent1.db");
    will_return(__wrap_remove, OS_SUCCESS);
    expect_string(__wrap_remove, filename, "var/db/agents/001-agent1.db-shm");
    will_return(__wrap_remove, OS_SUCCESS);
    expect_string(__wrap_remove, filename, "var/db/agents/001-agent1.db-wal");
    will_return(__wrap_remove, OS_SUCCESS);

    ret = wdb_remove_agent_db(id, name);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_remove_agent */

void test_wdb_remove_agent_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("agent1");
    __real_cJSON_AddItemToObject(row, "name", str);
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB in select-agent-name
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

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

    __real_cJSON_Delete(root);
}

void test_wdb_remove_agent_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("agent1");
    __real_cJSON_AddItemToObject(row, "name", str);
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB in select-agent-name
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

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

    __real_cJSON_Delete(root);
}

void test_wdb_remove_agent_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("agent1");
    __real_cJSON_AddItemToObject(row, "name", str);
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB in select-agent-name
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

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

    __real_cJSON_Delete(root);
}

void test_wdb_remove_agent_error_delete_belongs_and_name(void **state)
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

    char *query_belong_str = "global delete-agent-belong 1";
    response = "err";

    // Calling Wazuh DB in delete-agent-belong
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_belong_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-agent-belong 1");

    const char *query_name_str = "global select-agent-name 1";

    // Calling Wazuh DB in select-agent-name
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent's 1 name.");

    ret = wdb_remove_agent(id, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_agent_success(void **state)
{
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;
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

    char *query_belongs_str = "global delete-agent-belong 1";
    response = "ok";

    // Calling Wazuh DB in delete-agent-belong
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_belongs_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("agent1");
    __real_cJSON_AddItemToObject(row, "name", str);
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB in select-agent-name
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

    // Removing DB files
    will_return_always(__wrap_isChroot, 0);
    expect_string(__wrap_remove, filename, "var/db/agents/001-agent1.db");
    will_return(__wrap_remove, OS_SUCCESS);
    expect_string(__wrap_remove, filename, "var/db/agents/001-agent1.db-shm");
    will_return(__wrap_remove, OS_SUCCESS);
    expect_string(__wrap_remove, filename, "var/db/agents/001-agent1.db-wal");
    will_return(__wrap_remove, OS_SUCCESS);

    ret = wdb_remove_agent(id, NULL);

    assert_int_equal(OS_SUCCESS, ret);

    __real_cJSON_Delete(root);
}

/* Tests wdb_get_agent_keepalive */

void test_wdb_get_agent_keepalive_error_no_name_nor_ip(void **state) {
    time_t keepalive = 0;
    char *name = NULL;
    char *ip = NULL;

    expect_string(__wrap__mdebug1, formatted_msg, "Empty agent name or ip when trying to get last keepalive.");

    keepalive = wdb_get_agent_keepalive(name, ip, NULL);

    assert_int_equal(OS_INVALID, keepalive);
}

void test_wdb_get_agent_keepalive_error_no_json_response(void **state) {
    time_t keepalive = 0;
    char name[]="agent1";
    char ip[]="0.0.0.1";
    cJSON* response = NULL;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, response);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the last agent keepalive.");

    keepalive = wdb_get_agent_keepalive(name, ip, NULL);

    assert_int_equal(OS_INVALID, keepalive);
}

void test_wdb_get_agent_keepalive_error_empty_json_response(void **state) {
    time_t keepalive = 0;
    char name[]="agent1";
    char ip[]="0.0.0.1";
    cJSON* response = cJSON_Parse("[{}]");

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, response);
    expect_function_call(__wrap_cJSON_Delete);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    keepalive = wdb_get_agent_keepalive(name, ip, NULL);

    assert_int_equal(OS_SUCCESS, keepalive);

    __real_cJSON_Delete(response);
}

void test_wdb_get_agent_keepalive_success(void **state) {
    time_t keepalive = 0;
    char name[]="agent1";
    char ip[]="0.0.0.1";
    cJSON* response = cJSON_Parse("[{\"last_keepalive\":100}]");

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, response);
    expect_function_call(__wrap_cJSON_Delete);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, __real_cJSON_GetObjectItem(response->child, "last_keepalive"));

    keepalive = wdb_get_agent_keepalive(name, ip, NULL);

    assert_int_equal(100, keepalive);

    __real_cJSON_Delete(response);
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

/* Tests wdb_get_agent_status */

void test_wdb_get_agent_status_error_no_json_response(void **state) {
    int id = 1;
    int status = 0;

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent status.");

    status = wdb_get_agent_status(id, NULL);

    assert_int_equal(OS_INVALID, status);
}

void test_wdb_get_agent_status_error_json_data(void **state) {
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;
    int id = 1;
    int status = 0;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    expect_function_call(__wrap_cJSON_Delete);

    status = wdb_get_agent_status(id, NULL);

    assert_int_equal(OS_INVALID, status);

    __real_cJSON_Delete(root);
}

void test_wdb_get_agent_status_success(void **state) {
    cJSON *root = NULL;
    cJSON *row = NULL;
    cJSON *str = NULL;
    int id = 1;
    int status = 0;

    root = __real_cJSON_CreateArray();
    row = __real_cJSON_CreateObject();
    str = __real_cJSON_CreateString("empty");
    __real_cJSON_AddItemToObject(row, "status", str);
    __real_cJSON_AddItemToArray(root, row);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, str);

    expect_function_call(__wrap_cJSON_Delete);

    status = wdb_get_agent_status(id, NULL);

    assert_int_equal(WDB_AGENT_EMPTY, status);

    __real_cJSON_Delete(root);
}

/* Tests wdb_set_agent_status */

void test_wdb_set_agent_status_error_invalid_status(void **state)
{
    int ret = 0;
    int id = 1;
    int status = -1; // Invalid status

    ret = wdb_set_agent_status(id, status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_agent_status_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    int status = WDB_AGENT_EMPTY;

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_set_agent_status(id, status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_agent_status_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    int status = WDB_AGENT_EMPTY;

    const char *json_str = strdup("{\"id\":1,\"status\":\"empty\"}");
    const char *query_str = "global update-agent-status {\"id\":1,\"status\":\"empty\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "empty");

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
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-status {\"id\":1,\"status\":\"empty\"}");

    ret = wdb_set_agent_status(id, status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_agent_status_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    int status = WDB_AGENT_EMPTY;

    const char *json_str = strdup("{\"id\":1,\"status\":\"empty\"}");
    const char *query_str = "global update-agent-status {\"id\":1,\"status\":\"empty\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "empty");

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
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-status {\"id\":1,\"status\":\"empty\"}");

    ret = wdb_set_agent_status(id, status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_agent_status_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    int status = WDB_AGENT_EMPTY;

    const char *json_str = strdup("{\"id\":1,\"status\":\"empty\"}");
    const char *query_str = "global update-agent-status {\"id\":1,\"status\":\"empty\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "empty");

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

    ret = wdb_set_agent_status(id, status, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_agent_status_success_empty(void **state)
{
    int ret = 0;
    int id = 1;
    int status = WDB_AGENT_EMPTY;

    const char *json_str = strdup("{\"id\":1,\"status\":\"empty\"}");
    const char *query_str = "global update-agent-status {\"id\":1,\"status\":\"empty\"}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "empty");

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

    ret = wdb_set_agent_status(id, status, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

void test_wdb_set_agent_status_success_pending(void **state)
{
    int ret = 0;
    int id = 1;
    int status = WDB_AGENT_PENDING;

    const char *json_str = strdup("{\"id\":1,\"status\":\"pending\"}");
    const char *query_str = "global update-agent-status {\"id\":1,\"status\":\"pending\"}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "pending");

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

    ret = wdb_set_agent_status(id, status, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

void test_wdb_set_agent_status_success_updated(void **state)
{
    int ret = 0;
    int id = 1;
    int status = WDB_AGENT_UPDATED;

    const char *json_str = strdup("{\"id\":1,\"status\":\"updated\"}");
    const char *query_str = "global update-agent-status {\"id\":1,\"status\":\"updated\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, (cJSON *)1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "status");
    expect_string(__wrap_cJSON_AddStringToObject, string, "updated");

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

    ret = wdb_set_agent_status(id, status, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_get_agents_by_keepalive */

void test_wdb_get_agents_by_keepalive_wdbc_query_error(void **state) {
    const char *condition = ">";
    int keepalive = 10;

    const char *query_str = "global get-agents-by-keepalive condition > 10 last_id 0";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    int *array = wdb_get_agents_by_keepalive(condition, keepalive, false, NULL);

    assert_null(array);
}

void test_wdb_get_agents_by_keepalive_wdbc_parse_error(void **state) {
    const char *condition = ">";
    int keepalive = 10;

    const char *query_str = "global get-agents-by-keepalive condition > 10 last_id 0";
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

    int *array = wdb_get_agents_by_keepalive(condition, keepalive, false, NULL);

    assert_null(array);
}

void test_wdb_get_agents_by_keepalive_success(void **state) {
    const char *condition = ">";
    int keepalive = 10;

    const char *query_str = "global get-agents-by-keepalive condition > 10 last_id 0";

    // Setting the payload
    set_payload = 1;
    strncpy(test_payload, "ok 1,2,3", 8);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, test_payload);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    int *array = wdb_get_agents_by_keepalive(condition, keepalive, false, NULL);

    assert_int_equal(1, array[0]);
    assert_int_equal(2, array[1]);
    assert_int_equal(3, array[2]);
    assert_int_equal(-1, array[3]);

    os_free(array);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
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
    strncpy(test_payload, "ok 1,2,3", 8);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, test_payload);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    int *array = wdb_get_all_agents(false, NULL);

    assert_int_equal(1, array[0]);
    assert_int_equal(2, array[1]);
    assert_int_equal(3, array[2]);
    assert_int_equal(-1, array[3]);

    os_free(array);

    // Cleaning payload
    set_payload = 0;
    memset(test_payload, '\0', OS_MAXSTR);
}

/* Tests wdb_update_agent_group */

void test_wdb_update_agent_group_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    char *test_group = "test_group";

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_group(id, test_group, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_group_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    char *test_group = "test_group";

    const char *json_str = strdup("{\"id\":1,\"group\":\"test_group\"}");
    const char *query_str = "global update-agent-group {\"id\":1,\"group\":\"test_group\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test_group");

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
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-group {\"id\":1,\"group\":\"test_group\"}");

    ret = wdb_update_agent_group(id, test_group, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_group_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    char *test_group = "test_group";

    const char *json_str = strdup("{\"id\":1,\"group\":\"test_group\"}");
    const char *query_str = "global update-agent-group {\"id\":1,\"group\":\"test_group\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test_group");

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
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-group {\"id\":1,\"group\":\"test_group\"}");

    ret = wdb_update_agent_group(id, test_group, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_group_error_result(void **state)
{
    int ret = 0;
    int id = 1;
    char *test_group = "test_group";

    const char *json_str = strdup("{\"id\":1,\"group\":\"test_group\"}");
    const char *query_str = "global update-agent-group {\"id\":1,\"group\":\"test_group\"}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test_group");

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

    ret = wdb_update_agent_group(id, test_group, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_group_error_multi_group(void **state)
{
    int ret = 0;
    int id = 1;
    char *test_group = "test_group";

    const char *json_str = strdup("{\"id\":1,\"group\":\"test_group\"}");
    const char *query_str = "global update-agent-group {\"id\":1,\"group\":\"test_group\"}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test_group");

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

    //// wdb_update_agent_multi_group error
    query_str = "global delete-agent-belong 1";
    response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-agent-belong 1");

    ret = wdb_update_agent_group(id, test_group, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_group_success(void **state)
{
    int ret = 0;
    int id = 1;
    char *test_group = "test_group";

    const char *json_str = strdup("{\"id\":1,\"group\":\"test_group\"}");
    const char *query_str = "global update-agent-group {\"id\":1,\"group\":\"test_group\"}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_string(__wrap_cJSON_AddStringToObject, string, "test_group");

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

    //// wdb_update_agent_multi_group success
    //// wdb_delete_agent_belongs success
    query_str = "global delete-agent-belong 1";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    //// wdb_find_group error
    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent group id.");

    //// wdb_insert_group success
    query_str = "global insert-agent-group test_group";
    response = "ok";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    //// wdb_find_group success
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

    //// wdb_update_agent_belongs error
    json_str = strdup("{\"id_group\":1,\"id_agent\":1}");
    query_str = "global insert-agent-belong {\"id_group\":1,\"id_agent\":1}";
    response = "ok";

    will_return(__wrap_cJSON_CreateObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_group");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_agent");
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

    ret = wdb_update_agent_group(id, test_group, NULL);

    assert_int_equal(OS_SUCCESS, ret);

    __real_cJSON_Delete(root);
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

/* Tests wdb_update_agent_belongs */

void test_wdb_update_agent_belongs_error_json(void **state)
{
    int ret = 0;
    int id_group = 1;
    int id_agent = 2;

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_belongs(id_group, id_agent, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_belongs_error_socket(void **state)
{
    int ret = 0;
    int id_group = 1;
    int id_agent = 2;

    const char *json_str = strdup("{\"id_group\":1,\"id_agent\":2}");
    const char *query_str = "global insert-agent-belong {\"id_group\":1,\"id_agent\":2}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_group");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_agent");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 2);

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
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global insert-agent-belong {\"id_group\":1,\"id_agent\":2}");

    ret = wdb_update_agent_belongs(id_group, id_agent, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_belongs_error_sql_execution(void **state)
{
    int ret = 0;
    int id_group = 1;
    int id_agent = 2;

    const char *json_str = strdup("{\"id_group\":1,\"id_agent\":2}");
    const char *query_str = "global insert-agent-belong {\"id_group\":1,\"id_agent\":2}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_group");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_agent");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 2);

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
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global insert-agent-belong {\"id_group\":1,\"id_agent\":2}");

    ret = wdb_update_agent_belongs(id_group, id_agent, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_belongs_error_result(void **state)
{
    int ret = 0;
    int id_group = 1;
    int id_agent = 2;

    const char *json_str = strdup("{\"id_group\":1,\"id_agent\":2}");
    const char *query_str = "global insert-agent-belong {\"id_group\":1,\"id_agent\":2}";
    const char *response = "err";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_group");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_agent");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 2);

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

    ret = wdb_update_agent_belongs(id_group, id_agent, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_belongs_success(void **state)
{
    int ret = 0;
    int id_group = 1;
    int id_agent = 2;

    const char *json_str = strdup("{\"id_group\":1,\"id_agent\":2}");
    const char *query_str = "global insert-agent-belong {\"id_group\":1,\"id_agent\":2}";
    const char *response = "ok";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_group");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_agent");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 2);

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

    ret = wdb_update_agent_belongs(id_group, id_agent, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_update_agent_multi_group */

void test_wdb_update_agent_multi_group_error_deleting_agent(void **state) {
    int ret = 0;
    int id = 1;
    char *name = "test_group";

    char *query_str = "global delete-agent-belong 1";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-agent-belong 1");

    ret = wdb_update_agent_multi_group(id, name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_multi_group_error_update_belongs_single(void **state) {
    int ret = 0;
    int id = 1;
    char *name = "test_group";

    //// wdb_delete_agent_belongs success
    char *query_str = "global delete-agent-belong 1";
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

    //// wdb_find_group error

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent group id.");

    //// wdb_insert_group success
    query_str = "global insert-agent-group test_group";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    //// wdb_find_group success

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

    //// wdb_update_agent_belongs error
    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_multi_group(id, name, NULL);

    assert_int_equal(OS_INVALID, ret);

    __real_cJSON_Delete(root);
}

void test_wdb_update_agent_multi_group_error_update_belongs_multi(void **state) {
    int ret = 0;
    int id = 1;

    char *name = NULL;
    os_strdup("test_group1,test_group2", name);

    //// wdb_delete_agent_belongs success
    char *query_str = "global delete-agent-belong 1";
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

    //// wdb_find_group error
    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent group id.");

    //// wdb_insert_group success
    query_str = "global insert-agent-group test_group1";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    //// wdb_find_group success
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

    //// wdb_update_agent_belongs success
    const char *json_str = strdup("{\"id_group\":1,\"id_agent\":2}");
    query_str = "global insert-agent-belong {\"id_group\":1,\"id_agent\":2}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_group");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id_agent");
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

    //// wdb_find_group error
    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent group id.");

    //// wdb_insert_group success
    query_str = "global insert-agent-group test_group2";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    //// wdb_find_group success
    cJSON *root2 = __real_cJSON_CreateArray();
    cJSON *row2 = __real_cJSON_CreateObject();
    __real_cJSON_AddNumberToObject(row2, "id", 2);
    __real_cJSON_AddItemToArray(root2, row2);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root2);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, __real_cJSON_GetObjectItem(root2->child, "id"));

    expect_function_call(__wrap_cJSON_Delete);

    //// wdb_update_agent_belongs error
    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_multi_group(id, name, NULL);

    assert_int_equal(OS_INVALID, ret);

    os_free(name);
    __real_cJSON_Delete(root);
    __real_cJSON_Delete(root2);
}

void test_wdb_update_agent_multi_group_success(void **state) {
    int ret = 0;
    int id = 1;
    char *name = NULL;

    //// wdb_delete_agent_belongs success
    char *query_str = "global delete-agent-belong 1";
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

    ret = wdb_update_agent_multi_group(id, name, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_remove_group_from_belongs_db */

void test_wdb_remove_group_from_belongs_db_error_socket(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group-belong test_group";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-group-belong test_group");

    ret = wdb_remove_group_from_belongs_db(name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_group_from_belongs_db_error_sql_execution(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group-belong test_group";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-group-belong test_group");

    ret = wdb_remove_group_from_belongs_db(name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_group_from_belongs_db_error_result(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group-belong test_group";
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

    ret = wdb_remove_group_from_belongs_db(name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_group_from_belongs_db_success(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group-belong test_group";
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

    ret = wdb_remove_group_from_belongs_db(name, NULL);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_remove_group_db */

void test_wdb_remove_group_db_error_removing_belongs(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group-belong test_group";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-group-belong test_group");

    // Handling result
    expect_string(__wrap__merror, formatted_msg, "At wdb_remove_group_from_belongs_db(): couldn't delete 'test_group' from 'belongs' table.");

    ret = wdb_remove_group_db(name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_group_db_error_socket(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group-belong test_group";
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

    query_str = "global delete-group test_group";
    response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-group test_group");

    ret = wdb_remove_group_db(name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_group_db_error_sql_execution(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group-belong test_group";
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

    query_str = "global delete-group test_group";
    response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-group test_group");

    ret = wdb_remove_group_db(name, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_remove_group_db_error_result(void **state)
{
    int ret = 0;
    const char *name = "test_group";

    const char *query_str = "global delete-group-belong test_group";
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

    query_str = "global delete-group test_group";
    response = "err";

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

    const char *query_str = "global delete-group-belong test_group";
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

    query_str = "global delete-group test_group";

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

    ret = wdb_update_groups(DEFAULTDIR SHAREDCFG_DIR, NULL);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_groups_error_max_path(void **state) {
    int ret = 0;
    cJSON *root = NULL;
    cJSON *row1 = NULL;
    cJSON *row2 = NULL;
    cJSON *str1 = NULL;
    cJSON *str2 = NULL;
    char *very_long_name = NULL;

    // Generating a very long group name
    os_calloc(PATH_MAX+1, sizeof(char), very_long_name);
    int i = 0;
    for (i; i < PATH_MAX; ++i) {*(very_long_name + i) = 'A';};

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
    will_return(__wrap_opendir, 0);

    //// Call to wdb_remove_group_db
    const char *name = "test_group";

    const char *query_str = "global delete-group-belong test_group";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-group-belong test_group");

    // Handling result
    expect_string(__wrap__merror, formatted_msg, "At wdb_remove_group_from_belongs_db(): couldn't delete 'test_group' from 'belongs' table.");

    ret = wdb_update_groups(DEFAULTDIR SHAREDCFG_DIR, NULL);

    assert_int_equal(OS_INVALID, ret);

    __real_cJSON_Delete(root);
    os_free(very_long_name);
}

void test_wdb_update_groups_error_removing_group_db(void **state) {
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
    const char *name = "test_group";

    const char *query_str = "global delete-group-belong test_group";
    const char *response = "err";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Handling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global delete-group-belong test_group");

    // Handling result
    expect_string(__wrap__merror, formatted_msg, "At wdb_remove_group_from_belongs_db(): couldn't delete 'test_group' from 'belongs' table.");

    ret = wdb_update_groups(DEFAULTDIR SHAREDCFG_DIR, NULL);

    assert_int_equal(OS_INVALID, ret);

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
    expect_string(__wrap__merror, formatted_msg, "Couldn't open directory '/var/ossec/etc/shared': error.");

    ret = wdb_update_groups(DEFAULTDIR SHAREDCFG_DIR, NULL);

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
    strncpy(dir_ent->d_name, "test_group", 10);

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
    expect_string(__wrap_IsDir, file, "/var/ossec/etc/shared/test_group");
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

    ret = wdb_update_groups(DEFAULTDIR SHAREDCFG_DIR, NULL);

    assert_int_equal(OS_SUCCESS, ret);

    __real_cJSON_Delete(root);
    os_free(dir_ent);
}

/* Tests wdb_agent_belongs_first_time */

void test_wdb_agent_belongs_first_time_success(void **state) {
    int ret = OS_INVALID;

    //// Call to wdb_get_all_agents
    const char *query_str = "global get-all-agents last_id 0";

    // Setting the payload
    set_payload = 1;
    strncpy(test_payload, "ok 1", 8);

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, test_payload);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    //// Call to wdb_get_agent_group
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

    //// Call to wdb_update_agent_multi_group
    //// wdb_delete_agent_belongs success
    query_str = "global delete-agent-belong 1";
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

    //// wdb_find_group error
    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent group id.");

    //// wdb_insert_group success
    query_str = "global insert-agent-group default";

    // Calling Wazuh DB
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    expect_any(__wrap_wdbc_parse_result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    //// wdb_find_group success
    cJSON *root2 = __real_cJSON_CreateArray();
    cJSON *row2 = __real_cJSON_CreateObject();
    __real_cJSON_AddNumberToObject(row2, "id", 1);
    __real_cJSON_AddItemToArray(root2, row2);

    // Calling Wazuh DB
    will_return(__wrap_wdbc_query_parse_json, 0);
    will_return(__wrap_wdbc_query_parse_json, root);

    // Getting JSON data
    will_return(__wrap_cJSON_GetObjectItem, __real_cJSON_GetObjectItem(root->child, "id"));

    expect_function_call(__wrap_cJSON_Delete);

    //// wdb_update_agent_belongs error
    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_agent_belongs_first_time(NULL);

    assert_int_equal(OS_SUCCESS, ret);

    set_payload = 0;

    __real_cJSON_Delete(root);
    __real_cJSON_Delete(root2);
}

/* Tests get_agent_date_added */

void test_get_agent_date_added_error_open_file(void **state) {
    time_t date_add = 0;
    int agent_id = 1;

    will_return(__wrap_isChroot, 0);

    // Opening destination database file
    expect_string(__wrap_fopen, path, "/var/ossec/queue/agents-timestamp");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 0);

    date_add = get_agent_date_added(agent_id);

    assert_int_equal(0, date_add);
}

void test_get_agent_date_added_error_no_data(void **state) {
    time_t date_add = 0;
    int agent_id = 1;

    will_return(__wrap_isChroot, 0);

    // Opening destination database file
    expect_string(__wrap_fopen, path, "/var/ossec/queue/agents-timestamp");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

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

    will_return(__wrap_isChroot, 0);

    // Opening destination database file
    expect_string(__wrap_fopen, path, "/var/ossec/queue/agents-timestamp");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

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

    will_return(__wrap_isChroot, 0);

    // Opening destination database file
    expect_string(__wrap_fopen, path, "/var/ossec/queue/agents-timestamp");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    // Getting data
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "001 agent1 any 2020:01:01 01-01-01");

    expect_string(__wrap__merror, formatted_msg, "Invalid date format in file '/queue/agents-timestamp' for agent '1'");

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

    will_return(__wrap_isChroot, 0);

    // Opening destination database file
    expect_string(__wrap_fopen, path, "/var/ossec/queue/agents-timestamp");
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, 1);

    // Getting data
    expect_value(__wrap_fgets, __stream, 1);
    will_return(__wrap_fgets, "001 agent1 any 2020-01-01 01:01:01");

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, OS_SUCCESS);

    date_add = get_agent_date_added(agent_id);

    // The date_returned variable is the date 2020-01-01 01:01:01 transformed to INT
    test_time.tm_year = 2020-1900;
    test_time.tm_mon = 1-1;
    test_time.tm_mday = 1;
    test_time.tm_hour = 1;
    test_time.tm_min = 1;
    test_time.tm_sec = 1;
    test_time.tm_isdst = 0;

    date_returned = mktime(&test_time);

    assert_int_equal(date_returned, date_add);
}

int main()
{
    const struct CMUnitTest tests[] =
    {
        /* Tests wdb_create_agent_db */
        cmocka_unit_test_setup_teardown(test_wdb_create_agent_db_error_no_name, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_create_agent_db_error_creating_source_profile, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_create_agent_db_error_reopening_source_profile, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_create_agent_db_error_opening_dest_profile, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_create_agent_db_error_writing_profile, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_create_agent_db_error_getting_ids, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_create_agent_db_error_changing_owner, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_create_agent_db_error_changing_mode, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_create_agent_db_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_insert_agent */
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_success, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_success_keep_date, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_update_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_update_agent_data */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_data_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_get_agent_info */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_info_error_no_json_response, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_info_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_get_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_labels_error_no_json_response, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_labels_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_set_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_labels_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_labels_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_labels_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_labels_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_update_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_delete_agent_belongs */
        cmocka_unit_test_setup_teardown(test_wdb_delete_agent_belongs_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_delete_agent_belongs_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_delete_agent_belongs_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_delete_agent_belongs_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_get_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_name_error_no_json_response, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_name_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_remove_agent_db */
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_db_error_removing_db, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_db_error_removing_db_shm_wal, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_db_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_remove_agent */
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_error_delete_belongs_and_name, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_agent_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_get_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_keepalive_error_no_name_nor_ip, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_keepalive_error_no_json_response, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_keepalive_error_empty_json_response, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_keepalive_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_get_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_group_error_no_json_response, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_group_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_find_agent */
        cmocka_unit_test_setup_teardown(test_wdb_find_agent_error_invalid_parameters, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_find_agent_error_json_input, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_find_agent_error_json_output, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_find_agent_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_get_agent_status */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_status_error_no_json_response, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_status_error_json_data, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_status_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_set_agent_status */
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_status_error_invalid_status, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_status_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_status_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_status_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_status_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_status_success_empty, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_status_success_pending, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_status_success_updated, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_get_agents_by_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_get_agents_by_keepalive_wdbc_query_error, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agents_by_keepalive_wdbc_parse_error, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agents_by_keepalive_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_get_all_agents */
        cmocka_unit_test_setup_teardown(test_wdb_get_all_agents_wdbc_query_error, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_all_agents_wdbc_parse_error, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_all_agents_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_update_agent_group */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_group_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_group_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_group_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_group_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_group_error_multi_group, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_group_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_find_group */
        cmocka_unit_test_setup_teardown(test_wdb_find_group_error_no_json_response, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_find_group_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_insert_group */
        cmocka_unit_test_setup_teardown(test_wdb_insert_group_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_insert_group_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_insert_group_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_insert_group_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_update_agent_belongs */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_belongs_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_belongs_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_belongs_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_belongs_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_belongs_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_update_agent_multi_group */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_multi_group_error_deleting_agent, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_multi_group_error_update_belongs_single, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_multi_group_error_update_belongs_multi, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_multi_group_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_remove_group_from_belongs_db */
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_from_belongs_db_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_from_belongs_db_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_from_belongs_db_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_from_belongs_db_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_remove_group_db */
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_db_error_removing_belongs, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_db_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_db_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_db_error_result, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_remove_group_db_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_update_groups */
        cmocka_unit_test_setup_teardown(test_wdb_update_groups_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_groups_error_max_path, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_groups_error_removing_group_db, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_groups_error_adding_new_groups, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_groups_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_agent_belongs_first_time */
        cmocka_unit_test_setup_teardown(test_wdb_agent_belongs_first_time_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests get_agent_date_added */
        cmocka_unit_test_setup_teardown(test_get_agent_date_added_error_open_file, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_get_agent_date_added_error_no_data, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_get_agent_date_added_error_no_date, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_get_agent_date_added_error_invalid_date, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_get_agent_date_added_success, setup_wdb_agent, teardown_wdb_agent)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
