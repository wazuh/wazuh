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
#include <stdio.h>
#include <string.h>

#include "wazuh_db/wdb.h"
#include "wazuhdb_op.h"

#define WDBQUERY_SIZE OS_BUFFER_SIZE
#define WDBOUTPUT_SIZE OS_MAXSTR

int test_mode = 0;

/* redefinitons/wrapping */

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
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

char *__wrap_strerror (int __errnum) {
    return mock_type(char*);
}

cJSON * __wrap_cJSON_CreateObject(void) {
    return mock_type(cJSON *);
}

cJSON * __wrap_cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number) {
    check_expected(name);
    check_expected(number);
    return mock_type(cJSON *);
}

cJSON* __wrap_cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string) {
    check_expected(name);
    check_expected(string);
    return mock_type(cJSON *);
}

char* __wrap_cJSON_PrintUnformatted(const cJSON *item) {
    return mock_type(char *);
}

void __wrap_cJSON_Delete(cJSON *item) {
    function_called();
    return;
}

time_t __wrap_time(time_t *__timer) {
    *__timer = 1;
    return 1;
}

extern FILE *__real_fopen(const char * __filename, const char * __modes);
FILE *__wrap_fopen(const char * __filename, const char * __modes) {
    check_expected(__filename);
    check_expected(__modes);
    if (test_mode) {
        return mock_type(FILE *);
    }
    return __real_fopen(__filename, __modes);
}

extern size_t __real_fread(void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream);
size_t __wrap_fread(void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __stream) {
    if (test_mode) {
        return mock_type(size_t);
    }
    return __real_fread(__ptr, __size, __n, __stream);
}

extern size_t __real_fwrite(const void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __s);
size_t __wrap_fwrite(const void *__restrict __ptr, size_t __size, size_t __n, FILE *__restrict __s) {
    if (test_mode) {
        return mock_type(size_t);
    }
    return __real_fwrite(__ptr, __size, __n, __s);
}

extern int __real_fclose(FILE *__stream);
int __wrap_fclose(FILE *stream) {
    if (test_mode) {
        return mock_type(int);
    }
    return __real_fclose(stream);
}

int __wrap_wdbc_query_ex(int *sock, const char *query, char *response, const int len) {
    check_expected(*sock);
    check_expected(query);
    check_expected(len);

    return mock_type(int);
}

int __wrap_wdbc_parse_result(char *result, char **payload) {
    return mock_type(int);
}

cJSON *__wrap_wdbc_query_parse_json(int *sock, const char *query, char *response, const int len) {
    check_expected(*sock);
    check_expected(query);
    check_expected(len);

    return mock_type(cJSON *);
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

int __wrap_chown(const char *__file, __uid_t __owner, __gid_t __group) {
    check_expected(__file);
    check_expected(__owner);
    check_expected(__group);

    return mock_type(int);
}

int __wrap_chmod(const char *__file, __mode_t __mode) {
    check_expected(__file);
    check_expected(__mode);

    return mock_type(int);
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
    expect_string(__wrap_fopen, __filename, "var/db/.template.db");
    expect_string(__wrap_fopen, __modes, "r");
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
    expect_string(__wrap_fopen, __filename, "var/db/.template.db");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, 0);
    // Creating profile
    expect_string(__wrap__mdebug1, formatted_msg, "Profile database not found, creating.");
    expect_string(__wrap_wdb_create_profile, path, "var/db/.template.db");
    will_return(__wrap_wdb_create_profile, OS_SUCCESS);
    // Opening source database file
    expect_string(__wrap_fopen, __filename, "var/db/.template.db");
    expect_string(__wrap_fopen, __modes, "r");
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
    expect_string(__wrap_fopen, __filename, "var/db/.template.db");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    expect_string(__wrap_fopen, __filename, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, __modes, "w");
    will_return(__wrap_fopen, 0);
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
    expect_string(__wrap_fopen, __filename, "var/db/.template.db");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    expect_string(__wrap_fopen, __filename, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, __modes, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, 100);
    will_return(__wrap_fwrite, 0);
    // Closing files
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
    expect_string(__wrap_fopen, __filename, "var/db/.template.db");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    expect_string(__wrap_fopen, __filename, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, __modes, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, 100);
    will_return(__wrap_fwrite, 100);
    will_return(__wrap_fread, 0);
    // Closing files
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
    expect_string(__wrap_fopen, __filename, "var/db/.template.db");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    expect_string(__wrap_fopen, __filename, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, __modes, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, 100);
    will_return(__wrap_fwrite, 100);
    will_return(__wrap_fread, 0);
    // Closing files
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
    expect_string(__wrap_fopen, __filename, "var/db/.template.db");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    expect_string(__wrap_fopen, __filename, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, __modes, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, 100);
    will_return(__wrap_fwrite, 100);
    will_return(__wrap_fread, 0);
    // Closing files
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
    expect_string(__wrap_chmod, __file, "var/db/agents/001-agent1.db");
    expect_value(__wrap_chmod, __mode, 0660);
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
    expect_string(__wrap_fopen, __filename, "var/db/.template.db");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    expect_string(__wrap_fopen, __filename, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, __modes, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, 100);
    will_return(__wrap_fwrite, 100);
    will_return(__wrap_fread, 0);
    // Closing files
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
    expect_string(__wrap_chmod, __file, "var/db/agents/001-agent1.db");
    expect_value(__wrap_chmod, __mode, 0660);
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

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date);

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

    const char *json_str = "{\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}";
    const char *query_str = "global insert-agent {\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "agent1");
    expect_string(__wrap_cJSON_AddStringToObject, name, "ip");
    expect_value(__wrap_cJSON_AddStringToObject, string, "192.168.0.101");
    expect_string(__wrap_cJSON_AddStringToObject, name, "register_ip");
    expect_value(__wrap_cJSON_AddStringToObject, string, "any");
    expect_string(__wrap_cJSON_AddStringToObject, name, "internal_key");
    expect_value(__wrap_cJSON_AddStringToObject, string, "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_value(__wrap_cJSON_AddStringToObject, string, "default");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "date_add");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Hnadling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global insert-agent {\"id\":1,\
\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}");

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date);

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

    const char *json_str = "{\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}";
    const char *query_str = "global insert-agent {\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "agent1");
    expect_string(__wrap_cJSON_AddStringToObject, name, "ip");
    expect_value(__wrap_cJSON_AddStringToObject, string, "192.168.0.101");
    expect_string(__wrap_cJSON_AddStringToObject, name, "register_ip");
    expect_value(__wrap_cJSON_AddStringToObject, string, "any");
    expect_string(__wrap_cJSON_AddStringToObject, name, "internal_key");
    expect_value(__wrap_cJSON_AddStringToObject, string, "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_value(__wrap_cJSON_AddStringToObject, string, "default");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "date_add");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Hnadling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global insert-agent {\"id\":1,\
\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}");

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date);

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

    const char *json_str = "{\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}";
    const char *query_str = "global insert-agent {\"id\":1,\"name\":\"agent1\",\"ip\":\"192.168.0.101\",\"register_ip\":\"any\",\
\"internal_key\":\"e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301\",\"group\":\"default\",\"date_add\":1}";

    FILE* db_file = (FILE*)1;

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "agent1");
    expect_string(__wrap_cJSON_AddStringToObject, name, "ip");
    expect_value(__wrap_cJSON_AddStringToObject, string, "192.168.0.101");
    expect_string(__wrap_cJSON_AddStringToObject, name, "register_ip");
    expect_value(__wrap_cJSON_AddStringToObject, string, "any");
    expect_string(__wrap_cJSON_AddStringToObject, name, "internal_key");
    expect_value(__wrap_cJSON_AddStringToObject, string, "e6ecef1698e21e8fb160e81c722a0523d72554dc1fc3e4374e247f4baac52301");
    expect_string(__wrap_cJSON_AddStringToObject, name, "group");
    expect_value(__wrap_cJSON_AddStringToObject, string, "default");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "date_add");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    // Hnadling result and creating agent database
    // Opening source database file
    expect_string(__wrap_fopen, __filename, "var/db/.template.db");
    expect_string(__wrap_fopen, __modes, "r");
    will_return(__wrap_fopen, 1);
    // Opening destination database file
    expect_string(__wrap_fopen, __filename, "var/db/agents/001-agent1.db");
    expect_string(__wrap_fopen, __modes, "w");
    will_return(__wrap_fopen, 1);
    // Writing destination profile
    will_return(__wrap_fread, 100);
    will_return(__wrap_fwrite, 100);
    will_return(__wrap_fread, 0);
    // Closing files
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
    expect_string(__wrap_chmod, __file, "var/db/agents/001-agent1.db");
    expect_value(__wrap_chmod, __mode, 0660);
    will_return(__wrap_chmod, OS_SUCCESS);

    ret = wdb_insert_agent(id, name, ip, register_ip, internal_key, group, keep_date);

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

    ret = wdb_update_agent_name(id, name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_name_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";

    const char *json_str = "{\"id\":1,\"name\":\"agent1\"}";
    const char *query_str = "global update-agent-name {\"id\":1,\"name\":\"agent1\"}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "agent1");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Hnadling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-name {\"id\":1,\"name\":\"agent1\"}");

    ret = wdb_update_agent_name(id, name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_name_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";

    const char *json_str = "{\"id\":1,\"name\":\"agent1\"}";
    const char *query_str = "global update-agent-name {\"id\":1,\"name\":\"agent1\"}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "agent1");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Hnadling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-name {\"id\":1,\"name\":\"agent1\"}");

    ret = wdb_update_agent_name(id, name);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_name_success(void **state)
{
    int ret = 0;
    int id = 1;
    const char *name = "agent1";

    const char *json_str = "{\"id\":1,\"name\":\"agent1\"}";
    const char *query_str = "global update-agent-name {\"id\":1,\"name\":\"agent1\"}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "agent1");

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_update_agent_name(id, name);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_update_agent_version */

void test_wdb_update_agent_version_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    char *os_name = "osname";
    char *os_version = "osversion";
    char *os_major = "osmajor";
    char *os_minor = "osminor";
    char *os_codename = "oscodename";
    char *os_platform = "osplatform";
    char *os_build = "osbuild";
    char *os_uname = "osuname";
    char *os_arch = "osarch";
    char *version = "version";
    char *config_sum = "csum";
    char *merged_sum = "msum";
    char *manager_host = "managerhost";
    char *node_name = "nodename";
    char *agent_ip = "agentip";
    wdb_sync_status_t sync_status = WDB_SYNC_REQ;

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_version(id, os_name, os_version, os_major, os_minor, os_codename,
                                   os_platform, os_build, os_uname, os_arch, version, config_sum,
                                   merged_sum, manager_host, node_name, agent_ip, sync_status);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_version_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    char *os_name = "osname";
    char *os_version = "osversion";
    char *os_major = "osmajor";
    char *os_minor = "osminor";
    char *os_codename = "oscodename";
    char *os_platform = "osplatform";
    char *os_build = "osbuild";
    char *os_uname = "osuname";
    char *os_arch = "osarch";
    char *version = "version";
    char *config_sum = "csum";
    char *merged_sum = "msum";
    char *manager_host = "managerhost";
    char *node_name = "nodename";
    char *agent_ip = "agentip";
    wdb_sync_status_t sync_status = WDB_SYNC_REQ;

    const char *json_str = "{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"sync_status\":1}";
    const char *query_str = "global update-agent-version {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"sync_status\":1}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_version");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osversion");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_major");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osmajor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_minor");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osminor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_codename");
    expect_value(__wrap_cJSON_AddStringToObject, string, "oscodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_platform");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osplatform");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_build");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osbuild");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_uname");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osuname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_arch");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osarch");
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_value(__wrap_cJSON_AddStringToObject, string, "version");
    expect_string(__wrap_cJSON_AddStringToObject, name, "config_sum");
    expect_value(__wrap_cJSON_AddStringToObject, string, "csum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "merged_sum");
    expect_value(__wrap_cJSON_AddStringToObject, string, "msum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "manager_host");
    expect_value(__wrap_cJSON_AddStringToObject, string, "managerhost");
    expect_string(__wrap_cJSON_AddStringToObject, name, "node_name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "nodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "agent_ip");
    expect_value(__wrap_cJSON_AddStringToObject, string, "agentip");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "sync_status");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Hnadling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-version \
{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"sync_status\":1}");

    ret = wdb_update_agent_version(id, os_name, os_version, os_major, os_minor, os_codename,
                                   os_platform, os_build, os_uname, os_arch, version, config_sum,
                                   merged_sum, manager_host, node_name, agent_ip, sync_status);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_version_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    char *os_name = "osname";
    char *os_version = "osversion";
    char *os_major = "osmajor";
    char *os_minor = "osminor";
    char *os_codename = "oscodename";
    char *os_platform = "osplatform";
    char *os_build = "osbuild";
    char *os_uname = "osuname";
    char *os_arch = "osarch";
    char *version = "version";
    char *config_sum = "csum";
    char *merged_sum = "msum";
    char *manager_host = "managerhost";
    char *node_name = "nodename";
    char *agent_ip = "agentip";
    wdb_sync_status_t sync_status = WDB_SYNC_REQ;

    const char *json_str = "{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"sync_status\":1}";
    const char *query_str = "global update-agent-version {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"sync_status\":1}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_version");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osversion");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_major");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osmajor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_minor");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osminor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_codename");
    expect_value(__wrap_cJSON_AddStringToObject, string, "oscodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_platform");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osplatform");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_build");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osbuild");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_uname");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osuname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_arch");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osarch");
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_value(__wrap_cJSON_AddStringToObject, string, "version");
    expect_string(__wrap_cJSON_AddStringToObject, name, "config_sum");
    expect_value(__wrap_cJSON_AddStringToObject, string, "csum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "merged_sum");
    expect_value(__wrap_cJSON_AddStringToObject, string, "msum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "manager_host");
    expect_value(__wrap_cJSON_AddStringToObject, string, "managerhost");
    expect_string(__wrap_cJSON_AddStringToObject, name, "node_name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "nodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "agent_ip");
    expect_value(__wrap_cJSON_AddStringToObject, string, "agentip");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "sync_status");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Hnadling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-agent-version \
{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"sync_status\":1}");

    ret = wdb_update_agent_version(id, os_name, os_version, os_major, os_minor, os_codename,
                                   os_platform, os_build, os_uname, os_arch, version, config_sum,
                                   merged_sum, manager_host, node_name, agent_ip, sync_status);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_version_success(void **state)
{
    int ret = 0;
    int id = 1;
    char *os_name = "osname";
    char *os_version = "osversion";
    char *os_major = "osmajor";
    char *os_minor = "osminor";
    char *os_codename = "oscodename";
    char *os_platform = "osplatform";
    char *os_build = "osbuild";
    char *os_uname = "osuname";
    char *os_arch = "osarch";
    char *version = "version";
    char *config_sum = "csum";
    char *merged_sum = "msum";
    char *manager_host = "managerhost";
    char *node_name = "nodename";
    char *agent_ip = "agentip";
    wdb_sync_status_t sync_status = WDB_SYNC_REQ;

    const char *json_str = "{\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"sync_status\":1}";
    const char *query_str = "global update-agent-version {\"id\": 1,\"os_name\":\"osname\",\"os_version\":\"osversion\",\
\"os_major\":\"osmajor\",\"os_minor\":\"osminor\",\"os_codename\":\"oscodename\",\
\"os_platform\":\"osplatform\",\"os_build\":\"osbuild\",\"os_uname\":\"osuname\",\
\"os_arch\":\"osarch\",\"version\":\"version\",\"config_sum\":\"csum\",\"merged_sum\":\"msum\",\
\"manager_host\":\"managerhost\",\"node_name\":\"nodename\",\"agent_ip\":\"agentip\",\"sync_status\":1}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);
    will_return_always(__wrap_cJSON_AddStringToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_version");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osversion");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_major");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osmajor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_minor");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osminor");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_codename");
    expect_value(__wrap_cJSON_AddStringToObject, string, "oscodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_platform");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osplatform");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_build");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osbuild");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_uname");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osuname");
    expect_string(__wrap_cJSON_AddStringToObject, name, "os_arch");
    expect_value(__wrap_cJSON_AddStringToObject, string, "osarch");
    expect_string(__wrap_cJSON_AddStringToObject, name, "version");
    expect_value(__wrap_cJSON_AddStringToObject, string, "version");
    expect_string(__wrap_cJSON_AddStringToObject, name, "config_sum");
    expect_value(__wrap_cJSON_AddStringToObject, string, "csum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "merged_sum");
    expect_value(__wrap_cJSON_AddStringToObject, string, "msum");
    expect_string(__wrap_cJSON_AddStringToObject, name, "manager_host");
    expect_value(__wrap_cJSON_AddStringToObject, string, "managerhost");
    expect_string(__wrap_cJSON_AddStringToObject, name, "node_name");
    expect_value(__wrap_cJSON_AddStringToObject, string, "nodename");
    expect_string(__wrap_cJSON_AddStringToObject, name, "agent_ip");
    expect_value(__wrap_cJSON_AddStringToObject, string, "agentip");
    expect_string(__wrap_cJSON_AddNumberToObject, name, "sync_status");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_update_agent_version(id, os_name, os_version, os_major, os_minor, os_codename,
                                   os_platform, os_build, os_uname, os_arch, version, config_sum,
                                   merged_sum, manager_host, node_name, agent_ip, sync_status);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_get_agent_labels */

void test_wdb_get_agent_labels_error_no_json_response(void **state) {
    cJSON *root = NULL;
    int id = 1;

    const char *query_str = "global get-labels 1";

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_parse_json, *sock, -1);
    expect_string(__wrap_wdbc_query_parse_json, query, query_str);
    expect_value(__wrap_wdbc_query_parse_json, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_parse_json, NULL);

    expect_string(__wrap__merror, formatted_msg, "Error querying Wazuh DB to get the agent's 1 labels.");

    root = wdb_get_agent_labels(id);

    assert_null(root);
}

void test_wdb_get_agent_labels_success(void **state) {
    cJSON *root = NULL;
    int id = 1;

    const char *query_str = "global get-labels 1";

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_parse_json, *sock, -1);
    expect_string(__wrap_wdbc_query_parse_json, query, query_str);
    expect_value(__wrap_wdbc_query_parse_json, len, OS_MAXSTR);
    will_return(__wrap_wdbc_query_parse_json, (cJSON *)1);

    root = wdb_get_agent_labels(id);

    assert_ptr_equal(1, root);
}

/* Tests wdb_set_agent_labels */

void test_wdb_set_agent_labels_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    char *labels = "key1:value1\nkey2:value2";

    char *query_str = "global set-labels 1 key1:value1\nkey2:value2";

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, OS_BUFFER_SIZE);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Hnadling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global set-labels 1 key1:value1\nkey2:value2");

    ret = wdb_set_agent_labels(id, labels);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_agent_labels_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    char *labels = "key1:value1\nkey2:value2";

    char *query_str = "global set-labels 1 key1:value1\nkey2:value2";

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, OS_BUFFER_SIZE);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Hnadling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global set-labels 1 key1:value1\nkey2:value2");

    ret = wdb_set_agent_labels(id, labels);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_set_agent_labels_success(void **state)
{
    int ret = 0;
    int id = 1;
    char *labels = "key1:value1\nkey2:value2";

    char *query_str = "global set-labels 1 key1:value1\nkey2:value2";

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, OS_BUFFER_SIZE);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_set_agent_labels(id, labels);

    assert_int_equal(OS_SUCCESS, ret);
}

/* Tests wdb_update_agent_keepalive */

void test_wdb_update_agent_keepalive_error_json(void **state)
{
    int ret = 0;
    int id = 1;
    wdb_sync_status_t sync_status = WDB_SYNCED;

    will_return(__wrap_cJSON_CreateObject, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Error creating data JSON for Wazuh DB.");

    ret = wdb_update_agent_keepalive(id, sync_status);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_error_socket(void **state)
{
    int ret = 0;
    int id = 1;
    wdb_sync_status_t sync_status = WDB_SYNCED;

    const char *json_str = "{\"id\":1,\"sync_status\":0}";
    const char *query_str = "global update-keepalive {\"id\":1,\"sync_status\":0}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "sync_status");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, OS_INVALID);

    // Hnadling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Error in the response from socket");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-keepalive {\"id\":1,\"sync_status\":0}");

    ret = wdb_update_agent_keepalive(id, sync_status);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_error_sql_execution(void **state)
{
    int ret = 0;
    int id = 1;
    wdb_sync_status_t sync_status = WDB_SYNCED;

    const char *json_str = "{\"id\":1,\"sync_status\":0}";
    const char *query_str = "global update-keepalive {\"id\":1,\"sync_status\":0}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "sync_status");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, -100); // Returning any error

    // Hnadling result
    expect_string(__wrap__mdebug1, formatted_msg, "Global DB Cannot execute SQL query; err database queue/db/global.db");
    expect_string(__wrap__mdebug2, formatted_msg, "Global DB SQL query: global update-keepalive {\"id\":1,\"sync_status\":0}");

    ret = wdb_update_agent_keepalive(id, sync_status);

    assert_int_equal(OS_INVALID, ret);
}

void test_wdb_update_agent_keepalive_success(void **state)
{
    int ret = 0;
    int id = 1;
    wdb_sync_status_t sync_status = WDB_SYNCED;

    const char *json_str = "{\"id\":1,\"sync_status\":0}";
    const char *query_str = "global update-keepalive {\"id\":1,\"sync_status\":0}";

    will_return(__wrap_cJSON_CreateObject, 1);
    will_return_always(__wrap_cJSON_AddNumberToObject, 1);

    // Adding data to JSON
    expect_string(__wrap_cJSON_AddNumberToObject, name, "id");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "sync_status");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);

    // Printing JSON
    will_return(__wrap_cJSON_PrintUnformatted, json_str);
    expect_function_call(__wrap_cJSON_Delete);

    // Calling Wazuh DB
    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, query_str);
    expect_value(__wrap_wdbc_query_ex, len, WDBOUTPUT_SIZE);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    // Parsing Wazuh DB result
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    ret = wdb_update_agent_keepalive(id, sync_status);

    assert_int_equal(OS_SUCCESS, ret);
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
        cmocka_unit_test_setup_teardown(test_wdb_insert_agent_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_update_agent_name */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_name_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_update_agent_version */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_version_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_version_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_version_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_version_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_get_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_labels_error_no_json_response, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_get_agent_labels_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_set_agent_labels */
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_labels_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_labels_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_set_agent_labels_success, setup_wdb_agent, teardown_wdb_agent),
        /* Tests wdb_update_agent_keepalive */
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_json, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_socket, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_error_sql_execution, setup_wdb_agent, teardown_wdb_agent),
        cmocka_unit_test_setup_teardown(test_wdb_update_agent_keepalive_success, setup_wdb_agent, teardown_wdb_agent),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
