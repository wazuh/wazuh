/*
 * Copyright (C) 2015, Wazuh Inc.
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

#include "os_err.h"
#include "shared.h"
#include "../../os_auth/auth.h"
#include "../../headers/sec.h"
#include "../../addagent/validate.h"

#include "../wrappers/posix/dirent_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_auth/os_auth_wrappers.h"

#define EXISTENT_AGENT1 "ExistentAgent1"
#define EXISTENT_AGENT2 "ExistentAgent2"
#define EXISTENT_AGENT3 "ExistentAgent3"
#define NEW_AGENT1      "Agent1"
#define NEW_AGENT2      "Agent2"
#define EXISTENT_IP1    "192.0.0.255"
#define EXISTENT_IP2    "192.0.0.254"
#define NEW_IP1         "192.0.0.0"
#define NEW_IP2         "192.0.0.1"
#define ANY_IP          "any"
#define EXISTENT_GROUP1 "ExistentGroup1"
#define EXISTENT_GROUP2 "ExistentGroup2"
#define UNKNOWN_GROUP   "UnknownGroup"
#define AGENT1_ID       "001"

double __wrap_difftime (time_t __time1, time_t __time0) {
    return mock();
}

void keys_init(keystore *keys, key_mode_t key_mode, int save_removed) {
    /* Initialize hashes */
    keys->keytree_id = rbtree_init();
    keys->keytree_ip = rbtree_init();
    keys->keytree_sock = rbtree_init();

    if (!(keys->keytree_id && keys->keytree_ip && keys->keytree_sock)) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* Initialize structure */
    os_calloc(1, sizeof(keyentry*), keys->keyentries);
    keys->keysize = 0;
    keys->id_counter = 0;
    keys->flags.key_mode = key_mode;
    keys->flags.save_removed = save_removed;

    /* Add additional entry for sender == keysize */
    os_calloc(1, sizeof(keyentry), keys->keyentries[keys->keysize]);
    w_mutex_init(&keys->keyentries[keys->keysize]->mutex, NULL);
}

void keyentry_init (keyentry *key, char *name, char *id, char *ip, char *raw_key) {
    os_calloc(1, sizeof(os_ip), key->ip);
    key->ip->ip = ip ? strdup(ip) : NULL;
    key->name = name ? strdup(name) : NULL;
    key->id = id ? strdup(id) : NULL;
    key->raw_key = raw_key ? strdup(raw_key) : NULL;
}

void free_keyentry (keyentry *key) {
    os_free(key->ip->ip);
    os_free(key->ip);
    os_free(key->name);
    os_free(key->id);
    os_free(key->raw_key);
}

//Params used on enrollment
typedef struct _enrollment_param {
    char* ip;
    char* name;
    char* groups;
} enrollment_param;

//Error responses
typedef struct _enrollment_response {
    w_err_t err;
    char* response;
} enrollment_response;

extern struct keynode *queue_insert;
extern struct keynode *queue_remove;
extern struct keynode * volatile *insert_tail;
extern struct keynode * volatile *remove_tail;

/* setup/teardowns */
static int setup_group(void **state) {

    for (unsigned int a = 0; a < 3; a++) {
        expect_any(__wrap_OS_IsValidIP, ip_address);
        expect_any(__wrap_OS_IsValidIP, final_ip);
        will_return(__wrap_OS_IsValidIP, -1);
    }

    keys_init(&keys, 0, !config.flags.clear_removed);
    OS_AddNewAgent(&keys, NULL, EXISTENT_AGENT1, EXISTENT_IP1, NULL);
    OS_AddNewAgent(&keys, NULL, EXISTENT_AGENT2, EXISTENT_IP2, NULL);
    OS_AddNewAgent(&keys, NULL, EXISTENT_AGENT3, ANY_IP, NULL);

    if (gethostname(shost, sizeof(shost) - 1) < 0) {
        strncpy(shost, "localhost", sizeof(shost) - 1);
        shost[sizeof(shost) - 1] = '\0';
    }

    /* Initialize queues */
    insert_tail = &queue_insert;
    remove_tail = &queue_remove;

    return 0;
}

static int teardown_group(void **state) {
    OS_FreeKeys(&keys);

    struct keynode *cur = NULL;
    struct keynode *next = NULL;

    for (cur = queue_remove; cur; cur = next) {
        next = cur->next;
        os_free(cur->id);
        os_free(cur->name);
        os_free(cur->ip);
        os_free(cur);
    }

    return 0;
}

int setup_validate_force_disabled(void **state) {
    config.force_options.enabled = 0;
    return 0;
}

int setup_validate_force_enabled(void **state) {
    config.force_options.enabled = 1;
    return 0;
}

/* tests */
static void test_w_auth_validate_data(void **state) {
    char response[2048] = {0};
    w_err_t err;

    /* New agent / IP*/
    response[0] = '\0';
    err = w_auth_validate_data(response, NEW_IP1, NEW_AGENT1, NULL, NULL);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");

    /* any IP*/
    response[0] = '\0';
    err = w_auth_validate_data(response, ANY_IP, NEW_AGENT1, NULL, NULL);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");

    /* Existent IP */
    response[0] = '\0';
    expect_string(__wrap__mwarn, formatted_msg, "Duplicate IP '"EXISTENT_IP1"', rejecting enrollment. "
                                                "Agent '001' won't be removed because the force option is disabled.");
    err = w_auth_validate_data(response, EXISTENT_IP1, NEW_AGENT1, NULL, NULL);
    assert_int_equal(err, OS_INVALID);
    assert_string_equal(response, "ERROR: Duplicate IP: "EXISTENT_IP1"");

    /* Existent Agent Name */
    response[0] = '\0';
    expect_string(__wrap__mwarn, formatted_msg, "Duplicate name '"EXISTENT_AGENT1"', rejecting enrollment. "
                                                "Agent '001' won't be removed because the force option is disabled.");
    err = w_auth_validate_data(response, NEW_IP1, EXISTENT_AGENT1, NULL, NULL);
    assert_int_equal(err, OS_INVALID);
    assert_string_equal(response, "ERROR: Duplicate agent name: "EXISTENT_AGENT1"");

   /* Manager name */
   char host_name[512];
    if (gethostname(host_name, sizeof(shost) - 1) < 0) {
        strncpy(host_name, "localhost", sizeof(host_name) - 1);
        host_name[sizeof(host_name) - 1] = '\0';
    }
    char err_response[2048];
    snprintf(err_response, 2048, "ERROR: Invalid agent name: %s", host_name) ;
    char merror_message[2048];
    snprintf(merror_message, 2048, "Invalid agent name %s (same as manager)", host_name);
    expect_string(__wrap__merror, formatted_msg, merror_message);
    err = w_auth_validate_data(response,NEW_IP1, host_name, NULL, NULL);
    assert_int_equal(err, OS_INVALID);
    assert_string_equal(response, err_response);

    /* Check no agent was deleted*/
    assert_true(keys.keysize == 3);
    int index = 0;
    index = OS_IsAllowedName(&keys, EXISTENT_AGENT1);
    assert_true(index >= 0);
    index = OS_IsAllowedName(&keys, EXISTENT_AGENT2);
    assert_true(index >= 0);
}

static void test_w_auth_validate_data_replace_agent(void **state) {
    char response[2048] = {0};
    w_err_t err;
    char *connection_status = "active";
    time_t date_add = 1632255744;
    time_t disconnection_time = 0;
    cJSON *j_agent_info_array = NULL;
    cJSON *j_agent_info = NULL;

    /* Duplicate IP*/
    j_agent_info_array = cJSON_CreateArray();
    j_agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(j_agent_info, "connection_status", connection_status);
    cJSON_AddNumberToObject(j_agent_info, "disconnection_time", disconnection_time);
    cJSON_AddNumberToObject(j_agent_info, "date_add", date_add);
    cJSON_AddItemToArray(j_agent_info_array, j_agent_info);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info_array);

    response[0] = '\0';
    expect_string(__wrap__minfo, formatted_msg, "Duplicate IP '"EXISTENT_IP1"'. "
                                                "Removing old agent '"EXISTENT_AGENT1"' (id '001').");
    err = w_auth_validate_data(response, EXISTENT_IP1, NEW_AGENT1, NULL, NULL);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");

    /* Duplicate Name*/
    j_agent_info_array = cJSON_CreateArray();
    j_agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(j_agent_info, "connection_status", connection_status);
    cJSON_AddNumberToObject(j_agent_info, "disconnection_time", disconnection_time);
    cJSON_AddNumberToObject(j_agent_info, "date_add", date_add);
    cJSON_AddItemToArray(j_agent_info_array, j_agent_info);

    expect_value(__wrap_wdb_get_agent_info, id, 2);
    will_return(__wrap_wdb_get_agent_info, j_agent_info_array);

    response[0] = '\0';
    expect_string(__wrap__minfo, formatted_msg, "Duplicate name. "
                                                "Removing old agent '"EXISTENT_AGENT2"' (id '002').");
    err = w_auth_validate_data(response, NEW_IP2, EXISTENT_AGENT2, NULL, NULL);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");

    /* Check agents were deleted*/
    int index = 0;
    index = OS_IsAllowedIP(&keys, EXISTENT_IP1);
    assert_true(index < 0);
    index = OS_IsAllowedName(&keys, EXISTENT_AGENT2);
    assert_true(index < 0);
}

static void test_w_auth_validate_groups(void **state) {
    w_err_t err;
    char response[2048] = {0};

    /* Existent group */
    will_return(__wrap_opendir, 1);
    response[0] = '\0';
    err = w_auth_validate_groups(EXISTENT_GROUP1, response);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");

    /* Non existent group*/
    will_return(__wrap_opendir, 0);
    expect_string(__wrap__merror, formatted_msg, "Invalid group: "UNKNOWN_GROUP);
    response[0] = '\0';
    err = w_auth_validate_groups(UNKNOWN_GROUP, response);
    assert_int_equal(err, OS_INVALID);
    assert_string_equal(response, "ERROR: Invalid group: "UNKNOWN_GROUP"");

    /* Existent multigroups */
    will_return(__wrap_opendir, 1);
    will_return(__wrap_opendir, 1);
    response[0] = '\0';
    err = w_auth_validate_groups(EXISTENT_GROUP1","EXISTENT_GROUP2, response);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");

    /* One Non Existent on multigroups */
    will_return(__wrap_opendir, 1);
    will_return(__wrap_opendir, 1);
    will_return(__wrap_opendir, 0);
    expect_string(__wrap__merror, formatted_msg, "Invalid group: "UNKNOWN_GROUP);
    response[0] = '\0';
    err = w_auth_validate_groups(EXISTENT_GROUP1","EXISTENT_GROUP2","UNKNOWN_GROUP, response);
    assert_int_equal(err, OS_INVALID);
    assert_string_equal(response, "ERROR: Invalid group: "UNKNOWN_GROUP"");
}

static void test_w_auth_replace_agent_force_disabled(void **state) {
    w_err_t err;
    keyentry key;
    keyentry_init(&key, NEW_AGENT1, AGENT1_ID, NEW_IP1, NULL);
    char* str_result = NULL;

    err = w_auth_replace_agent(&key, NULL, &config.force_options, &str_result);

    assert_int_equal(err, OS_INVALID);
    assert_string_equal(str_result, "Agent '001' won't be removed because the force option is disabled.");
    free_keyentry(&key);
    os_free(str_result);
}

static void test_w_auth_replace_agent_agent_info_failed(void **state) {
    w_err_t err;
    keyentry key;
    keyentry_init(&key, NEW_AGENT1, AGENT1_ID, NEW_IP1, NULL);
    char* str_result = NULL;

    config.force_options.enabled = 1;
    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, NULL);

    err = w_auth_replace_agent(&key, NULL, &config.force_options, &str_result);

    config.force_options.enabled = 0;
    assert_int_equal(err, OS_INVALID);
    assert_string_equal(str_result, "Failed to get agent-info for agent '001'");
    free_keyentry(&key);
    os_free(str_result);
}

static void test_w_auth_replace_agent_not_disconnected(void **state) {
    w_err_t err;
    keyentry key;
    keyentry_init(&key, NEW_AGENT1, AGENT1_ID, NEW_IP1, NULL);
    char *connection_status = "active";
    char* str_result = NULL;
    time_t date_add = 1632255744;
    time_t disconnection_time = 0;
    cJSON *j_agent_info_array = NULL;
    cJSON *j_agent_info = NULL;

    j_agent_info_array = cJSON_CreateArray();
    j_agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(j_agent_info, "connection_status", connection_status);
    cJSON_AddNumberToObject(j_agent_info, "disconnection_time", disconnection_time);
    cJSON_AddNumberToObject(j_agent_info, "date_add", date_add);
    cJSON_AddItemToArray(j_agent_info_array, j_agent_info);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info_array);

    // time since disconnected
    will_return(__wrap_difftime, 10);

    config.force_options.disconnected_time_enabled = true;
    config.force_options.disconnected_time = 100;

    err = w_auth_replace_agent(&key, NULL, &config.force_options, &str_result);

    assert_int_equal(err, OS_INVALID);
    assert_string_equal(str_result, "Agent '001' can't be replaced since it is not disconnected.");
    free_keyentry(&key);
    os_free(str_result);
}

static void test_w_auth_replace_agent_not_disconnected_long_enough(void **state) {
    w_err_t err;
    keyentry key;
    keyentry_init(&key, NEW_AGENT1, AGENT1_ID, NEW_IP1, NULL);
    char *connection_status = "disconnected";
    char* str_result = NULL;
    time_t date_add = 1632255744;
    time_t disconnection_time = 1632258049;
    cJSON *j_agent_info_array = NULL;
    cJSON *j_agent_info = NULL;

    j_agent_info_array = cJSON_CreateArray();
    j_agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(j_agent_info, "connection_status", connection_status);
    cJSON_AddNumberToObject(j_agent_info, "disconnection_time", disconnection_time);
    cJSON_AddNumberToObject(j_agent_info, "date_add", date_add);
    cJSON_AddItemToArray(j_agent_info_array, j_agent_info);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info_array);

    // time since disconnected
    will_return(__wrap_difftime, 10);

    config.force_options.disconnected_time_enabled = true;
    config.force_options.disconnected_time = 100;

    err = w_auth_replace_agent(&key, NULL, &config.force_options, &str_result);

    config.force_options.disconnected_time_enabled = false;
    config.force_options.disconnected_time = 0;

    assert_int_equal(err, OS_INVALID);
    assert_string_equal(str_result, "Agent '001' has not been disconnected long enough to be replaced.");
    free_keyentry(&key);
    os_free(str_result);
}

static void test_w_auth_replace_agent_not_old_enough(void **state) {
    w_err_t err;
    keyentry key;
    keyentry_init(&key, NEW_AGENT1, AGENT1_ID, NEW_IP1, NULL);
    char *connection_status = "active";
    char* str_result = NULL;
    time_t date_add = 1632255744;
    time_t disconnection_time = 0;
    cJSON *j_agent_info_array = NULL;
    cJSON *j_agent_info = NULL;

    j_agent_info_array = cJSON_CreateArray();
    j_agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(j_agent_info, "connection_status", connection_status);
    cJSON_AddNumberToObject(j_agent_info, "disconnection_time", disconnection_time);
    cJSON_AddNumberToObject(j_agent_info, "date_add", date_add);
    cJSON_AddItemToArray(j_agent_info_array, j_agent_info);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info_array);

    config.force_options.disconnected_time_enabled = false;

    // time since registration
    will_return(__wrap_difftime, 10);

    config.force_options.after_registration_time = 100;

    err = w_auth_replace_agent(&key, NULL, &config.force_options, &str_result);

    config.force_options.after_registration_time = 0;

    assert_int_equal(err, OS_INVALID);
    assert_string_equal(str_result, "Agent '001' doesn't comply with the registration time to be removed.");
    free_keyentry(&key);
    os_free(str_result);
}

static void test_w_auth_replace_agent_existent_key_hash(void **state) {
    w_err_t err;
    keyentry key;
    keyentry_init(&key, NEW_AGENT1, AGENT1_ID, NEW_IP1, "1234");
    // This is the SHA1 hash of the string: IdNameKey
    char *key_hash = "15153d246b71789195b48778875af94f9378ecf9";
    char *connection_status = "never_connected";
    char* str_result = NULL;
    time_t date_add = 1632255744;
    time_t disconnection_time = 0;
    cJSON *j_agent_info_array = NULL;
    cJSON *j_agent_info = NULL;

    j_agent_info_array = cJSON_CreateArray();
    j_agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(j_agent_info, "connection_status", connection_status);
    cJSON_AddNumberToObject(j_agent_info, "disconnection_time", disconnection_time);
    cJSON_AddNumberToObject(j_agent_info, "date_add", date_add);
    cJSON_AddItemToArray(j_agent_info_array, j_agent_info);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info_array);

    config.force_options.disconnected_time_enabled = false;
    config.force_options.after_registration_time = 0;
    config.force_options.key_mismatch = true;

    err = w_auth_replace_agent(&key, key_hash, &config.force_options, &str_result);

    config.force_options.key_mismatch = false;

    assert_int_equal(err, OS_INVALID);
    assert_string_equal(str_result, "Agent '001' key already exists on the manager.");
    free_keyentry(&key);
    os_free(str_result);
}

static void test_w_auth_replace_agent_success(void **state) {
    w_err_t err;
    keyentry key;
    keyentry_init(&key, NEW_AGENT1, AGENT1_ID, NEW_IP1, NULL);
    char *connection_status = "disconnected";
    char* str_result = NULL;
    time_t date_add = 1632255744;
    time_t disconnection_time = 1632258049;
    cJSON *j_agent_info_array = NULL;
    cJSON *j_agent_info = NULL;

    j_agent_info_array = cJSON_CreateArray();
    j_agent_info = cJSON_CreateObject();
    cJSON_AddStringToObject(j_agent_info, "connection_status", connection_status);
    cJSON_AddNumberToObject(j_agent_info, "disconnection_time", disconnection_time);
    cJSON_AddNumberToObject(j_agent_info, "date_add", date_add);
    cJSON_AddItemToArray(j_agent_info_array, j_agent_info);

    expect_value(__wrap_wdb_get_agent_info, id, 1);
    will_return(__wrap_wdb_get_agent_info, j_agent_info_array);

    will_return(__wrap_difftime, 10);

    config.force_options.disconnected_time_enabled = false;
    config.force_options.after_registration_time = 1;

    err = w_auth_replace_agent(&key, NULL, &config.force_options, &str_result);

    config.force_options.after_registration_time = 0;

    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(str_result, "Removing old agent '"NEW_AGENT1"' (id '001').");
    free_keyentry(&key);
    os_free(str_result);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_auth_validate_groups),
        cmocka_unit_test_setup(test_w_auth_validate_data, setup_validate_force_disabled),
        cmocka_unit_test_setup(test_w_auth_validate_data_replace_agent, setup_validate_force_enabled),
        cmocka_unit_test_setup(test_w_auth_replace_agent_force_disabled, setup_validate_force_disabled),
        cmocka_unit_test_setup(test_w_auth_replace_agent_agent_info_failed, setup_validate_force_disabled),
        cmocka_unit_test_setup(test_w_auth_replace_agent_not_disconnected_long_enough, setup_validate_force_enabled),
        cmocka_unit_test_setup(test_w_auth_replace_agent_not_disconnected, setup_validate_force_enabled),
        cmocka_unit_test_setup(test_w_auth_replace_agent_not_old_enough, setup_validate_force_enabled),
        cmocka_unit_test_setup(test_w_auth_replace_agent_existent_key_hash, setup_validate_force_enabled),
        cmocka_unit_test_setup(test_w_auth_replace_agent_success, setup_validate_force_enabled),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
