/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "shared.h"
#include "../../os_auth/auth.h"
#include "../../headers/sec.h"
#include "../../addagent/manage_agents.h"

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

void keys_init(keystore *keys, int rehash_keys, int save_removed) {
    /* Initialize hashes */
    keys->keyhash_id = OSHash_Create();
    keys->keyhash_ip = OSHash_Create();
    keys->keyhash_sock = OSHash_Create();

    if (!(keys->keyhash_id && keys->keyhash_ip && keys->keyhash_sock)) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* Initialize structure */
    os_calloc(1, sizeof(keyentry*), keys->keyentries);
    keys->keysize = 0;
    keys->id_counter = 0;
    keys->flags.rehash_keys = rehash_keys;
    keys->flags.save_removed = save_removed;

    /* Add additional entry for sender == keysize */
    os_calloc(1, sizeof(keyentry), keys->keyentries[keys->keysize]);
    w_mutex_init(&keys->keyentries[keys->keysize]->mutex, NULL);
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

    return 0;
}

int setup_validate_force_insert_0(void **state) {
    config.flags.force_insert = 0;
    return 0;
}

int setup_validate_force_insert_1(void **state) {
    config.flags.force_insert = 1;
    return 0;
}

/* tests */

static void test_w_auth_validate_data(void **state) {

    char response[2048] = {0};
    w_err_t err;

    /* New agent / IP*/
    response[0] = '\0';
    err = w_auth_validate_data(response,NEW_IP1, NEW_AGENT1, NULL);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");

    /* any IP*/
    response[0] = '\0';
    err = w_auth_validate_data(response,ANY_IP, NEW_AGENT1, NULL);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");

    /* Existent IP */
    response[0] = '\0';
    expect_string(__wrap__merror, formatted_msg, "Duplicated IP "EXISTENT_IP1);
    err = w_auth_validate_data(response,EXISTENT_IP1, NEW_AGENT1, NULL);
    assert_int_equal(err, OS_INVALID);
    assert_string_equal(response, "ERROR: Duplicated IP: "EXISTENT_IP1"");

    /* Existent Agent Name */
    response[0] = '\0';
    expect_string(__wrap__merror, formatted_msg, "Invalid agent name "EXISTENT_AGENT1" (duplicated)");
    err = w_auth_validate_data(response,NEW_IP1, EXISTENT_AGENT1, NULL);
    assert_int_equal(err, OS_INVALID);
    assert_string_equal(response, "ERROR: Duplicated agent name: "EXISTENT_AGENT1"");

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
    err = w_auth_validate_data(response,NEW_IP1, host_name, NULL);
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

static void test_w_auth_validate_data_force_insert(void **state) {

    char response[2048] = {0};
    w_err_t err;

    /* Duplicated IP*/
    response[0] = '\0';
    expect_string(__wrap__minfo, formatted_msg, "Duplicated IP '"EXISTENT_IP1"' (001). Removing old agent.");
    err = w_auth_validate_data(response, EXISTENT_IP1, NEW_AGENT1, NULL);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");

     /* Duplicated Name*/
    response[0] = '\0';
    expect_string(__wrap__minfo, formatted_msg, "Duplicated name '"EXISTENT_AGENT2"' (002). Removing old agent.");
    err = w_auth_validate_data(response, NEW_IP2, EXISTENT_AGENT2, NULL);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");

    /* Check agents were deleted*/
    int index = 0;
    index = OS_IsAllowedIP(&keys, EXISTENT_IP1);
    assert_true(index < 0);
    index = OS_IsAllowedName(&keys, EXISTENT_AGENT2);
    assert_true(index < 0);
}

static void test_w_auth_validate_data_register_limit(void **state) {
    char response[2048] = {0};
    char agent_name[2048] = "agent_x";
    char error_message[2048];
    w_err_t err;


    //Filling most of keys element with a fixed key to reduce computing time
    char fixed_key[KEYSIZE] = "1234";
    for(unsigned i=0; i<100000; i++) {
        OS_AddNewAgent(&keys, NULL, agent_name, ANY_IP, fixed_key);
    }

    //Adding last keys as usual
    for(unsigned i=0; i<10; i++) {
        snprintf(agent_name, 2048, "__agent_%d", i);
        response[0] = '\0';
        err = w_auth_validate_data(response,ANY_IP, agent_name, NULL);
        assert_int_equal(err, OS_SUCCESS);
        assert_string_equal(response, "");
        OS_AddNewAgent(&keys, NULL, agent_name, ANY_IP, NULL);
    }
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


int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_auth_validate_groups),
        cmocka_unit_test_setup(test_w_auth_validate_data, setup_validate_force_insert_0),
        cmocka_unit_test_setup(test_w_auth_validate_data_force_insert, setup_validate_force_insert_1),
        cmocka_unit_test_setup(test_w_auth_validate_data_register_limit, setup_validate_force_insert_0),

    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
