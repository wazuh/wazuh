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
#include "../../addagent/manage_agents.h"
#include "../../headers/sec.h"


/* redefinitons/wrapping */
void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...) {
    return 1;
}

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
extern struct keynode *queue_backup;
extern struct keynode *queue_remove;
extern struct keynode * volatile *insert_tail;
extern struct keynode * volatile *backup_tail;
extern struct keynode * volatile *remove_tail;

char* new_id = NULL;
char* new_key = NULL;

/* setup/teardowns */
static int setup_group(void **state) {
    keys_init(&keys, 0, !config.flags.clear_removed); 
    
    /* Initialize queues */    
    insert_tail = &queue_insert;
    backup_tail = &queue_backup;
    remove_tail = &queue_remove;

    return 0;
}

static int teardown_group(void **state) {
    OS_FreeKeys(&keys);

    return 0;
}

static int teardown_add_agent(void **state) {
    os_free(new_id);
    os_free(new_key);

    return 0;
}


/* tests */

static void test_w_auth_add_agent(void **state) {   
    char response[2048] = {0};   
    w_err_t err;
    /* Successful new agent */
    err = w_auth_add_agent(response, "192.0.0.0", "agent1", NULL, &new_id, &new_key);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");  
    assert_non_null(new_id);
    assert_non_null(new_key);
}
    
static void test_w_auth_add_agent_with_group(void **state) { 
    char response[2048] = {0};   
    w_err_t err; 
    /* Successful new agent with group */
    err = w_auth_add_agent(response, "192.0.0.1", "agent2", "Group1,Group2,Group3", &new_id, &new_key);
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");  
    assert_non_null(new_id);
    assert_non_null(new_key);    
}


int main(void) {   
    const struct CMUnitTest tests[] = { 
        cmocka_unit_test_teardown(test_w_auth_add_agent, teardown_add_agent),  
        cmocka_unit_test_teardown(test_w_auth_add_agent_with_group, teardown_add_agent), 
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
