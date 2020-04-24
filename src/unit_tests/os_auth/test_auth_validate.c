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

#define MOCK_KEYS_FILE "./client.keys"

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
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
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

#define EXISTENT_AGENT1 "ExistentAgent1"
#define EXISTENT_AGENT2 "ExistentAgent2"
#define EXISTENT_IP1 "192.0.0.255"
#define EXISTENT_IP2 "192.0.0.254"

/* setup/teardowns */
static int setup_group(void **state) {
    keys_init(&keys, 0, !config.flags.clear_removed);
    OS_AddNewAgent(&keys, NULL, EXISTENT_AGENT1, EXISTENT_IP1, NULL);
    OS_AddNewAgent(&keys, NULL, EXISTENT_AGENT1, EXISTENT_IP1, NULL);
}

int setup_validate_default(void **state) {    
    //JJP: Fix...
    keys_init(&keys, 0, !config.flags.clear_removed);
    OS_AddNewAgent(&keys, NULL, EXISTENT_AGENT1, EXISTENT_IP1, NULL);
    OS_AddNewAgent(&keys, NULL, EXISTENT_AGENT1, EXISTENT_IP1, NULL);

    config.flags.use_source_ip = 0;
    return 0;
}

int setup_validate_cfg(void **state) {
        config.flags.use_source_ip = 0;
    //config.flags.use_source_ip = 0;
    return 0;
}


/* tests */

static void test_w_auth_validate_data(void **state) {    

    char response[2048] = {0};   
    w_err_t err;

    /* New agent / IP*/
    response[0] = '\0';         
    err = w_auth_validate_data(response,"192.0.0.0", "agent1", NULL);  
    assert_int_equal(err, OS_SUCCESS);
    assert_string_equal(response, "");   
    
    /* Existent IP */
    response[0] = '\0'; 
    expect_string(__wrap__merror, formatted_msg, "Duplicated IP "EXISTENT_IP1);        
    err = w_auth_validate_data(response,EXISTENT_IP1, "agent1", NULL);  
    assert_int_equal(err, OS_INVALID);
    assert_string_equal(response, "ERROR: Duplicated IP: "EXISTENT_IP1"\n\n");     
}


int main(void) {   
    bool block = 1;
    while(block){;}
    const struct CMUnitTest tests[] = { 
        cmocka_unit_test(test_w_auth_validate_data),
    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
