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

#include "../../headers/shared.h"
#include "../../analysisd/logtest.h"

int w_logtest_init_parameters();
void *w_logtest_init();
void w_logtest_remove_session(char *token);
void *w_logtest_check_inactive_sessions(w_logtest_connection_t * connection);

int logtest_enabled = 1;

/* setup/teardown */



/* wraps */

int __wrap_OS_BindUnixDomain(const char *path, int type, int max_msg_size) {
    return mock();
}

int __wrap_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len) {
    return mock();
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_pthread_mutex_init() {
    return mock();
}

int __wrap_pthread_mutex_lock(pthread_mutex_t * mutex) {
    return mock_type(int);
}

int __wrap_pthread_mutex_unlock(pthread_mutex_t * mutex) {
    return mock_type(int);
}

int __wrap_pthread_mutex_destroy() {
    return mock();
}

int __wrap_ReadConfig(int modules, const char *cfgfile, void *d1, void *d2) {
    if (!logtest_enabled) {
        w_logtest_conf.enabled = false;
    }
    return mock();
}

OSHash *__wrap_OSHash_Create() {
    return mock_type(OSHash *);
}

int __wrap_OSHash_setSize(OSHash *self, unsigned int new_size) {
    if (new_size) check_expected(new_size);
    return mock();
}

OSList *__wrap_OSList_Create() {
    return mock_type(OSList *);
}

int __wrap_OSList_SetMaxSize() {
    return mock();
}

void __wrap__minfo(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap_w_mutex_init() {
    return;
}

void __wrap_w_mutex_destroy() {
    return;
}

void __wrap_w_create_thread() {
    return;
}

int __wrap_close (int __fd) {
    return mock();
}

int __wrap_getDefine_Int() {
    return mock();
}

void * __wrap_OSHash_Delete_ex(OSHash *self, const char *key) {
    if (key) check_expected(key);
    return mock_type(void *);
}

int __wrap_OSHash_Add_ex(OSHash *hash, const char *key, void *data) {
    check_expected_ptr(key);
    check_expected_ptr(hash);
    check_expected_ptr(data);
    return mock_type(int);
}

void __wrap_os_remove_rules_list(RuleNode *node) {
    return;
}

void * __wrap_OSHash_Free(OSHash *self) {
    return mock_type(void *);
}

void __wrap_os_remove_decoders_list(OSDecoderNode *decoderlist_pn, OSDecoderNode *decoderlist_npn) {
    return;
}

void __wrap_os_remove_cdblist(ListNode **l_node) {
    return;
}

void __wrap_os_remove_cdbrules(ListRule **l_rule) {
    os_free(*l_rule);
    return;
}

void __wrap_os_remove_eventlist(EventList *list) {
    return;
}

unsigned int __wrap_sleep (unsigned int __seconds) {
    return mock_type(unsigned int);
}

OSHashNode *__wrap_OSHash_Begin(const OSHash *self, unsigned int *i) {
    return mock_type(OSHashNode *);
}

time_t __wrap_time(time_t *t) {
    return mock_type(time_t);
}

double __wrap_difftime (time_t __time1, time_t __time0) {
    return mock();
}

OSHashNode *__wrap_OSHash_Next(const OSHash *self, unsigned int *i, OSHashNode *current) {
    return mock_type(OSHashNode *);
}

OSStore *__wrap_OSStore_Free(OSStore *list) {
    return mock_type(OSStore *);
}

/* tests */

/* w_logtest_init_parameters */

void test_w_logtest_init_parameters_invalid(void **state)
{
    will_return(__wrap_ReadConfig, OS_INVALID);

    int ret = w_logtest_init_parameters();
    assert_int_equal(ret, OS_INVALID);

}

void test_w_logtest_init_parameters_done(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    int ret = w_logtest_init_parameters();
    assert_int_equal(ret, OS_SUCCESS);

}

/* w_logtest_init */
void test_w_logtest_init_error_parameters(void **state)
{
    will_return(__wrap_ReadConfig, OS_INVALID);

    expect_string(__wrap__merror, formatted_msg, "(7304): Invalid wazuh-logtest configuration");

    w_logtest_init();

}


void test_w_logtest_init_logtest_disabled(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    logtest_enabled = 0;

    expect_string(__wrap__minfo, formatted_msg, "(7201): Logtest disabled");

    w_logtest_init();

    logtest_enabled = 1;

}

void test_w_logtest_init_conection_fail(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SOCKTERR);

    expect_string(__wrap__merror, formatted_msg, "(7300): Unable to bind to socket '/queue/ossec/logtest'. Errno: (0) Success");

    w_logtest_init();

}

void test_w_logtest_init_OSHash_create_fail(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SUCCESS);

    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(7303): Failure to initialize all_sessions hash");

    w_logtest_init();

}

void test_w_logtest_init_OSHash_setSize_fail(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SUCCESS);

    will_return(__wrap_OSHash_Create, 1);

    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, NULL);

    expect_string(__wrap__merror, formatted_msg, "(7305): Failure to resize all_sessions hash");

    w_logtest_init();

}

void test_w_logtest_init_done(void **state)
{
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SUCCESS);

    will_return(__wrap_OSHash_Create, 1);

    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);

    expect_string(__wrap__minfo, formatted_msg, "(7200): Logtest started");

    // Needs to implement w_logtest_main

    w_logtest_init();

}

/* w_logtest_fts_init */
void test_w_logtest_fts_init_create_list_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1290): Unable to create a new list (calloc).");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);

}

void test_w_logtest_fts_init_SetMaxSize_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 0);

    expect_string(__wrap__merror, formatted_msg, "(1292): Error setting error size.");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);

}

void test_w_logtest_fts_init_create_hash_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 1);

    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1295): Unable to create a new hash (calloc).");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);

}

void test_w_logtest_fts_init_setSize_failure(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;
    OSHash *hash = (OSHash *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 1);

    will_return(__wrap_OSHash_Create, hash);

    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 0);

    expect_string(__wrap__merror, formatted_msg, "(1292): Error setting error size.");

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 0);

}

void test_w_logtest_fts_init_success(void **state)
{
    OSList *fts_list;
    OSHash *fts_store;
    OSList *list = (OSList *) 1;
    OSHash *hash = (OSHash *) 1;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 1);

    will_return(__wrap_OSHash_Create, hash);

    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 1);

}

/* w_logtest_remove_session */
void test_w_logtest_remove_session_fail(void **state)
{
    char * key = "test";

    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, NULL);

    w_logtest_remove_session(key);

}

void test_w_logtest_remove_session_OK(void **state)
{
    char * key = "test";
    w_logtest_session_t *session;
    os_calloc(1, sizeof(w_logtest_session_t), session);

    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, session);

    will_return(__wrap_OSStore_Free, session->decoder_store);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);

    w_logtest_remove_session(key);

}

/* w_logtest_check_inactive_sessions */
void test_w_logtest_check_inactive_sessions_no_remove(void **state)
{

    w_logtest_connection_t connection;
    const int active_session = 5;
    connection.active_client = active_session;

    w_logtest_session_t *session;
    os_calloc(1, sizeof(w_logtest_session_t), session);
    session->last_connection = 1;

    OSHashNode *hash_node;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    hash_node->key = "test";
    hash_node->data = session;

    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_sleep, 0);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_OSHash_Begin, hash_node);

    will_return(__wrap_pthread_mutex_lock, 0);
    
    will_return(__wrap_time, NULL);

    will_return(__wrap_difftime, 1);

    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_FOREVER, 0);

    will_return(__wrap_pthread_mutex_unlock, 0);

    w_logtest_check_inactive_sessions(&connection);

    assert_int_equal(connection.active_client, active_session);

    os_free(session);
    os_free(hash_node);

}

void test_w_logtest_check_inactive_sessions_remove(void **state)
{

    w_logtest_connection_t connection;
    const int active_session = 5;
    connection.active_client = active_session;

    w_logtest_session_t *session;
    os_calloc(1, sizeof(w_logtest_session_t), session);
    session->last_connection = 1;

    OSHashNode *hash_node;
    os_calloc(1, sizeof(OSHashNode), hash_node);
    hash_node->key = "test";
    hash_node->data = session;

    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_sleep, 0);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_OSHash_Begin, hash_node);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_time, NULL);

    will_return(__wrap_difftime, 1000000);

    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_OSHash_Next, NULL);

    // test_w_logtest_remove_session_ok
    char * key = "test";

    expect_value(__wrap_OSHash_Delete_ex, key, "test");
    will_return(__wrap_OSHash_Delete_ex, session);

    will_return(__wrap_OSStore_Free, NULL);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);


    will_return(__wrap_FOREVER, 0);

    will_return(__wrap_pthread_mutex_unlock, 0);

    w_logtest_check_inactive_sessions(&connection);

    assert_int_equal(connection.active_client, active_session - 1);

    os_free(hash_node);

}

/* w_logtest_register_session */
void test_w_logtest_register_session_dont_remove(void ** state) {
    w_logtest_connection_t connection;
    const int active_session = 5;

    connection.active_client = active_session;
    w_logtest_conf.max_sessions = active_session + 1;

    w_logtest_session_t session;
    w_strdup("test", session.token);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_pthread_mutex_unlock, 0);

    expect_value(__wrap_OSHash_Add_ex, hash, w_logtest_sessions);
    expect_value(__wrap_OSHash_Add_ex, key, session.token);
    expect_value(__wrap_OSHash_Add_ex, data, &session);
    will_return(__wrap_OSHash_Add_ex, 0);

    w_logtest_register_session(&connection, &session);

    assert_int_equal(connection.active_client, active_session + 1);

    os_free(session.token)
}

void test_w_logtest_register_session_remove_old(void ** state) {
    w_logtest_connection_t connection;
    const int active_session = 5;

    connection.active_client = active_session;
    w_logtest_conf.max_sessions = active_session;

    /* New session */
    w_logtest_session_t session;
    w_strdup("new_session", session.token);

    /* Oldest session */
    w_logtest_session_t * old_session;
    os_calloc(1, sizeof(w_logtest_session_t), old_session);
    old_session->expired = 0;
    old_session->last_connection = 100;
    w_strdup("old_session", old_session->token);
    OSHashNode * hash_node_old;
    os_calloc(1, sizeof(OSHashNode), hash_node_old);
    w_strdup("old_session", hash_node_old->key);
    hash_node_old->data = old_session;

    /* Other session */
    w_logtest_session_t other_session;
    other_session.expired = 0;
    other_session.last_connection = 300;
    OSHashNode * hash_node_other;
    os_calloc(1, sizeof(OSHashNode), hash_node_other);
    w_strdup("other_session", hash_node_other->key);
    hash_node_other->data = &other_session;

    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_OSHash_Begin, hash_node_other);
    will_return(__wrap_OSHash_Next, hash_node_old);

    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_pthread_mutex_unlock, 0);
    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_OSHash_Next, NULL);

    /* w_logtest_remove_session */
    expect_value(__wrap_OSHash_Delete_ex, key, old_session->token);
    will_return(__wrap_OSHash_Delete_ex, old_session);

    will_return(__wrap_OSStore_Free, NULL);

    will_return(__wrap_OSHash_Free, old_session);

    will_return(__wrap_OSHash_Free, old_session);

    will_return(__wrap_OSHash_Free, old_session);

    will_return(__wrap_pthread_mutex_unlock, 0);

    expect_value(__wrap_OSHash_Add_ex, hash, w_logtest_sessions);
    expect_value(__wrap_OSHash_Add_ex, key, session.token);
    expect_value(__wrap_OSHash_Add_ex, data, &session);
    will_return(__wrap_OSHash_Add_ex, 0);

    w_logtest_register_session(&connection, &session);
    assert_int_equal(connection.active_client, active_session);

    os_free(session.token);
    os_free(hash_node_other->key);
    os_free(hash_node_old->key);
    os_free(hash_node_other);
    os_free(hash_node_old);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests w_logtest_init_parameters
        cmocka_unit_test(test_w_logtest_init_parameters_invalid),
        cmocka_unit_test(test_w_logtest_init_parameters_done),
        // Tests w_logtest_init
        cmocka_unit_test(test_w_logtest_init_error_parameters),
        cmocka_unit_test(test_w_logtest_init_logtest_disabled),
        cmocka_unit_test(test_w_logtest_init_conection_fail),
        cmocka_unit_test(test_w_logtest_init_OSHash_create_fail),
        // Tests w_logtest_fts_init
        cmocka_unit_test(test_w_logtest_fts_init_create_list_failure),
        cmocka_unit_test(test_w_logtest_fts_init_SetMaxSize_failure),
        cmocka_unit_test(test_w_logtest_fts_init_create_hash_failure),
        cmocka_unit_test(test_w_logtest_fts_init_setSize_failure),
        cmocka_unit_test(test_w_logtest_fts_init_success),
        // Tests w_logtest_remove_session
        cmocka_unit_test(test_w_logtest_remove_session_fail),
        cmocka_unit_test(test_w_logtest_remove_session_OK),
        // Tests w_logtest_check_inactive_sessions
        cmocka_unit_test(test_w_logtest_check_inactive_sessions_no_remove),
        cmocka_unit_test(test_w_logtest_check_inactive_sessions_remove),
        // Test w_logtest_register_session
        cmocka_unit_test(test_w_logtest_register_session_dont_remove),
        cmocka_unit_test(test_w_logtest_register_session_remove_old),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
