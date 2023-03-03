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

#include "../../headers/shared.h"
#include "../../analysisd/logtest.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_xml/os_xml_wrappers.h"

int w_logtest_init_parameters();
void * w_logtest_init();
void w_logtest_remove_session(char * token);
void w_logtest_register_session(w_logtest_connection_t * connection, w_logtest_session_t * session);
void w_logtest_remove_old_session(w_logtest_connection_t * connection);
void * w_logtest_check_inactive_sessions(w_logtest_connection_t * connection);
int w_logtest_fts_init(OSList ** fts_list, OSHash ** fts_store);
w_logtest_session_t * w_logtest_initialize_session(OSList * list_msg);
char * w_logtest_generate_token();
void w_logtest_add_msg_response(cJSON * response, OSList * list_msg, int * error_code);
int w_logtest_check_input(char * input_json, cJSON ** req, char ** command_value, char ** msg, OSList * list_msg);
int w_logtest_check_input_request(cJSON * root, char ** msg, OSList * list_msg);
int w_logtest_check_input_remove_session(cJSON * root, char ** msg);
char * w_logtest_process_request(char * raw_request, w_logtest_connection_t * connection);
char * w_logtest_generate_error_response(char * msg);
int w_logtest_preprocessing_phase(Eventinfo * lf, cJSON * request);
void w_logtest_decoding_phase(Eventinfo * lf, w_logtest_session_t * session);
int w_logtest_rulesmatching_phase(Eventinfo * lf, w_logtest_session_t * session,
                                  cJSON * rules_debug_list,
                                  OSList * list_msg);
cJSON *w_logtest_process_log(cJSON * request, w_logtest_session_t * session,
                              w_logtest_extra_data_t * extra_data,
                              OSList * list_msg);
int w_logtest_process_request_remove_session(cJSON * json_request, cJSON * json_response, OSList * list_msg,
                                             w_logtest_connection_t * connection);
void * w_logtest_clients_handler(w_logtest_connection_t * connection);
int w_logtest_process_request_log_processing(cJSON * json_request, cJSON * json_response, OSList * list_msg,
                                             w_logtest_connection_t * connection);
void w_logtest_ruleset_free_config (_Config * ruleset_config);
bool w_logtest_ruleset_load_config(OS_XML * xml, XML_NODE conf_section_nodes,
                                  _Config * ruleset_config, OSList * list_msg);

int logtest_enabled = 1;

int w_logtest_conf_threads = 1;

int random_bytes_result = 0;

char * cJSON_error_ptr = NULL;

bool session_load_acm_store = false;

bool refill_OS_CleanMSG =  false;
OSDecoderInfo * decoder_CleanMSG;

Eventinfo * event_OS_AddEvent = NULL;

w_logtest_session_t * stored_session = NULL;
bool store_session = false;

extern OSHash *w_logtest_sessions;

int session_level_alert = 7;

/* setup/teardown */

static int setup_group(void **state) {
    w_logtest_sessions = (OSHash *) 8;
    return 0;
}

/* wraps */

int __wrap_OS_BindUnixDomain(const char *path, int type, int max_msg_size) {
    return mock();
}

int __wrap_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len) {
    return mock_type(int);
}

void __wrap__os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func,
                                    const char * file, char * msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(level);
    check_expected_ptr(list);
    check_expected(formatted_msg);
}

int __wrap_CreateThreadJoinable(pthread_t *lthread, void * (*function_pointer)(void *), void *data)
{
    return mock_type(int);
}

int __wrap_CreateThread(void * (*function_pointer)(void *), void *data)
{
    return mock_type(int);
}

int __wrap_pthread_join (pthread_t __th, void **__thread_return) {
    return mock_type(int);
}

int __wrap_unlink(const char *file) {
    check_expected_ptr(file);
    return mock();
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

int __wrap_pthread_mutex_trylock(pthread_mutex_t *mutex) {
    return mock();
}

int __wrap_pthread_rwlock_init() {
    return mock();
}

int __wrap_pthread_rwlock_wrlock(pthread_rwlock_t * mutex) {
    return mock_type(int);
}

int __wrap_pthread_rwlock_rdlock(pthread_rwlock_t * mutex) {
    return mock_type(int);
}

int __wrap_pthread_rwlock_unlock(pthread_rwlock_t * mutex) {
    return mock_type(int);
}

int __wrap_ReadConfig(int modules, const char *cfgfile, void *d1, void *d2) {
    if (!logtest_enabled) {
        w_logtest_conf.enabled = false;
    }
    w_logtest_conf.threads = w_logtest_conf_threads;
    return mock();
}

OSHash *__wrap_OSHash_Create() {
    return mock_type(OSHash *);
}

int __wrap_OSHash_setSize(OSHash *self, unsigned int new_size) {
    if (new_size) check_expected(new_size);
    return mock();
}

void __wrap_w_analysisd_accumulate_free(OSHash **acm_store) {
    return;
}

void __wrap_OSList_CleanOnlyNodes(OSList *list) {
    return;
}

int __wrap_OSHash_SetFreeDataPointer(OSHash *self, void (free_data_function)(void *)) {
    return mock_type(int);
}

OSList *__wrap_OSList_Create() {
    return mock_type(OSList *);
}

OSListNode *__wrap_OSList_GetFirstNode(OSList * list) {
    return mock_type(OSListNode *);
}

int __wrap_OSList_SetMaxSize() {
    return mock();
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

void * __wrap_OSHash_Delete(OSHash *self, const char *key) {
    if (key) check_expected(key);
    return mock_type(void *);
}

int __wrap_OSHash_Add_ex(OSHash *hash, const char *key, void *data) {

    if (key) check_expected(key);
    if (data) check_expected(data);
    if (data && store_session) stored_session = (w_logtest_session_t *) data;
    return mock_type(int);
}

int __wrap_OSHash_Add(OSHash *hash, const char *key, void *data) {

    if (key) check_expected(key);
    if (data) check_expected(data);
    if (data && store_session) stored_session = (w_logtest_session_t *) data;
    return mock_type(int);
}

void * __wrap_OSHash_Get_ex(OSHash *self, const char *key) {
    if (key) check_expected(key);
    return mock_type(void *);
}

void * __wrap_OSHash_Get(OSHash *self, const char *key) {
    if (key) check_expected(key);
    return mock_type(void *);
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
    os_free(list);
    return;
}

int __wrap_Read_Rules(XML_NODE node, void * configp, void * list) {

    int retval = mock_type(int);
    _Config * ruleset = (_Config *) configp;

    if (retval < 0) {
        return retval;
    }

    ruleset->decoders = calloc(2, sizeof(char *));
    os_strdup("test_decoder.xml", ruleset->decoders[0]);

    ruleset->lists = calloc(2, sizeof(char *));
    os_strdup("test_list.xml", ruleset->lists[0]);

    ruleset->includes = calloc(2, sizeof(char *));
    os_strdup("test_rule.xml", ruleset->includes[0]);

    return retval;
}

int __wrap_Read_Alerts(XML_NODE node, void * configp, void * list) {
    int retval = mock_type(int);
    _Config * ruleset = (_Config *) configp;

    if (retval < 0) {
        return retval;
    }

    ruleset->logbylevel = session_level_alert;
    return retval;
}

unsigned int __wrap_sleep (unsigned int __seconds) {
    return mock_type(unsigned int);
}

OSHashNode *__wrap_OSHash_Begin(const OSHash *self, unsigned int *i) {
    return mock_type(OSHashNode *);
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

void __wrap_OS_CreateEventList(int maxsize, EventList *list) {
    return;
}

int __wrap_ReadDecodeXML(const char *file, OSDecoderNode **decoderlist_pn,
                        OSDecoderNode **decoderlist_nopn, OSStore **decoder_list,
                        OSList* log_msg) {
    int retval = mock_type(int);

    if (retval > 0) {
        *decoder_list = (OSStore *) 1;
    }
    return retval;
}

int __wrap_SetDecodeXML(OSList* log_msg, OSStore **decoder_list,
                        OSDecoderNode **decoderlist_npn, OSDecoderNode **decoderlist_pn) {
    return mock_type(int);
}

int __wrap_Lists_OP_LoadList(char * files, ListNode ** cdblistnode, OSList * msg) {
    return mock_type(int);
}

void __wrap_Lists_OP_MakeAll(int force, int show_message, ListNode **lnode) {
    return;
}

int __wrap_Rules_OP_ReadRules(char * file, RuleNode ** rule_list, ListNode ** cbd , EventList ** evet, OSList * msg) {
    return mock_type(int);
}

void __wrap_OS_ListLoadRules(ListNode **l_node, ListRule **lrule) {
    return;
}

int __wrap__setlevels(RuleNode *node, int nnode) {
    return mock_type(int);
}

int __wrap_AddHash_Rule(RuleNode *node) {
    return mock_type(int);
}

int __wrap_Accumulate_Init(OSHash **acm_store, int *acm_lookups, time_t *acm_purge_ts) {
    if (session_load_acm_store) {
        *acm_store = (OSHash *) 8;
    }
    return mock_type(int);
}

void __wrap_randombytes(void * ptr, size_t length) {
    check_expected(length);
    *((int32_t *) ptr) = random_bytes_result;
    return;
}

cJSON * __wrap_cJSON_ParseWithOpts(const char *value, const char **return_parse_end,
                                   cJSON_bool require_null_terminated) {
    *return_parse_end = cJSON_error_ptr;
    return mock_type(cJSON *);
}

cJSON* __wrap_cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string) {
    return mock_type(cJSON *);
}

cJSON * __wrap_cJSON_GetObjectItemCaseSensitive(const cJSON * const object, const char * const string) {
    return mock_type(cJSON *);
}

cJSON * __wrap_cJSON_GetObjectItem(const cJSON * const object, const char * const string) {
    return mock_type(cJSON *);
}

char * __wrap_cJSON_GetStringValue(cJSON *item) {
    return mock_type(char *);
}

int __wrap_OS_CleanMSG(char *msg, Eventinfo *lf) {
    if (refill_OS_CleanMSG) {
        lf->program_name = strdup ("test program name");
        lf->is_a_copy = 1;
        lf->log = msg;
        lf->decoder_info = decoder_CleanMSG;
    }

    return mock_type(int);
}

Eventinfo * __wrap_Accumulate(Eventinfo *lf, OSHash **acm_store, int *acm_lookups, time_t *acm_purge_ts) {
    return lf;
}

char* __wrap_ParseRuleComment(Eventinfo *lf) {
    return mock_type(char *);
}

cJSON* __wrap_cJSON_AddBoolToObject(cJSON * const object, const char * const name, const cJSON_bool boolean) {
    return mock_type(cJSON *);
}

cJSON_bool __wrap_cJSON_IsNumber(const cJSON * const item) {
    return mock_type(cJSON_bool);
}

cJSON_bool __wrap_cJSON_IsObject(const cJSON * const item) {
    return mock_type(cJSON_bool);
}

cJSON * __wrap_cJSON_CreateArray() {
    return mock_type(cJSON *);
}

cJSON * __wrap_cJSON_CreateObject() {
    return mock_type(cJSON *);
}

cJSON * __wrap_cJSON_AddNumberToObject(cJSON * const object, const char * const name, const double number) {
    check_expected(number);
    check_expected(name);
    return mock_type(cJSON *);
}

char * __wrap_cJSON_PrintUnformatted(const cJSON *item){
    return mock_type(char *);
}

void __wrap_cJSON_Delete(cJSON *item){
    return;
}

cJSON_bool __wrap_cJSON_IsString(const cJSON * const item) {
    return mock_type(cJSON_bool);
}

void __wrap_cJSON_DeleteItemFromObjectCaseSensitive(cJSON *object, const char *string){
    return;
}

void __wrap_cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item){
    check_expected(object);
    check_expected(string);
    return;
}

cJSON * __wrap_cJSON_CreateString(const char *string){
    return mock_type(cJSON *);
}

void __wrap_cJSON_AddItemToArray(cJSON *array, cJSON *item) {
    return;
}

cJSON * __wrap_cJSON_Parse(const char *value) {
    return mock_type(cJSON *);
}

char *__wrap_Eventinfo_to_jsonstr(const Eventinfo *lf, bool force_full_log){
    return mock_type(char *);
}

void __wrap_os_analysisd_free_log_msg(os_analysisd_log_msg_t * log_msg) {
    os_free(log_msg->file);
    os_free(log_msg->func);
    os_free(log_msg->msg);
    os_free(log_msg);
    return;
}

char * __wrap_os_analysisd_string_log_msg(os_analysisd_log_msg_t * log_msg) {
    return mock_type(char *);
}

void __wrap_OSList_DeleteCurrentlyNode(OSList *list) {
    if (list) {
        os_free(list->cur_node)
    }
    return;
}

int __wrap_wm_strcat(char **str1, const char *str2, char sep) {
    if(*str1 == NULL){
        os_calloc(4 , sizeof(char), *str1);
    }
    check_expected(str2);
    return mock_type(int);
}

void __wrap_DecodeEvent(struct _Eventinfo *lf, OSHash *rules_hash, regex_matching *decoder_match, OSDecoderNode *node) {
    check_expected(node);
}

RuleInfo * __wrap_OS_CheckIfRuleMatch(struct _Eventinfo *lf, EventList *last_events,
                                      ListNode **cdblists, RuleNode *curr_node,
                                      regex_matching *rule_match, OSList **fts_list,
                                      OSHash **fts_store) {
    return mock_type(RuleInfo *);
}

void __wrap_OS_AddEvent(Eventinfo *lf, EventList *list) {
    event_OS_AddEvent = lf;
    return;
}

int __wrap_IGnore(Eventinfo *lf, int pos) {
    return mock_type(int);
}

void * __wrap_OSList_AddData(OSList *list, void *data) {
    return mock_type(void *);
}

int __wrap_OS_RecvSecureTCP(int sock, char * ret,uint32_t size) {
       return mock_type(int);
}

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void * msg) {
    return mock_type(int);
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

    expect_string(__wrap__merror, formatted_msg, "(7300): Unable to bind to socket 'queue/sockets/logtest'. Errno: (0) Success");

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

    will_return(__wrap_OSHash_Create, 8);

    expect_in_range(__wrap_OSHash_setSize, new_size, 1, 400);
    will_return(__wrap_OSHash_setSize, NULL);

    expect_string(__wrap__merror, formatted_msg, "(7305): Failure to resize all_sessions hash");

    w_logtest_init();

}

void test_w_logtest_init_pthread_fail(void **state)
{
    w_logtest_conf_threads = 2;
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SUCCESS);

    will_return(__wrap_OSHash_Create, 8);

    expect_in_range(__wrap_OSHash_setSize, new_size, 1, 400);
    will_return(__wrap_OSHash_setSize, 1);

    will_return(__wrap_pthread_mutex_init, 0);

    expect_string(__wrap__minfo, formatted_msg, "(7200): Logtest started");

    will_return(__wrap_CreateThreadJoinable, -1);

    expect_string(__wrap__merror_exit, formatted_msg, "(1109): Unable to create new pthread.");

    expect_assert_failure(w_logtest_init());
    w_logtest_conf_threads = 1;

}

void test_w_logtest_init_unlink_fail(void **state)
{
    w_logtest_conf_threads = 1;
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SUCCESS);

    will_return(__wrap_OSHash_Create, 8);

    expect_in_range(__wrap_OSHash_setSize, new_size, 1, 400);
    will_return(__wrap_OSHash_setSize, 1);

    will_return(__wrap_pthread_mutex_init, 0);

    expect_string(__wrap__minfo, formatted_msg, "(7200): Logtest started");

    will_return(__wrap_CreateThread, 1);

    //w_logtest_clients_handler
    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_accept, 5);

    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7314): Failure to receive message: empty or reception timeout");

    will_return(__wrap_close, 0);
    will_return(__wrap_FOREVER, 0);


    will_return(__wrap_close, 0);

    expect_string(__wrap_unlink, file, LOGTEST_SOCK);
    will_return(__wrap_unlink, 1);

    char msg[OS_SIZE_4096];
    errno = EBUSY;
    snprintf(msg, OS_SIZE_4096, "(1129): Could not unlink file '%s' due to [(%d)-(%s)].",
            LOGTEST_SOCK, errno, strerror(errno));

    expect_string(__wrap__merror, formatted_msg, msg);

    will_return(__wrap_pthread_mutex_destroy, 0);

    w_logtest_init();
    w_logtest_conf_threads = 1;

}

void test_w_logtest_init_done(void **state)
{
    w_logtest_conf_threads = 1;
    will_return(__wrap_ReadConfig, 0);

    will_return(__wrap_OS_BindUnixDomain, OS_SUCCESS);

    will_return(__wrap_OSHash_Create, 8);

    expect_in_range(__wrap_OSHash_setSize, new_size, 1, 400);
    will_return(__wrap_OSHash_setSize, 1);

    will_return(__wrap_pthread_mutex_init, 0);

    expect_string(__wrap__minfo, formatted_msg, "(7200): Logtest started");

    will_return(__wrap_CreateThread, 1);

    //w_logtest_clients_handler
    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_accept, 5);

    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7314): Failure to receive message: empty or reception timeout");

    will_return(__wrap_close, 0);
    will_return(__wrap_FOREVER, 0);


    will_return(__wrap_close, 0);

    expect_string(__wrap_unlink, file, LOGTEST_SOCK);
    will_return(__wrap_unlink, 0);


    will_return(__wrap_pthread_mutex_destroy, 0);

    w_logtest_init();
    w_logtest_conf_threads = 1;

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
    OSList *list = (OSList *) 8;

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
    OSList *list = (OSList *) 8;

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
    OSList *list = (OSList *) 8;
    OSHash *hash = (OSHash *) 8;

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
    OSList *list = (OSList *) 8;
    OSHash *hash = (OSHash *) 8;

    will_return(__wrap_getDefine_Int, 5);

    will_return(__wrap_OSList_Create, list);

    will_return(__wrap_OSList_SetMaxSize, 1);

    will_return(__wrap_OSHash_Create, hash);

    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    int ret = w_logtest_fts_init(&fts_list, &fts_store);
    assert_int_equal(ret, 1);

}

/* w_logtest_remove_session */
void test_w_logtest_remove_session_fail(void **state)
{
    char * key = "test";

    expect_value(__wrap_OSHash_Delete, key, "test");
    will_return(__wrap_OSHash_Delete, NULL);

    w_logtest_remove_session(key);

}

void test_w_logtest_remove_session_OK(void **state)
{
    char * key = "test";
    w_logtest_session_t *session;
    os_calloc(1, sizeof(w_logtest_session_t), session);

    expect_value(__wrap_OSHash_Delete, key, "test");
    will_return(__wrap_OSHash_Delete, session);

    will_return(__wrap_OSStore_Free, session->decoder_store);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_pthread_mutex_destroy, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7206): The session 'test' was closed successfully");

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

    will_return(__wrap_pthread_rwlock_wrlock, 0);

    will_return(__wrap_OSHash_Begin, hash_node);

    will_return(__wrap_time, NULL);

    will_return(__wrap_difftime, 1);

    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_pthread_rwlock_unlock, 0);

    will_return(__wrap_FOREVER, 0);

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

    will_return(__wrap_pthread_rwlock_wrlock, 0);

    will_return(__wrap_OSHash_Begin, hash_node);

    will_return(__wrap_time, NULL);

    will_return(__wrap_difftime, 1000000);

    will_return(__wrap_pthread_mutex_trylock, 0);

    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_OSHash_Next, NULL);

    // test_w_logtest_remove_session_ok
    char * key = "test";

    expect_value(__wrap_OSHash_Delete, key, "test");
    will_return(__wrap_OSHash_Delete, session);

    will_return(__wrap_OSStore_Free, NULL);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_pthread_mutex_destroy, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7206): The session 'test' was closed successfully");

    will_return(__wrap_FOREVER, 0);

    will_return(__wrap_pthread_rwlock_unlock, 0);


    w_logtest_check_inactive_sessions(&connection);

    assert_int_equal(connection.active_client, active_session - 1);

    os_free(hash_node);

}

/* w_logtest_remove_old_session */
void test_w_logtest_remove_old_session_Begin_fail(void ** state) {

    w_logtest_connection_t connection;

    connection.active_client = 2;
    w_logtest_conf.max_sessions = 1;

    will_return(__wrap_OSHash_Begin, NULL);

    w_logtest_remove_old_session(&connection);

}

void test_w_logtest_remove_old_session_one(void ** state) {

    w_logtest_connection_t connection;

    connection.active_client = 2;
    w_logtest_conf.max_sessions = 1;

    /* Oldest session */
    w_logtest_session_t * old_session;
    os_calloc(1, sizeof(w_logtest_session_t), old_session);
    old_session->last_connection = 100;
    w_strdup("old_session", old_session->token);
    OSHashNode * hash_node_old;
    os_calloc(1, sizeof(OSHashNode), hash_node_old);
    w_strdup("old_session", hash_node_old->key);
    hash_node_old->data = old_session;

    will_return(__wrap_OSHash_Begin, hash_node_old);
    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_pthread_mutex_unlock, 0);

    /* Remove session */
    expect_string(__wrap_OSHash_Delete, key, "old_session");
    will_return(__wrap_OSHash_Delete, old_session);

    will_return(__wrap_OSStore_Free, old_session->decoder_store);

    will_return(__wrap_OSHash_Free, old_session);

    will_return(__wrap_OSHash_Free, old_session);

    will_return(__wrap_pthread_mutex_destroy, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7206): The session 'old_session' was closed successfully");


    w_logtest_remove_old_session(&connection);

    assert_int_equal(connection.active_client, w_logtest_conf.max_sessions);

    os_free(hash_node_old->key);
    os_free(hash_node_old);
}

void test_w_logtest_remove_old_session_many(void ** state) {

    w_logtest_connection_t connection;

    connection.active_client = 3;
    w_logtest_conf.max_sessions = 2;

    /* Oldest session */
    w_logtest_session_t * old_session;
    os_calloc(1, sizeof(w_logtest_session_t), old_session);
    old_session->last_connection = 100;
    w_strdup("old_session", old_session->token);
    OSHashNode * hash_node_old;
    os_calloc(1, sizeof(OSHashNode), hash_node_old);
    w_strdup("old_session", hash_node_old->key);
    hash_node_old->data = old_session;

    /* Other session */
    w_logtest_session_t other_session;
    other_session.last_connection = 300;
    OSHashNode * hash_node_other;
    os_calloc(1, sizeof(OSHashNode), hash_node_other);
    w_strdup("other_session", hash_node_other->key);
    hash_node_other->data = &other_session;

    will_return(__wrap_OSHash_Begin, hash_node_other);
    will_return(__wrap_OSHash_Next, hash_node_old);

    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_pthread_mutex_unlock, 0);
    /* w_logtest_remove_session */
    expect_value(__wrap_OSHash_Delete, key, old_session->token);
    will_return(__wrap_OSHash_Delete, old_session);

    will_return(__wrap_OSStore_Free, NULL);

    will_return(__wrap_OSHash_Free, old_session);

    will_return(__wrap_OSHash_Free, old_session);

    will_return(__wrap_pthread_mutex_destroy, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7206): The session 'old_session' was closed successfully");

    w_logtest_remove_old_session(&connection);
    assert_int_equal(connection.active_client, w_logtest_conf.max_sessions);

    os_free(hash_node_other->key);
    os_free(hash_node_old->key);
    os_free(hash_node_other);
    os_free(hash_node_old);
}

/* w_logtest_register_session */
void test_w_logtest_register_session_dont_remove(void ** state) {
    w_logtest_connection_t connection;
    const int active_session = 5;

    connection.active_client = active_session;
    w_logtest_conf.max_sessions = active_session + 1;

    w_logtest_session_t session;
    w_strdup("test", session.token);

    expect_value(__wrap_OSHash_Add, key, session.token);
    expect_value(__wrap_OSHash_Add, data, &session);
    will_return(__wrap_OSHash_Add, 0);

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
    old_session->last_connection = 100;
    w_strdup("old_session", old_session->token);
    OSHashNode * hash_node_old;
    os_calloc(1, sizeof(OSHashNode), hash_node_old);
    w_strdup("old_session", hash_node_old->key);
    hash_node_old->data = old_session;

    /* Other session */
    w_logtest_session_t other_session;
    other_session.last_connection = 300;
    OSHashNode * hash_node_other;
    os_calloc(1, sizeof(OSHashNode), hash_node_other);
    w_strdup("other_session", hash_node_other->key);
    hash_node_other->data = &other_session;

    will_return(__wrap_OSHash_Begin, hash_node_other);
    will_return(__wrap_OSHash_Next, hash_node_old);

    will_return(__wrap_OSHash_Next, NULL);

    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_pthread_mutex_unlock, 0);

    /* w_logtest_remove_session */
    expect_value(__wrap_OSHash_Delete, key, old_session->token);
    will_return(__wrap_OSHash_Delete, old_session);

    will_return(__wrap_OSStore_Free, NULL);

    will_return(__wrap_OSHash_Free, old_session);

    will_return(__wrap_OSHash_Free, old_session);

    will_return(__wrap_pthread_mutex_destroy, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7206): The session 'old_session' was closed successfully");

    expect_value(__wrap_OSHash_Add, key, session.token);
    expect_value(__wrap_OSHash_Add, data, &session);
    will_return(__wrap_OSHash_Add, 0);


    w_logtest_register_session(&connection, &session);
    assert_int_equal(connection.active_client, active_session);

    os_free(session.token);
    os_free(hash_node_other->key);
    os_free(hash_node_old->key);
    os_free(hash_node_other);
    os_free(hash_node_old);
}

/* w_logtest_initialize_session */
void test_w_logtest_initialize_session_error_load_ruleset(void ** state) {
    char * token = strdup("test");
    OSList * msg = (OSList *) 8;
    w_logtest_session_t * session;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    /* w_logtest_ruleset_load */
    will_return(__wrap_OS_ReadXML, -1);
    will_return(__wrap_OS_ReadXML, "unknown");
    will_return(__wrap_OS_ReadXML, 5);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(1226): Error reading XML file 'etc/ossec.conf': "
                  "unknown (line 5).");

    will_return(__wrap_pthread_mutex_destroy, 0);

    session = w_logtest_initialize_session(msg);

    assert_null(session);

    os_free(token);
}

void test_w_logtest_initialize_session_error_decoders(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 8;
    w_logtest_session_t * session;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    will_return(__wrap_ReadDecodeXML, 0);


    will_return(__wrap_pthread_mutex_destroy, 0);

    session = w_logtest_initialize_session(msg);

    assert_null(session);

    os_free(token);
}

void test_w_logtest_initialize_session_error_set_decoders(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 1;
    w_logtest_session_t * session;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);


    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    will_return(__wrap_OSStore_Free, (OSStore *) 8);

    will_return(__wrap_pthread_mutex_destroy, 0);

    session = w_logtest_initialize_session(msg);

    assert_null(session);
    os_free(token);
}

void test_w_logtest_initialize_session_error_cbd_list(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 8;
    w_logtest_session_t * session;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);


    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 1);
    will_return(__wrap_Lists_OP_LoadList, -1);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    will_return(__wrap_OSStore_Free, (OSStore *) 8);

    will_return(__wrap_pthread_mutex_destroy, 0);

    session = w_logtest_initialize_session(msg);

    assert_null(session);
    os_free(token);
}

void test_w_logtest_initialize_session_error_rules(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 8;
    w_logtest_session_t * session;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 1);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, -1);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    will_return(__wrap_OSStore_Free, (OSStore *) 8);

    will_return(__wrap_pthread_mutex_destroy, 0);

    session = w_logtest_initialize_session(msg);

    assert_null(session);
    os_free(token);
}

void test_w_logtest_initialize_session_error_hash_rules(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 8;
    w_logtest_session_t * session;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 1);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 0);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    will_return(__wrap_OSStore_Free, (OSStore *) 8);

    will_return(__wrap_pthread_mutex_destroy, 0);

    session = w_logtest_initialize_session(msg);

    assert_null(session);

    os_free(token);
}

void test_w_logtest_initialize_session_error_fts_init(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 8;
    w_logtest_session_t * session;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 1);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 8);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init fail */
    OSList * fts_list;
    OSHash * fts_store;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1290): Unable to create a new list (calloc).");

    // test_w_logtest_remove_session_ok_error_FTS_INIT
    will_return(__wrap_OSStore_Free, (OSStore *) 8);
    will_return(__wrap_OSHash_Free, (OSHash *) 0);

    will_return(__wrap_pthread_mutex_destroy, 0);

    session = w_logtest_initialize_session(msg);

    assert_null(session);

    os_free(token);
}

void test_w_logtest_initialize_session_error_accumulate_init(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 8;
    w_logtest_session_t * session;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 1);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 8);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list;
    os_calloc(1, sizeof(OSList), list);
    OSHash * hash = (OSHash *) 8;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    will_return(__wrap_Accumulate_Init, 0);

    // test_w_logtest_remove_session_ok_error_acm
    will_return(__wrap_OSStore_Free, (OSStore *) 8);
    will_return(__wrap_OSHash_Free, (OSStore *) 8);
    will_return(__wrap_OSHash_Free, (OSStore *) 8);

    will_return(__wrap_OSHash_Free, (OSStore *) 8);
    will_return(__wrap_pthread_mutex_destroy, 0);

    session_load_acm_store = true;

    session = w_logtest_initialize_session(msg);

    session_load_acm_store = false;

    assert_null(session);

    os_free(token);
}

void test_w_logtest_initialize_session_success(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 8;
    w_logtest_session_t * session;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 1212);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 1);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 8);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list = (OSList *) 8;
    OSHash * hash = (OSHash *) 8;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    will_return(__wrap_Accumulate_Init, 1);

    session = w_logtest_initialize_session(msg);

    assert_non_null(session);
    assert_int_equal(session->last_connection, 1212);

    os_free(token);
    os_free(session->eventlist);
    os_free(session->token);
    os_free(session);

}

void test_w_logtest_initialize_session_success_duplicate_key(void ** state) {

    char * token = strdup("test");
    OSList * msg = (OSList *) 8;
    w_logtest_session_t * session;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, (void *) 8);

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_time, 1212);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 1);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 8);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list = (OSList *) 8;
    OSHash * hash = (OSHash *) 8;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);

    will_return(__wrap_Accumulate_Init, 1);

    session = w_logtest_initialize_session(msg);

    assert_non_null(session);
    assert_int_equal(session->last_connection, 1212);

    os_free(token);
    os_free(session->eventlist);
    os_free(session->token);
    os_free(session);
}
/* w_logtest_generate_token */
void test_w_logtest_generate_token_success(void ** state) {

    char * token = NULL;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    token = w_logtest_generate_token();

    assert_non_null(token);
    assert_string_equal(token, "4995f9b3");

    os_free(token);
}

void test_w_logtest_generate_token_success_empty_bytes(void ** state) {

    char * token = NULL;

    random_bytes_result = 5555; // 0x15_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    token = w_logtest_generate_token();

    assert_non_null(token);
    assert_string_equal(token, "000015b3");

    os_free(token);
}

void test_w_logtest_add_msg_response_null_list(void ** state) {
    cJSON * response;
    OSList * list_msg;
    int retval = 0;
    const int ret_expect = retval;

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);

}

void test_w_logtest_add_msg_response_new_field_msg(void ** state) {
    cJSON * response = (cJSON*) 8;
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    const int ret_expect = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval = 999;

    cJSON * json_arr_msg = (cJSON*) 2;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_CreateArray, (cJSON*) 8);

    expect_value(__wrap_cJSON_AddItemToObject, object, response);
    expect_string(__wrap_cJSON_AddItemToObject, string, "messages");

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);
    os_free(list_msg);
}

void test_w_logtest_add_msg_response_error_msg(void ** state) {
    cJSON * response = (cJSON*) 8;
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    const int ret_expect = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval = 999;

    cJSON * json_arr_msg = (cJSON*) 2;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);
    os_free(list_msg);
}

void test_w_logtest_add_msg_response_warn_msg(void ** state) {
    cJSON * response = (cJSON*) 8;;
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    const int ret_expect = W_LOGTEST_RCODE_WARNING;
    int retval = W_LOGTEST_RCODE_SUCCESS;

    cJSON * json_arr_msg = (cJSON*) 2;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_WARNING;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "WARNING: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);
    os_free(list_msg);
}

void test_w_logtest_add_msg_response_warn_dont_remplaze_error_msg(void ** state) {
    cJSON * response = (cJSON*) 8;
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    const int ret_expect = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval = W_LOGTEST_RCODE_ERROR_PROCESS;

    cJSON * json_arr_msg = (cJSON*) 2;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_WARNING;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "WARNING: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);
    os_free(list_msg);
}

void test_w_logtest_add_msg_response_info_msg(void ** state) {
    cJSON * response = (cJSON*) 8;;
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    const int ret_expect = 999;
    int retval = ret_expect;

    cJSON * json_arr_msg = (cJSON*) 2;

    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_INFO;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "INFO: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    w_logtest_add_msg_response(response, list_msg, &retval);

    assert_int_equal(retval, ret_expect);
    os_free(list_msg);

}

/* w_logtest_check_input */
void test_w_logtest_check_input_malformed_json_long(void ** state) {

    char * input_raw_json = strdup("Test_input_json|_long<error>Test_i|nput_json_long");
    int pos_error = 25;
    char expect_slice_json[] = "|_long<error>Test_i|";

    int retval;
    const int ret_expect = W_LOGTEST_CODE_ERROR_PARSING;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;
    char ** command_value = (char **) 3;
    char * msg = NULL;

    cJSON_error_ptr = input_raw_json + pos_error;
    will_return(__wrap_cJSON_ParseWithOpts, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7307): Error parsing JSON in position 25, ... |_long<error>Test_i| ...");


    retval = w_logtest_check_input(input_raw_json, &request, command_value, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_string_equal("(7307): Error parsing JSON in position 25, ... |_long<error>Test_i| ...", msg);

    os_free(input_raw_json);
    os_free(msg);
}

void test_w_logtest_check_input_malformed_json_short(void ** state) {

    char * input_raw_json = strdup("json<err>json");
    int pos_error = 7;
    char expect_slice_json[] = "json<err>json";

    int retval;
    const int ret_expect = W_LOGTEST_CODE_ERROR_PARSING;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;
    char ** command_value = (char **) 3;
    char * msg = NULL;

    cJSON_error_ptr = input_raw_json + pos_error;
    will_return(__wrap_cJSON_ParseWithOpts, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7307): Error parsing JSON in position 7, ... json<err>json ...");


    retval = w_logtest_check_input(input_raw_json, &request, command_value, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_string_equal("(7307): Error parsing JSON in position 7, ... json<err>json ...", msg);

    os_free(input_raw_json);
    os_free(msg);
}

void test_w_logtest_check_input_parameter_not_found(void ** state) {

    char * input_raw_json = (char *) 8;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;
    char ** command_value = (char **) 3;
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_INVALID_JSON;

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7313): 'parameters' JSON field not found");


    retval = w_logtest_check_input(input_raw_json, &request, command_value, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_string_equal("(7313): 'parameters' JSON field not found", msg);

    os_free(msg);

}

void test_w_logtest_check_input_parameter_bad_type(void ** state) {

    char * input_raw_json = (char *) 8;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;
    char ** command_value = (char **) 3;
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_INVALID_JSON;

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsObject, (cJSON *) 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7317): 'parameters' JSON field value is not valid");


    retval = w_logtest_check_input(input_raw_json, &request, command_value, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_string_equal("(7317): 'parameters' JSON field value is not valid", msg);

    os_free(msg);

}

void test_w_logtest_check_input_command_not_found(void ** state) {

    char * input_raw_json = (char *) 8;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;
    char ** command_value = (char **) 3;
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_INVALID_JSON;

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsObject, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7313): 'command' JSON field not found");


    retval = w_logtest_check_input(input_raw_json, &request, command_value, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_string_equal("(7313): 'command' JSON field not found", msg);

    os_free(msg);

}

void test_w_logtest_check_input_command_bad_type(void ** state) {

    char * input_raw_json = (char *) 8;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;
    char * command_value;
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_INVALID_JSON;

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsObject, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7317): 'command' JSON field value is not valid");


    retval = w_logtest_check_input(input_raw_json, &request, &command_value, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_string_equal("(7317): 'command' JSON field value is not valid", msg);

    os_free(msg);

}

void test_w_logtest_check_input_invalid_command(void ** state) {

    char * input_raw_json = (char *) 8;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;
    char * command_value;
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_COMMAND_NOT_ALLOWED;

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsObject, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, "invalid_command");

    expect_string(__wrap__mdebug1, formatted_msg, "(7306): Unable to process command");


    retval = w_logtest_check_input(input_raw_json, &request, &command_value, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_string_equal("(7306): Unable to process command", msg);

    os_free(msg);

}

void test_w_logtest_check_input_type_remove_sesion_ok(void ** state) {

    char * input_raw_json = (char *) 8;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;
    char * command_value;
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_SUCCESS;

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsObject, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, "remove_session");

    // w_logtest_check_input_remove_session ok
    cJSON token = {0};
    token.valuestring = strdup("12345678");

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);

    assert_int_equal(W_LOGTEST_TOKEN_LENGH, strlen(token.valuestring));

    retval = w_logtest_check_input(input_raw_json, &request, &command_value, &msg, list_msg);

    assert_string_equal(command_value, "remove_session");
    assert_int_equal(retval, ret_expect);
    os_free(token.valuestring);

}

void test_w_logtest_check_input_type_request_ok(void ** state) {

    char * input_raw_json = strdup("{input json}");
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_SUCCESS;

    cJSON * request;
    OSList * list_msg = (OSList *) 2;
    char * command;

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsObject, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, "log_processing");

    // w_logtest_check_input_request ok
    /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    /* The optional parameters */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    retval = w_logtest_check_input(input_raw_json, &request, &command, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_null(msg);
    assert_string_equal(command, "log_processing");
    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(event.valuestring);
    os_free(input_raw_json);

}

// w_logtest_check_input_request
void test_w_logtest_check_input_request_empty_json(void ** state) {

    cJSON root = {0};
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_INVALID_JSON;

    OSList * list_msg = (OSList *) 2;

    /* location */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7308): 'location' JSON field is required and must be a string");


    retval = w_logtest_check_input_request(&root, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_string_equal(msg, "(7308): 'location' JSON field is required and must be a string");
    os_free(msg);
}

void test_w_logtest_check_input_request_missing_location(void ** state) {

    cJSON root = {0};
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_INVALID_JSON;

    OSList * list_msg = (OSList *) 2;

    /* location */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7308): 'location' JSON field is required and must be a string");


    retval = w_logtest_check_input_request(&root, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_string_equal(msg, "(7308): 'location' JSON field is required and must be a string");
    os_free(msg);
}

void test_w_logtest_check_input_request_missing_log_format(void ** state) {

    cJSON root = {0};
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_INVALID_JSON;

    OSList * list_msg = (OSList *) 2;

    /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);
    will_return(__wrap_cJSON_IsString, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7308): 'log_format' JSON field is required and must be a string");

    retval = retval = w_logtest_check_input_request(&root, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    os_free(location.valuestring);
    os_free(msg);
}

void test_w_logtest_check_input_request_missing_event(void ** state) {

    cJSON root = {0};
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_INVALID_JSON;

    OSList * list_msg = (OSList *) 2;

    /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7313): 'event' JSON field not found");

    retval = w_logtest_check_input_request(&root, &msg, list_msg);

    assert_string_equal(msg, "(7313): 'event' JSON field not found");
    assert_int_equal(retval, ret_expect);
    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(msg);
}

void test_w_logtest_check_input_request_invalid_event(void ** state) {

    cJSON root = {0};
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_INVALID_JSON;

    OSList * list_msg = (OSList *) 2;

    /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsString, false);
    will_return(__wrap_cJSON_IsObject, false);

    expect_string(__wrap__mdebug1, formatted_msg, "(7317): 'event' JSON field value is not valid");

    retval = w_logtest_check_input_request(&root, &msg, list_msg);

    assert_string_equal(msg, "(7317): 'event' JSON field value is not valid");
    assert_int_equal(retval, ret_expect);
    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(msg);
}

void test_w_logtest_check_input_request_full(void ** state) {

    cJSON root = {0};
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_SUCCESS;

    OSList * list_msg = (OSList *) 2;

    /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    cJSON token = {0};
    token.valuestring = strdup("12345678");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, true);
    will_return(__wrap_cJSON_IsString, true);

    /* The optional parameters */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    retval = w_logtest_check_input_request(&root, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_null(msg);
    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(event.valuestring);
    os_free(token.valuestring);
}

void test_w_logtest_check_input_request_full_empty_token(void ** state) {

    cJSON root = {0};
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_SUCCESS;

    OSList * list_msg = (OSList *) 2;

   /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    /* The optional parameters */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    retval = w_logtest_check_input_request(&root, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_null(msg);
    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(event.valuestring);
}

void test_w_logtest_check_input_request_bad_token_lenght(void ** state) {

    cJSON root = {0};
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_SUCCESS;

    OSList * list_msg = (OSList *) 2;

   /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    cJSON token = {0};
    token.valuestring = strdup("1234");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, true);
    will_return(__wrap_cJSON_IsString, true);
    will_return(__wrap_cJSON_IsString, true);

    expect_string(__wrap__mdebug1, formatted_msg, "(7309): '1234' is not a valid token");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7309): '1234' is not a valid token");

    /* The optional parameters */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    retval = w_logtest_check_input_request(&root, &msg, list_msg);

    assert_null(msg);
    assert_int_equal(retval, ret_expect);
    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(event.valuestring);
    os_free(token.valuestring);
}

void test_w_logtest_check_input_request_bad_token_type(void ** state) {

    cJSON root = {0};
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_SUCCESS;

    OSList * list_msg = (OSList *) 2;

   /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    cJSON token = {0};
    token.type = cJSON_Number;
    token.valueint = 1234;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, false);

    will_return(__wrap_cJSON_IsString, false);

    will_return(__wrap_cJSON_PrintUnformatted, strdup("1234"));

    expect_string(__wrap__mdebug1, formatted_msg, "(7309): '1234' is not a valid token");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7309): '1234' is not a valid token");

    /* The optional parameters */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    retval = w_logtest_check_input_request(&root, &msg, list_msg);

    assert_null(msg);
    assert_int_equal(retval, ret_expect);
    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(event.valuestring);
}

void test_w_logtest_check_input_request_debug_rules(void ** state) {

    cJSON root = {0};
    char * msg = NULL;

    int retval;
    const int ret_expect = W_LOGTEST_CODE_SUCCESS;
    OSList * list_msg = (OSList *) 2;

    /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    cJSON token = {0};
    token.valuestring = strdup("12345678");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, true);
    will_return(__wrap_cJSON_IsString, true);

    /* The optional parameters */
    cJSON options = {0};
    options.valuestring = strdup("options");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &options);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7005): 'options' field must be a JSON object. The parameter will be ignored");
    will_return(__wrap_cJSON_IsObject, 0);

    retval = w_logtest_check_input_request(&root, &msg, list_msg);

    assert_int_equal(retval, ret_expect);
    assert_null(msg);
    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(event.valuestring);
    os_free(token.valuestring);
    os_free(options.valuestring)
}


// w_logtest_check_input_remove_session
void test_w_logtest_check_input_remove_session_not_string(void ** state)
{
    cJSON root = {0};
    char * msg = NULL;

    const int expected_retval = W_LOGTEST_CODE_INVALID_TOKEN;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 0);

    expect_string(__wrap__mdebug1, formatted_msg,
        "(7316): Failure to remove session. token JSON field must be a string");

    retval = w_logtest_check_input_remove_session(&root, &msg);

    assert_int_equal(retval, expected_retval);
    assert_string_equal(msg, "(7316): Failure to remove session. token JSON field must be a string");

    os_free(msg);

}

void test_w_logtest_check_input_remove_session_invalid_token(void ** state)
{
    cJSON root = {0};
    cJSON token = {0};
    token.valuestring = strdup("1234567");
    char * msg = NULL;

    const int expected_retval = W_LOGTEST_CODE_INVALID_TOKEN;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);

    expect_string(__wrap__mdebug1, formatted_msg, "(7309): '1234567' is not a valid token");

    assert_int_not_equal(W_LOGTEST_TOKEN_LENGH, strlen(token.valuestring));
    retval = w_logtest_check_input_remove_session(&root, &msg);

    assert_int_equal(retval, expected_retval);
    assert_string_equal(msg, "(7309): '1234567' is not a valid token");

    os_free(token.valuestring);
    os_free(msg);
}

void test_w_logtest_check_input_remove_session_ok(void ** state)
{
    cJSON root = {0};
    cJSON token = {0};
    token.valuestring = strdup("12345678");
    char * msg = NULL;

    const int expected_retval = W_LOGTEST_CODE_SUCCESS;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);

    assert_int_equal(W_LOGTEST_TOKEN_LENGH, strlen(token.valuestring));

    retval = w_logtest_check_input_remove_session(&root, &msg);

    assert_null(msg);
    assert_int_equal(retval, expected_retval);
    os_free(token.valuestring);
}

/* w_logtest_process_request */
void test_w_logtest_process_request_error_list(void ** state) {

    char raw_request[] = "Test request";
    w_logtest_connection_t connection;
    char * retval;

    will_return(__wrap_OSList_Create, NULL);
    expect_string(__wrap__merror, formatted_msg, "(1290): Unable to create a new list (calloc).");

    retval = w_logtest_process_request(raw_request, &connection);

    assert_null(retval);

}

void test_w_logtest_process_request_error_check_input(void ** state) {

    char * retval;
    w_logtest_connection_t connection;


    /* w_logtest_add_msg_response */
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);

    /* w_logtest_process_request */
    will_return(__wrap_OSList_Create, list_msg);
    will_return(__wrap_OSList_SetMaxSize, 0);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 8);
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 8);

    /* Error w_logtest_check_input */
    char * input_raw_json = strdup("Test request");
    int pos_error = 7;
    cJSON_error_ptr = input_raw_json + pos_error;

    will_return(__wrap_cJSON_ParseWithOpts, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7307): Error parsing JSON in position 7, ... Test request ...");

    /* w_logtest_process_request */
    will_return(__wrap_cJSON_AddStringToObject, NULL);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 1);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_any(__wrap_cJSON_AddItemToObject, object);
    expect_string(__wrap_cJSON_AddItemToObject, string, "data");

    will_return(__wrap_cJSON_PrintUnformatted, "{json response}");

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_pthread_mutex_unlock, 0);
    will_return(__wrap_pthread_rwlock_unlock, 0);
    will_return(__wrap_pthread_mutex_destroy, 0);

    retval = w_logtest_process_request(input_raw_json, &connection);

    assert_string_equal(retval, "{json response}");

    os_free(input_raw_json);
    cJSON_error_ptr = NULL;

}

void test_w_logtest_process_request_type_remove_session_ok(void ** state) {

    char * retval;
    char * input_raw_json = strdup("Test request");

    /* w_logtest_add_msg_response */
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);

    /* w_logtest_process_request */
    will_return(__wrap_OSList_Create, list_msg);
    will_return(__wrap_OSList_SetMaxSize, 0);
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 8);
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 8);

    /* w_logtest_check_input */
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, "remove_session");

    // w_logtest_check_input_remove_session ok
    cJSON token = {0};
    token.valuestring = strdup("12345678");

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);

    /* w_logtest_process_request_remove_session_fail */
    w_logtest_connection_t connection = {0};
    connection.active_client = 5;
    cJSON parameters = {0};

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &parameters);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7316): Failure to remove session. token JSON field must be a string");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7316): Failure to remove session. token JSON field must be a string");


    /*w_logtest_add_msg_response error*/
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    OSListNode * list_msg_node;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    /* w_logtest_process_request */
    expect_string(__wrap_cJSON_AddNumberToObject, name, "codemsg");
    expect_value(__wrap_cJSON_AddNumberToObject, number, -1);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_any(__wrap_cJSON_AddItemToObject, object);
    expect_string(__wrap_cJSON_AddItemToObject, string, "data");

    will_return(__wrap_cJSON_PrintUnformatted, "{json response}");

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_pthread_mutex_unlock, 0);
    will_return(__wrap_pthread_rwlock_unlock, 0);
    will_return(__wrap_pthread_mutex_destroy, 0);

    retval = w_logtest_process_request(input_raw_json, &connection);

    assert_string_equal(retval, "{json response}");

    os_free(input_raw_json);
    os_free(token.valuestring);

}

void test_w_logtest_process_request_type_log_processing(void ** state) {

    char * retval;
    char * input_raw_json = strdup("Test request");

    w_logtest_connection_t connection = {0};
    connection.active_client = 5;

    /* w_logtest_add_msg_response */
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);

    /* w_logtest_process_request */
    will_return(__wrap_OSList_Create, list_msg);
    will_return(__wrap_OSList_SetMaxSize, 0);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 8);
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 8);

    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsObject, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, "log_processing");

    // w_logtest_check_input_requeset ok
    /* location */
    cJSON location = {0};
    location.valuestring = strdup("location str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &location);
    will_return(__wrap_cJSON_IsString, true);

    /* log_format */
    cJSON log_format = {0};
    log_format.valuestring = strdup("log format str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &log_format);
    will_return(__wrap_cJSON_IsString, true);

    /* event */
    cJSON event = {0};
    event.valuestring = strdup("event str");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &event);
    will_return(__wrap_cJSON_IsString, true);

    /* token */
    cJSON token = {0};
    token.valuestring = strdup("12345678");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, true);
    will_return(__wrap_cJSON_IsString, true);

    /* The optional parameters */
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    /* w_logtest_process_request */
    cJSON parameters = {0};
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &parameters);

    /* log processing fail get session*/
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    /* Generate token */
    random_bytes_result = 5555; // 0x00_00_15_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "000015b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    /* Initialize session*/
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    will_return(__wrap_ReadDecodeXML, 0);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    will_return(__wrap_pthread_mutex_destroy, 0);


    /* w_logtest_get_session */
    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7311): Failure to initializing session");

    expect_string(__wrap__mdebug1, formatted_msg, "(7311): Failure to initializing session");


    /*w_logtest_add_msg_response error*/
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    OSListNode * list_msg_node;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "codemsg");
    expect_value(__wrap_cJSON_AddNumberToObject, number, -1);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_any(__wrap_cJSON_AddItemToObject, object);
    expect_string(__wrap_cJSON_AddItemToObject, string, "data");

    will_return(__wrap_cJSON_PrintUnformatted, "{json response}");

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_pthread_mutex_unlock, 0);
    will_return(__wrap_pthread_rwlock_unlock, 0);
    will_return(__wrap_pthread_mutex_destroy, 0);

    retval = w_logtest_process_request(input_raw_json, &connection);

    os_free(location.valuestring);
    os_free(log_format.valuestring);
    os_free(event.valuestring);
    os_free(token.valuestring);
    os_free(input_raw_json);

}

// test_w_logtest_generate_error_response_ok
void test_w_logtest_generate_error_response_ok(void ** state) {
    const char * retval_exp = "{json response}";
    char * retval;

    cJSON response = {0};

    will_return(__wrap_cJSON_CreateObject, &response);
    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    expect_value(__wrap_cJSON_AddItemToObject, object, &response);
    expect_string(__wrap_cJSON_AddItemToObject, string, "message");

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 5);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    will_return(__wrap_cJSON_PrintUnformatted, "{json response}");

    retval = w_logtest_generate_error_response("test msg");

    assert_string_equal(retval_exp, retval);
}

// Tests w_logtest_decoding_phase
void test_w_logtest_decoding_phase_program_name(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};

    lf.program_name = strdup("program name test");
    os_calloc(1, sizeof(OSDecoderNode), session.decoderlist_forpname);

    expect_value(__wrap_DecodeEvent, node, session.decoderlist_forpname);
    w_logtest_decoding_phase(&lf, &session);

    os_free(lf.program_name);
    os_free(session.decoderlist_forpname);

}

void test_w_logtest_decoding_phase_no_program_name(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};

    lf.program_name = NULL;
    os_calloc(1, sizeof(OSDecoderNode), session.decoderlist_nopname);

    expect_value(__wrap_DecodeEvent, node, session.decoderlist_nopname);
    w_logtest_decoding_phase(&lf, &session);

    os_free(session.decoderlist_nopname);
}

// w_logtest_preprocessing_phase
void test_w_logtest_preprocessing_phase_json_location_to_scape_ok(void ** state)
{
    Eventinfo lf = {0};
    cJSON request = {0};

    cJSON json_event = {0};
    cJSON json_event_child = {0};
    char * raw_event = strdup("{event}");
    char * str_location = strdup("loc:at\\ion");

    lf.log = strdup("{event}");

    json_event.child = &json_event_child;


    const int expect_retval = 0;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_PrintUnformatted, raw_event);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    will_return(__wrap_OS_CleanMSG, 0);


    retval = w_logtest_preprocessing_phase(&lf, &request);

    assert_int_equal(retval, expect_retval);


    os_free(str_location);
    os_free(lf.log);


}

void test_w_logtest_preprocessing_phase_json_event_ok(void ** state)
{
    Eventinfo lf = {0};
    cJSON request = {0};

    cJSON json_event = {0};
    cJSON json_event_child = {0};
    char * raw_event = strdup("{event}");
    char * str_location = strdup("location");

    lf.log = strdup("{event}");

    json_event.child = &json_event_child;


    const int expect_retval = 0;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_PrintUnformatted, raw_event);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    will_return(__wrap_OS_CleanMSG, 0);


    retval = w_logtest_preprocessing_phase(&lf, &request);

    assert_int_equal(retval, expect_retval);


    os_free(str_location);
    os_free(lf.log);


}

void test_w_logtest_preprocessing_phase_json_event_fail(void ** state)
{
    Eventinfo * lf;
    os_calloc(1, sizeof(Eventinfo), lf);

    cJSON request = {0};

    cJSON json_event = {0};
    cJSON json_event_child = {0};
    char * raw_event = strdup("{event}");
    char * str_location = strdup("location");

    json_event.child = &json_event_child;


    const int expect_retval = -1;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_PrintUnformatted, raw_event);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    will_return(__wrap_OS_CleanMSG, -1);


    retval = w_logtest_preprocessing_phase(lf, &request);

    assert_int_equal(retval, expect_retval);

    os_free(str_location);
    Free_Eventinfo(lf);

}

void test_w_logtest_preprocessing_phase_str_event_ok(void ** state)
{
    Eventinfo * lf;
    os_calloc(1, sizeof(Eventinfo), lf);

    cJSON request = {0};
    cJSON json_event = {0};
    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    lf->log = strdup("test log");

    const int expect_retval = 0;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    will_return(__wrap_OS_CleanMSG, 0);


    retval = w_logtest_preprocessing_phase(lf, &request);

    assert_int_equal(retval, expect_retval);

    os_free(str_location);
    os_free(raw_event);
    os_free(lf->log);
    os_free(lf);

}

void test_w_logtest_preprocessing_phase_str_event_fail(void ** state)
{
    Eventinfo * lf;
    os_calloc(1, sizeof(Eventinfo), lf);

    cJSON request = {0};
    cJSON json_event = {0};
    char * raw_event = strdup("event");
    char * str_location = strdup("location");



    const int expect_retval = -1;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    will_return(__wrap_OS_CleanMSG, -1);


    retval = w_logtest_preprocessing_phase(lf, &request);

    assert_int_equal(retval, expect_retval);

    Free_Eventinfo(lf);
    os_free(str_location);
    os_free(raw_event);

}

// w_logtest_rulesmatching_phase
void test_w_logtest_rulesmatching_phase_no_load_rules(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = -1;
    int retval;

    session.rule_list = NULL;

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);


}

void test_w_logtest_rulesmatching_phase_ossec_alert(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 0;
    int retval;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = OSSEC_ALERT;
    lf.generated_rule = NULL;

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);

    os_free(session.rule_list);


}

void test_w_logtest_rulesmatching_phase_dont_match_category(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 0;
    int retval;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.category = FIREWALL;

    assert_int_not_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);

    os_free(session.rule_list);


}

void test_w_logtest_rulesmatching_phase_dont_match(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 0;
    int retval;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.category = SYSLOG;

    assert_int_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_OS_CheckIfRuleMatch, NULL);

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);

    os_free(session.rule_list);


}

void test_w_logtest_rulesmatching_phase_match_level_0(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 0;
    int retval;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.level = 0;
    ruleinfo.category = SYSLOG;

    assert_int_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);
    assert_ptr_equal(lf.generated_rule, &ruleinfo);

    os_free(session.rule_list);

}

void test_w_logtest_rulesmatching_phase_match_dont_ignore_first_time(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 1;
    int retval;

    lf.generate_time = (time_t) 2020;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.level = 5;
    ruleinfo.category = SYSLOG;
    ruleinfo.ignore_time = 1;

    assert_int_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);
    assert_ptr_equal(lf.generated_rule, &ruleinfo);
    assert_ptr_equal(lf.generated_rule->time_ignored, (time_t) 2020);

    os_free(session.rule_list);

}

void test_w_logtest_rulesmatching_phase_match_ignore_time_ignore(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 0;
    int retval;

    lf.generate_time = (time_t) 2020;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.level = 5;
    ruleinfo.category = SYSLOG;
    ruleinfo.ignore_time = 10; // ignore
    ruleinfo.time_ignored = (time_t) 2015;

    assert_int_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);
    assert_ptr_equal(lf.generated_rule, &ruleinfo);

    os_free(session.rule_list);

}

void test_w_logtest_rulesmatching_phase_match_dont_ignore_time_out_windows(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 1;
    int retval;

    lf.generate_time = (time_t) 2020;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.level = 5;
    ruleinfo.category = SYSLOG;
    ruleinfo.ignore_time = 3; // Dont ignore
    ruleinfo.time_ignored = (time_t) 2015;

    assert_int_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);
    assert_ptr_equal(lf.generated_rule, &ruleinfo);
    assert_ptr_equal(lf.generated_rule->time_ignored, (time_t) 0);

    os_free(session.rule_list);

}

void test_w_logtest_rulesmatching_phase_match_ignore_event(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 0;
    int retval;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.level = 5;
    ruleinfo.category = SYSLOG;
    ruleinfo.ckignore = 1;

    assert_int_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);
    will_return(__wrap_IGnore, 1);

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);
    assert_ptr_equal(lf.generated_rule, &ruleinfo);

    os_free(session.rule_list);

}

void test_w_logtest_rulesmatching_phase_match_and_if_matched_sid_ok(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 1;
    int retval;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.level = 5;
    ruleinfo.category = SYSLOG;
    ruleinfo.ckignore = 0;


    OSList pre_matched_list = {0};
    pre_matched_list.last_node = (OSListNode *) 80;
    ruleinfo.sid_prev_matched = &pre_matched_list;

    assert_int_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);
    will_return(__wrap_OSList_AddData, 1);

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);
    assert_ptr_equal(lf.generated_rule, &ruleinfo);
    assert_ptr_equal(lf.sid_node_to_delete, (OSListNode *) 80);

    os_free(session.rule_list);

}

void test_w_logtest_rulesmatching_phase_match_and_if_matched_sid_fail(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 1;
    int retval;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.level = 5;
    ruleinfo.category = SYSLOG;
    ruleinfo.ckignore = 0;

    OSList pre_matched_list = {0};
    pre_matched_list.last_node = (OSListNode *) 80;
    ruleinfo.sid_prev_matched = &pre_matched_list;

    assert_int_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);
    will_return(__wrap_OSList_AddData, 0);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "Unable to add data to sig list.");

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);
    assert_ptr_equal(lf.generated_rule, &ruleinfo);
    assert_ptr_equal(lf.sid_node_to_delete, (OSListNode *) 0);

    os_free(session.rule_list);

}

void test_w_logtest_rulesmatching_phase_match_and_group_prev_matched_fail(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 1;
    int retval;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.level = 5;
    ruleinfo.category = SYSLOG;
    ruleinfo.ckignore = 0;
    ruleinfo.sid_prev_matched = (OSList *) 0;
    ruleinfo.group_prev_matched_sz = 1;
    os_calloc(1, sizeof(RuleInfo *), ruleinfo.group_prev_matched);

    OSList pre_matched_list = {0};
    pre_matched_list.last_node = (OSListNode *) 80;

    assert_int_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);
    will_return(__wrap_OSList_AddData, 0);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "Unable to add data to grp list.");

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);
    assert_ptr_equal(lf.generated_rule, &ruleinfo);
    assert_ptr_equal(lf.sid_node_to_delete, (OSListNode *) 0);

    os_free(session.rule_list);
    os_free(ruleinfo.group_prev_matched);
    os_free(lf.group_node_to_delete);

}

void test_w_logtest_rulesmatching_phase_match_and_group_prev_matched(void ** state)
{
    Eventinfo lf = {0};
    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    const int expect_retval = 1;
    int retval;

    OSDecoderInfo decoder_info = {0};
    lf.decoder_info = &decoder_info;
    decoder_info.type = SYSLOG;
    lf.generated_rule = NULL;

    RuleInfo ruleinfo = {0};
    ruleinfo.level = 5;
    ruleinfo.category = SYSLOG;
    ruleinfo.ckignore = 0;
    ruleinfo.sid_prev_matched = (OSList *) 0;
    ruleinfo.group_prev_matched_sz = 1;
    os_calloc(1, sizeof(RuleInfo *), ruleinfo.group_prev_matched);

    OSList pre_matched_list = {0};
    pre_matched_list.last_node = (OSListNode *) 80;

    assert_int_equal(ruleinfo.category, decoder_info.type);

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);
    will_return(__wrap_OSList_AddData, 1);

    cJSON * rules_debug_list = NULL;

    retval = w_logtest_rulesmatching_phase(&lf, &session, rules_debug_list, &list_msg);

    assert_int_equal(retval, expect_retval);
    assert_ptr_equal(lf.generated_rule, &ruleinfo);

    os_free(lf.group_node_to_delete);
    os_free(session.rule_list);
    os_free(ruleinfo.group_prev_matched);
}

// w_logtest_process_log
void test_w_logtest_process_log_preprocessing_fail(void ** state)
{
    Config.decoder_order_size = 1;

    w_logtest_extra_data_t extra_data;

    extra_data.alert_generated = false;

    cJSON request = {0};
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    w_logtest_session_t session = {0};
    OSList list_msg = {0};

    cJSON * retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    will_return(__wrap_OS_CleanMSG, -1);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1106): String not correctly formatted.");

    retval = w_logtest_process_log(&request, &session, &extra_data, &list_msg);

    assert_null(retval);
    assert_false(extra_data.alert_generated);
    os_free(str_location);
    os_free(raw_event);
}

void test_w_logtest_process_log_rule_match_fail(void ** state)
{
    Config.decoder_order_size = 1;

    w_logtest_extra_data_t extra_data;

    extra_data.alert_generated = false;

    cJSON request = {0};
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    OSDecoderInfo decoder_info = {0};
    decoder_info.accumulate = 0;
    decoder_CleanMSG = &decoder_info;

    cJSON * retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    refill_OS_CleanMSG = true;
    will_return(__wrap_OS_CleanMSG, 0);
    expect_value(__wrap_DecodeEvent, node, session.decoderlist_forpname);

    retval = w_logtest_process_log(&request, &session, &extra_data, &list_msg);

    assert_null(retval);
    assert_false(extra_data.alert_generated);
    os_free(str_location);
    os_free(raw_event);
    refill_OS_CleanMSG = false;

}

void test_w_logtest_process_log_rule_dont_match(void ** state)
{
    Config.decoder_order_size = 1;

    cJSON * output;
    os_calloc(1, sizeof(cJSON), output);

    w_logtest_extra_data_t extra_data;

    extra_data.alert_generated = false;

    cJSON request = {0};
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    OSDecoderInfo decoder_info = {0};
    decoder_info.accumulate = 1;
    decoder_info.type = SYSLOG;
    decoder_CleanMSG = &decoder_info;

    RuleInfo ruleinfo = {0};
    ruleinfo.category = FIREWALL;

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    cJSON * retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    // w_logtest_preprocessing_phase
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    refill_OS_CleanMSG = true;
    will_return(__wrap_OS_CleanMSG, 0);
    // w_logtest_decoding_phase
    expect_value(__wrap_DecodeEvent, node, session.decoderlist_forpname);

    will_return(__wrap_Eventinfo_to_jsonstr, strdup("output example"));
    will_return(__wrap_cJSON_Parse, output);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 0);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 0);

    retval = w_logtest_process_log(&request, &session, &extra_data, &list_msg);

    assert_non_null(retval);
    assert_false(extra_data.alert_generated);
    os_free(str_location);
    os_free(raw_event);
    os_free(session.rule_list);
    refill_OS_CleanMSG = false;
    os_free(output);

}

void test_w_logtest_process_log_rule_match(void ** state)
{
    Config.decoder_order_size = 1;

    w_logtest_extra_data_t extra_data;

    extra_data.alert_generated = false;

    Config.logbylevel = 3;

    cJSON * output;
    os_calloc(1, sizeof(cJSON), output);

    cJSON request = {0};
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    OSDecoderInfo decoder_info = {0};
    decoder_info.accumulate = 1;
    decoder_info.type = SYSLOG;
    decoder_CleanMSG = &decoder_info;

    RuleInfo ruleinfo = {0};
    ruleinfo.category = SYSLOG;
    ruleinfo.level = 10;

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    cJSON * retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    // w_logtest_preprocessing_phase
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    refill_OS_CleanMSG = true;
    will_return(__wrap_OS_CleanMSG, 0);

    // w_logtest_decoding_phase
    expect_value(__wrap_DecodeEvent, node, session.decoderlist_forpname);

    // w_logtest_rulesmatching_phase
    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);

    will_return(__wrap_ParseRuleComment, strdup("Comment test"));

    will_return(__wrap_Eventinfo_to_jsonstr, strdup("output example"));
    will_return(__wrap_cJSON_Parse, output);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    retval = w_logtest_process_log(&request, &session, &extra_data, &list_msg);

    assert_true(extra_data.alert_generated);
    assert_non_null(retval);

    Free_Eventinfo(event_OS_AddEvent);
    os_free(str_location);
    os_free(raw_event);
    os_free(session.rule_list);
    refill_OS_CleanMSG = false;
    os_free(output);
}

void test_w_logtest_process_log_rule_match_level_0(void ** state)
{
    Config.decoder_order_size = 1;

    w_logtest_extra_data_t extra_data;

    extra_data.alert_generated = false;

    Config.logbylevel = 3;

    cJSON * output;
    os_calloc(1, sizeof(cJSON), output);

    cJSON request = {0};
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    w_logtest_session_t session = {0};
    OSList list_msg = {0};
    OSDecoderInfo decoder_info = {0};
    decoder_info.accumulate = 1;
    decoder_info.type = SYSLOG;
    decoder_CleanMSG = &decoder_info;

    RuleInfo ruleinfo = {0};
    ruleinfo.category = SYSLOG;
    ruleinfo.level = 0;

    os_calloc(1, sizeof(RuleNode), session.rule_list);
    session.rule_list->next = NULL;
    session.rule_list->ruleinfo = &ruleinfo;

    cJSON * retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    // w_logtest_preprocessing_phase
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    refill_OS_CleanMSG = true;
    will_return(__wrap_OS_CleanMSG, 0);

    // w_logtest_decoding_phase
    expect_value(__wrap_DecodeEvent, node, session.decoderlist_forpname);

    // w_logtest_rulesmatching_phase
    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);

    will_return(__wrap_ParseRuleComment, strdup("Comment test"));

    will_return(__wrap_Eventinfo_to_jsonstr, strdup("output example"));
    will_return(__wrap_cJSON_Parse, output);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 0);
    expect_string(__wrap_cJSON_AddNumberToObject, name, "level");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    retval = w_logtest_process_log(&request, &session, &extra_data, &list_msg);

    assert_false(extra_data.alert_generated);
    assert_non_null(retval);

    os_free(str_location);
    os_free(raw_event);
    os_free(session.rule_list);
    refill_OS_CleanMSG = false;
    os_free(output);
}

// w_logtest_process_request_remove_session
void test_w_logtest_process_request_remove_session_invalid_token(void ** state)
{
    cJSON * json_request = (cJSON *) 8;
    cJSON * json_response = (cJSON *) 2;
    OSList list_msg = {0};
    OSList mock_list = {0};
    w_logtest_connection_t connection = {0};
    connection.active_client = 5;

    const int expect_retval = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7316): Failure to remove session. token JSON field must be a string");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &mock_list);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7316): Failure to remove session. token JSON field must be a string");


    /*w_logtest_add_msg_response error*/
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    OSListNode * list_msg_node;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg.cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);


    retval = w_logtest_process_request_remove_session(json_request, json_response, &mock_list, &connection);

    assert_int_equal(retval, expect_retval);
    assert_int_equal(connection.active_client, 5);

    os_free(list_msg_node);
}

void test_w_logtest_process_request_remove_session_session_not_found(void ** state)
{
    cJSON * json_request = (cJSON *) 8;
    cJSON * json_response = (cJSON *) 2;
    OSList list_msg = {0};
    w_logtest_connection_t connection = {0};
    connection.active_client = 5;

    cJSON token = {0};
    token.valuestring = "000015b3";

    const int expect_retval = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    expect_string(__wrap_OSHash_Get, key, "000015b3");
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7004): No session found for token '000015b3'");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, NULL);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7004): No session found for token '000015b3'");

    will_return(__wrap_pthread_rwlock_unlock, 0);

    /*w_logtest_add_msg_response error*/
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    OSListNode * list_msg_node;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg.cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);


    retval = w_logtest_process_request_remove_session(json_request, json_response, NULL, &connection);

    assert_int_equal(retval, expect_retval);
    assert_int_equal(connection.active_client, 5);
    os_free(list_msg_node);
}

void test_w_logtest_process_request_remove_session_session_in_use(void ** state)
{
    cJSON * json_request = (cJSON *) 8;
    cJSON * json_response = (cJSON *) 2;
    OSList list_msg = {0};
    w_logtest_connection_t connection = {0};
    connection.active_client = 5;

    cJSON token = {0};
    token.valuestring = "000015b3";

    const int expect_retval = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    expect_string(__wrap_OSHash_Get, key, "000015b3");
    will_return(__wrap_OSHash_Get, (void *) 8);
    will_return(__wrap_pthread_mutex_trylock, EBUSY);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, NULL);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7318): Failure to remove session '000015b3'");

    will_return(__wrap_pthread_rwlock_unlock, 0);

    /*w_logtest_add_msg_response error*/
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    OSListNode * list_msg_node;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg.cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);


    retval = w_logtest_process_request_remove_session(json_request, json_response, NULL, &connection);

    assert_int_equal(retval, expect_retval);
    assert_int_equal(connection.active_client, 5);
    os_free(list_msg_node);
}

void test_w_logtest_process_request_remove_session_ok(void ** state)
{
    cJSON * json_request = (cJSON *) 8;
    cJSON * json_response = (cJSON *) 2;
    OSList list_msg = {0};
    w_logtest_connection_t connection = {0};
    connection.active_client = 5;

    cJSON token = {0};
    token.valuestring = "000015b3";

    w_logtest_session_t *session;
    os_calloc(1, sizeof(w_logtest_session_t), session);

    const int expect_retval = W_LOGTEST_RCODE_SUCCESS;
    int retval;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    expect_string(__wrap_OSHash_Get, key, "000015b3");
    will_return(__wrap_OSHash_Get, session);
    will_return(__wrap_pthread_mutex_trylock, 0);
    will_return(__wrap_pthread_mutex_unlock, 0);

    // remove session ok

    expect_value(__wrap_OSHash_Delete, key, "000015b3");
    will_return(__wrap_OSHash_Delete, session);

    will_return(__wrap_OSStore_Free, session->decoder_store);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_OSHash_Free, session);

    will_return(__wrap_pthread_mutex_destroy, 0);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_INFO);
    expect_value(__wrap__os_analysisd_add_logmsg, list, NULL);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7206): The session '000015b3' was closed successfully");

    expect_string(__wrap__mdebug1, formatted_msg, "(7206): The session '000015b3' was closed successfully");

    will_return(__wrap_pthread_rwlock_unlock, 0);

    /*w_logtest_add_msg_response error*/
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_INFO;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    OSListNode * list_msg_node;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg.cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "INFO: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);


    retval = w_logtest_process_request_remove_session(json_request, json_response, NULL, &connection);

    assert_int_equal(retval, expect_retval);
    assert_int_equal(connection.active_client, 4);

    os_free(list_msg_node);
}

void test_w_logtest_clients_handler_error_acept(void ** state)
{
    w_logtest_connection_t conection = {0};
    char expected_str[OS_SIZE_1024];

    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_accept, -1);

    will_return(__wrap_pthread_mutex_unlock, 0);
    errno = ENOMEM;
    snprintf(expected_str, OS_SIZE_1024, "(7301): Failure to accept connection. Errno: %s", strerror(errno));

    expect_string(__wrap__merror, formatted_msg, expected_str);

    will_return(__wrap_FOREVER, 0);

    assert_null(w_logtest_clients_handler(&conection));

}

void test_w_logtest_clients_handler_error_acept_close_socket(void ** state)
{
    w_logtest_connection_t conection = {0};
    char expected_str[OS_SIZE_1024];

    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_accept, -1);

    will_return(__wrap_pthread_mutex_unlock, 0);
    errno = EBADF;
    snprintf(expected_str, OS_SIZE_1024, "(7301): Failure to accept connection. Errno: %s", strerror(errno));

    expect_string(__wrap__merror, formatted_msg, expected_str);

    assert_null(w_logtest_clients_handler(&conection));

}

void test_w_logtest_clients_handler_recv_error(void ** state)
{
    w_logtest_connection_t conection = {0};
    char expected_str[OS_SIZE_1024];

    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_accept, 5);

    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_OS_RecvSecureTCP, -1);
    errno = ENOTCONN;
    snprintf(expected_str, OS_SIZE_1024, "(7302): Failure to receive message: Errno: %s", strerror(ENOTCONN));

    expect_string(__wrap__mdebug1, formatted_msg, expected_str);

    will_return(__wrap_close, 0);
    will_return(__wrap_FOREVER, 0);


    assert_null(w_logtest_clients_handler(&conection));

}

void test_w_logtest_clients_handler_recv_msg_empty(void ** state)
{
    w_logtest_connection_t conection = {0};

    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_accept, 5);

    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7314): Failure to receive message: empty or reception timeout");

    will_return(__wrap_close, 0);
    will_return(__wrap_FOREVER, 0);


    assert_null(w_logtest_clients_handler(&conection));

}

void test_w_logtest_clients_handler_recv_msg_oversize(void ** state)
{
    w_logtest_connection_t conection = {0};

    will_return(__wrap_FOREVER, 1);

    will_return(__wrap_pthread_mutex_lock, 0);

    will_return(__wrap_accept, 5);

    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_OS_RecvSecureTCP, -6);

    expect_string(__wrap__mdebug1, formatted_msg, "(7315): Failure to receive message: size is bigger than expected");

    // w_logtest_generate_error_response
    cJSON response = {0};
    will_return(__wrap_cJSON_CreateObject, &response);
    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    expect_value(__wrap_cJSON_AddItemToObject, object, &response);
    expect_string(__wrap_cJSON_AddItemToObject, string, "message");

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 5);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    will_return(__wrap_cJSON_PrintUnformatted, strdup("{json response}"));
    will_return(__wrap_OS_SendSecureTCP, 0);

    will_return(__wrap_close, 0);
    will_return(__wrap_FOREVER, 0);


    assert_null(w_logtest_clients_handler(&conection));

}

void test_w_logtest_clients_handler_ok(void ** state)
{
    w_logtest_connection_t conection = {0};

    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_accept, 5);
    will_return(__wrap_pthread_mutex_unlock, 0);
    will_return(__wrap_OS_RecvSecureTCP, 100);

    /* w_logtest_process_request */
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    will_return(__wrap_OSList_Create, list_msg);
    will_return(__wrap_OSList_SetMaxSize, 0);

    will_return(__wrap_cJSON_CreateObject, (cJSON *) 8);
    will_return(__wrap_cJSON_CreateObject, (cJSON *) 8);
    will_return(__wrap_cJSON_ParseWithOpts, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_IsObject, true);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, "remove_session");

    /* w_logtest_check_input_remove_session ok */
    cJSON token = {0};
    token.valuestring = strdup("12345678");

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &token);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);
    will_return(__wrap_cJSON_IsString, (cJSON_bool) 1);

    /* w_logtest_process_request */
    cJSON parameter = {0};
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &parameter);

    /* w_logtest_process_request_remove_session_fail */
    w_logtest_connection_t connection = {0};
    connection.active_client = 5;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "(7316): Failure to remove session. token JSON field must be a string");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7316): Failure to remove session. token JSON field must be a string");


    /*w_logtest_add_msg_response error*/
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    OSListNode * list_msg_node;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    /* w_logtest_process_request */
    expect_string(__wrap_cJSON_AddNumberToObject, name, "codemsg");
    expect_value(__wrap_cJSON_AddNumberToObject, number, -1);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_string(__wrap_cJSON_AddNumberToObject, name, "error");
    expect_value(__wrap_cJSON_AddNumberToObject, number, 0);
    will_return(__wrap_cJSON_AddNumberToObject, NULL);

    expect_any(__wrap_cJSON_AddItemToObject, object);
    expect_string(__wrap_cJSON_AddItemToObject, string, "data");

    will_return(__wrap_cJSON_PrintUnformatted, strdup("{json response}"));

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_pthread_mutex_unlock, 0);
    will_return(__wrap_pthread_rwlock_unlock, 0);
    will_return(__wrap_pthread_mutex_destroy, 0);

    will_return(__wrap_OS_SendSecureTCP, 0);

    will_return(__wrap_close, 0);
    will_return(__wrap_FOREVER, 0);

    assert_null(w_logtest_clients_handler(&conection));

    os_free(token.valuestring);

}

// w_logtest_process_request_log_processing
void test_w_logtest_process_request_log_processing_fail_session(void ** state)
{
    cJSON json_request = {0};
    cJSON json_response = {0};
    OSList list_msg = {0};
    w_logtest_connection_t connection = {0};

    const int extpect_retval = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval;

    // Fail get session
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    /* Generate token */
    random_bytes_result = 5555; // 0x00_00_15_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "000015b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    /* Initialize session*/
    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    will_return(__wrap_time, 0);
    will_return(__wrap_pthread_mutex_init, 0);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    will_return(__wrap_ReadDecodeXML, 0);

    // test_w_logtest_remove_session_ok_error_load_decoder_cbd_rules_hash
    will_return(__wrap_pthread_mutex_destroy, 0);


    /* w_logtest_get_session */
    expect_string(__wrap__mdebug1, formatted_msg, "(7311): Failure to initializing session");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7311): Failure to initializing session");

    /* error w_logtest_add_msg_response */
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_ERROR;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;

    OSListNode * list_msg_node;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg.cur_node = list_msg_node;
    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    retval = w_logtest_process_request_log_processing(&json_request, &json_response, &list_msg, &connection);

    assert_int_equal(extpect_retval, retval);
    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
}

void test_w_logtest_process_request_log_processing_fail_process_log(void ** state)
{
    cJSON json_request = {0};
    cJSON json_response = {0};
    w_logtest_connection_t connection = {0};

    const int extpect_retval = W_LOGTEST_RCODE_ERROR_PROCESS;
    int retval;

    // get session
    cJSON * json_request_token;
    w_logtest_session_t active_session;
    char * token = strdup("test_token");
    const time_t now = (time_t) 2020;

    os_calloc(1, sizeof(cJSON), json_request_token);
    json_request_token->valuestring = token;
    active_session.last_connection = 0;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_request_token);

    will_return(__wrap_pthread_rwlock_wrlock, 0);

    expect_value(__wrap_OSHash_Get, key, token);
    will_return(__wrap_OSHash_Get, &active_session);

    will_return(__wrap_pthread_rwlock_unlock, 0);

    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_time, now);
    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_cJSON_AddStringToObject, NULL);

    /* now msg w_logtest_add_msg_response */
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_INFO;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "INFO: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    /* Fail w_logtest_process_log */
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    will_return(__wrap_OS_CleanMSG, -1);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1106): String not correctly formatted.");

    // w_logtest_process_request_log_processing
    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7312): Failed to process the event");

    expect_string(__wrap__mdebug1, formatted_msg, "(7312): Failed to process the event");

    // w_logtest_add_msg_response
    os_analysisd_log_msg_t * message_error;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message_error);
    message_error->level = LOGLEVEL_ERROR;
    message_error->msg = strdup("Test Message");
    message_error->file = NULL;
    message_error->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message_error;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    retval = w_logtest_process_request_log_processing(&json_request, &json_response, list_msg, &connection);

    assert_int_equal(extpect_retval, retval);

    os_free(token);
    os_free(json_request_token);
    os_free(list_msg_node);
    os_free(list_msg);
    os_free(str_location);
    os_free(raw_event);
}

void test_w_logtest_process_request_log_processing_ok_and_alert(void ** state)
{
    cJSON json_request = {0};
    cJSON json_response = {0};
    w_logtest_connection_t connection = {0};

    const int extpect_retval = W_LOGTEST_RCODE_SUCCESS;
    int retval;

    // get session
    cJSON * json_request_token;
    w_logtest_session_t active_session;
    char * token = strdup("test_token");
    const time_t now = (time_t) 2020;

    os_calloc(1, sizeof(cJSON), json_request_token);
    json_request_token->valuestring = token;
    active_session.last_connection = 0;
    active_session.logbylevel = 3;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_request_token);

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    expect_value(__wrap_OSHash_Get, key, token);
    will_return(__wrap_OSHash_Get, &active_session);
    will_return(__wrap_pthread_rwlock_unlock, 0);

    will_return(__wrap_pthread_mutex_lock, 0);
    will_return(__wrap_time, now);
    will_return(__wrap_pthread_mutex_unlock, 0);

    will_return(__wrap_cJSON_AddStringToObject, NULL);

    /* now msg w_logtest_add_msg_response */
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);
    OSListNode * list_msg_node;
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_INFO;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON*) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "INFO: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    /* Alert w_logtest_process_log */
    Config.decoder_order_size = 1;

    cJSON * output;
    os_calloc(1, sizeof(cJSON), output);

    cJSON request = {0};
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    OSDecoderInfo decoder_info = {0};
    decoder_info.accumulate = 1;
    decoder_info.type = SYSLOG;
    decoder_CleanMSG = &decoder_info;

    RuleInfo ruleinfo = {0};
    ruleinfo.category = SYSLOG;
    ruleinfo.level = 5;

    os_calloc(1, sizeof(RuleNode), active_session.rule_list);
    active_session.rule_list->next = NULL;
    active_session.rule_list->ruleinfo = &ruleinfo;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    // w_logtest_preprocessing_phase
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    refill_OS_CleanMSG = true;
    will_return(__wrap_OS_CleanMSG, 0);

    // w_logtest_decoding_phase
    expect_any(__wrap_DecodeEvent, node);

    // w_logtest_rulesmatching_phase
    will_return(__wrap_OS_CheckIfRuleMatch, &ruleinfo);

    will_return(__wrap_ParseRuleComment, "Comment test");

    will_return(__wrap_Eventinfo_to_jsonstr, strdup("output example"));
    will_return(__wrap_cJSON_Parse, output);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    // w_logtest_process_request_log_processing

    expect_any(__wrap_cJSON_AddItemToObject, object);
    expect_string(__wrap_cJSON_AddItemToObject, string, "output");

    // w_logtest_add_msg_response
    will_return(__wrap_OSList_GetFirstNode, NULL);

    // Alert level
    cJSON * json_level;
    os_calloc(1, sizeof(cJSON), json_level);
    cJSON * json_rule = (cJSON *) 8;
    json_level->valueint = 5;


    will_return(__wrap_cJSON_AddBoolToObject, NULL);

    retval = w_logtest_process_request_log_processing(&json_request, &json_response, list_msg, &connection);

    assert_int_equal(extpect_retval, retval);

    os_free(token);
    os_free(json_request_token);
    os_free(list_msg);
    os_free(str_location);
    os_free(raw_event);
    os_free(json_level);
    os_free(output);
    os_free(active_session.rule_list);
}

void test_w_logtest_process_request_log_processing_ok_session_expired(void ** state) {
    cJSON json_request = {0};
    cJSON json_response = {0};
    w_logtest_connection_t connection = {0};
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);

    const int extpect_retval = -1;
    int retval;

    // get session
    cJSON * json_request_token;
    w_logtest_session_t active_session;
    char * token = strdup("test_token");
    const time_t now = (time_t) 2020;

    os_calloc(1, sizeof(cJSON), json_request_token);
    json_request_token->valuestring = token;
    active_session.last_connection = 0;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_request_token);

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    expect_value(__wrap_OSHash_Get, key, token);
    will_return(__wrap_OSHash_Get, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "(7003): 'test_token' token expires");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7003): 'test_token' token expires");

    will_return(__wrap_pthread_rwlock_unlock, 0);

    // w_logtest_initialize_session

    /* Generate session token */
    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_time, 1212);

    /* w_logtest_ruleset_load */
    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);
    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);
    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 1);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 8);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list = (OSList *) 8;
    OSHash * hash = (OSHash *) 8;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);
    will_return(__wrap_Accumulate_Init, 1);

    will_return(__wrap_pthread_mutex_lock, 0);
    /* w_logtest_register_session */
    will_return(__wrap_pthread_rwlock_wrlock, 0);
    store_session = true;
    expect_string(__wrap_OSHash_Add, key, "4995f9b3");
    expect_any(__wrap_OSHash_Add, data);
    will_return(__wrap_OSHash_Add, 0);
    will_return(__wrap_pthread_rwlock_unlock, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7202): Session initialized with token '4995f9b3'");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_INFO);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7202): Session initialized with token '4995f9b3'");

    /* now msg w_logtest_add_msg_response */
    OSListNode * list_msg_node;
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_INFO;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "INFO: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    will_return(__wrap_cJSON_AddStringToObject, NULL);

    // Optionals parameters
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    /* Alert w_logtest_process_log */
    Config.decoder_order_size = 1;
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    OSDecoderInfo decoder_info = {0};
    decoder_info.accumulate = 1;
    decoder_info.type = SYSLOG;
    decoder_CleanMSG = &decoder_info;


    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    // w_logtest_preprocessing_phase
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    refill_OS_CleanMSG = true;
    will_return(__wrap_OS_CleanMSG, 0);

    // w_logtest_decoding_phase
    expect_any(__wrap_DecodeEvent, node);

    // w_logtest_process_request_log_processing
    will_return(__wrap_pthread_mutex_unlock, 0);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7312): Failed to process the event");

    expect_string(__wrap__mdebug1, formatted_msg, "(7312): Failed to process the event");

    // w_logtest_add_msg_response
    os_analysisd_log_msg_t * message_error;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message_error);
    message_error->level = LOGLEVEL_ERROR;
    message_error->msg = strdup("Test Message");
    message_error->file = NULL;
    message_error->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message_error;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    retval = w_logtest_process_request_log_processing(&json_request, &json_response, list_msg, &connection);

    assert_int_equal(extpect_retval, retval);

    os_free(stored_session->token);
    os_free(stored_session->eventlist);
    os_free(stored_session);
    os_free(token);
    os_free(json_request_token);
    os_free(list_msg);
    os_free(str_location);
    os_free(raw_event);
    os_free(list_msg_node);
    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
    store_session = false;
}

void test_w_logtest_process_request_log_processing_options_without_rules_debug(void ** state) {
    cJSON json_request = {0};
    cJSON json_response = {0};
    w_logtest_connection_t connection = {0};
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);

    const int extpect_retval = -1;
    int retval;

    // get session
    cJSON * json_request_token;
    w_logtest_session_t active_session;
    char * token = strdup("test_token");
    const time_t now = (time_t) 2020;

    os_calloc(1, sizeof(cJSON), json_request_token);
    json_request_token->valuestring = token;
    active_session.last_connection = 0;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_request_token);

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    expect_value(__wrap_OSHash_Get, key, token);
    will_return(__wrap_OSHash_Get, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "(7003): 'test_token' token expires");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7003): 'test_token' token expires");

    will_return(__wrap_pthread_rwlock_unlock, 0);

    // w_logtest_initialize_session

    /* Generate session token */
    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_time, 1212);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 8);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list = (OSList *) 8;
    OSHash * hash = (OSHash *) 8;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);
    will_return(__wrap_Accumulate_Init, 1);

    will_return(__wrap_pthread_mutex_lock, 0);
    /* w_logtest_register_session */
    will_return(__wrap_pthread_rwlock_wrlock, 0);
    store_session = true;
    expect_string(__wrap_OSHash_Add, key, "4995f9b3");
    expect_any(__wrap_OSHash_Add, data);
    will_return(__wrap_OSHash_Add, 0);
    will_return(__wrap_pthread_rwlock_unlock, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7202): Session initialized with token '4995f9b3'");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_INFO);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7202): Session initialized with token '4995f9b3'");

    /* now msg w_logtest_add_msg_response */
    OSListNode * list_msg_node;
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_INFO;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "INFO: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    will_return(__wrap_cJSON_AddStringToObject, NULL);

    // Optional parameters
    cJSON options = {0};
    options.valuestring = strdup("options");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &options);

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, NULL);

    /* Alert w_logtest_process_log */
    Config.decoder_order_size = 1;
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    OSDecoderInfo decoder_info = {0};
    decoder_info.accumulate = 1;
    decoder_info.type = SYSLOG;
    decoder_CleanMSG = &decoder_info;


    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    // w_logtest_preprocessing_phase
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    refill_OS_CleanMSG = true;
    will_return(__wrap_OS_CleanMSG, 0);

    // w_logtest_decoding_phase
    expect_any(__wrap_DecodeEvent, node);

    // w_logtest_process_request_log_processing
    will_return(__wrap_pthread_mutex_unlock, 0);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7312): Failed to process the event");

    expect_string(__wrap__mdebug1, formatted_msg, "(7312): Failed to process the event");

    // w_logtest_add_msg_response
    os_analysisd_log_msg_t * message_error;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message_error);
    message_error->level = LOGLEVEL_ERROR;
    message_error->msg = strdup("Test Message");
    message_error->file = NULL;
    message_error->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message_error;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    retval = w_logtest_process_request_log_processing(&json_request, &json_response, list_msg, &connection);

    assert_int_equal(extpect_retval, retval);

    os_free(stored_session->token);
    os_free(stored_session->eventlist);
    os_free(stored_session);
    os_free(token);
    os_free(json_request_token);
    os_free(list_msg);
    os_free(str_location);
    os_free(raw_event);
    os_free(list_msg_node);
    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
    os_free(options.valuestring);
    store_session = false;

}

void test_w_logtest_process_request_log_processing_rules_debug_not_bolean(void ** state) {
    cJSON json_request = {0};
    cJSON json_response = {0};
    w_logtest_connection_t connection = {0};
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);

    const int extpect_retval = -1;
    int retval;

    // get session
    cJSON * json_request_token;
    w_logtest_session_t active_session;
    char * token = strdup("test_token");
    const time_t now = (time_t) 2020;

    os_calloc(1, sizeof(cJSON), json_request_token);
    json_request_token->valuestring = token;
    active_session.last_connection = 0;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_request_token);

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    expect_value(__wrap_OSHash_Get, key, token);
    will_return(__wrap_OSHash_Get, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "(7003): 'test_token' token expires");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7003): 'test_token' token expires");

    will_return(__wrap_pthread_rwlock_unlock, 0);

    // w_logtest_initialize_session

    /* Generate session token */
    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_time, 1212);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 8);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list = (OSList *) 8;
    OSHash * hash = (OSHash *) 8;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);
    will_return(__wrap_Accumulate_Init, 1);

    will_return(__wrap_pthread_mutex_lock, 0);
    /* w_logtest_register_session */
    will_return(__wrap_pthread_rwlock_wrlock, 0);
    store_session = true;
    expect_string(__wrap_OSHash_Add, key, "4995f9b3");
    expect_any(__wrap_OSHash_Add, data);
    will_return(__wrap_OSHash_Add, 0);
    will_return(__wrap_pthread_rwlock_unlock, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7202): Session initialized with token '4995f9b3'");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_INFO);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7202): Session initialized with token '4995f9b3'");

    /* now msg w_logtest_add_msg_response */
    OSListNode * list_msg_node;
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_INFO;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "INFO: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    will_return(__wrap_cJSON_AddStringToObject, NULL);

    // Optional parameters
    cJSON options = {0};
    options.valuestring = strdup("options");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &options);

    cJSON rules_debug = {0};
    rules_debug.valuestring = strdup("rules_debug_not_bolean");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &rules_debug);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7006): 'rules_debug' field must be a boolean. The parameter will be ignored");

    /* Alert w_logtest_process_log */
    Config.decoder_order_size = 1;
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    OSDecoderInfo decoder_info = {0};
    decoder_info.accumulate = 1;
    decoder_info.type = SYSLOG;
    decoder_CleanMSG = &decoder_info;


    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    // w_logtest_preprocessing_phase
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    refill_OS_CleanMSG = true;
    will_return(__wrap_OS_CleanMSG, 0);

    // w_logtest_decoding_phase
    expect_any(__wrap_DecodeEvent, node);

    // w_logtest_process_request_log_processing
    will_return(__wrap_pthread_mutex_unlock, 0);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7312): Failed to process the event");

    expect_string(__wrap__mdebug1, formatted_msg, "(7312): Failed to process the event");

    // w_logtest_add_msg_response
    os_analysisd_log_msg_t * message_error;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message_error);
    message_error->level = LOGLEVEL_ERROR;
    message_error->msg = strdup("Test Message");
    message_error->file = NULL;
    message_error->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message_error;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    retval = w_logtest_process_request_log_processing(&json_request, &json_response, list_msg, &connection);

    assert_int_equal(extpect_retval, retval);

    os_free(stored_session->token);
    os_free(stored_session->eventlist);
    os_free(stored_session);
    os_free(token);
    os_free(json_request_token);
    os_free(list_msg);
    os_free(str_location);
    os_free(raw_event);
    os_free(list_msg_node);
    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
    os_free(options.valuestring);
    os_free(rules_debug.valuestring);
    store_session = false;
}

void test_w_logtest_process_request_log_processing_rules_debug_false(void ** state) {
    cJSON json_request = {0};
    cJSON json_response = {0};
    w_logtest_connection_t connection = {0};
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);

    const int extpect_retval = -1;
    int retval;

    // get session
    cJSON * json_request_token;
    w_logtest_session_t active_session;
    char * token = strdup("test_token");
    const time_t now = (time_t) 2020;

    os_calloc(1, sizeof(cJSON), json_request_token);
    json_request_token->valuestring = token;
    active_session.last_connection = 0;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_request_token);

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    expect_value(__wrap_OSHash_Get, key, token);
    will_return(__wrap_OSHash_Get, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "(7003): 'test_token' token expires");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7003): 'test_token' token expires");

    will_return(__wrap_pthread_rwlock_unlock, 0);

    // w_logtest_initialize_session

    /* Generate session token */
    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_time, 1212);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 8);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list = (OSList *) 8;
    OSHash * hash = (OSHash *) 8;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);
    will_return(__wrap_Accumulate_Init, 1);

    will_return(__wrap_pthread_mutex_lock, 0);
    /* w_logtest_register_session */
    will_return(__wrap_pthread_rwlock_wrlock, 0);
    store_session = true;
    expect_string(__wrap_OSHash_Add, key, "4995f9b3");
    expect_any(__wrap_OSHash_Add, data);
    will_return(__wrap_OSHash_Add, 0);
    will_return(__wrap_pthread_rwlock_unlock, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7202): Session initialized with token '4995f9b3'");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_INFO);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7202): Session initialized with token '4995f9b3'");

    /* now msg w_logtest_add_msg_response */
    OSListNode * list_msg_node;
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_INFO;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "INFO: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    will_return(__wrap_cJSON_AddStringToObject, NULL);

    // Optional parameters
    cJSON options = {0};
    options.valuestring = strdup("options");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &options);

    cJSON rules_debug = {0};
    rules_debug.type = 1;
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &rules_debug);

    /* Alert w_logtest_process_log */
    Config.decoder_order_size = 1;
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    OSDecoderInfo decoder_info = {0};
    decoder_info.accumulate = 1;
    decoder_info.type = SYSLOG;
    decoder_CleanMSG = &decoder_info;


    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    // w_logtest_preprocessing_phase
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    refill_OS_CleanMSG = true;
    will_return(__wrap_OS_CleanMSG, 0);

    // w_logtest_decoding_phase
    expect_any(__wrap_DecodeEvent, node);

    // w_logtest_process_request_log_processing
    will_return(__wrap_pthread_mutex_unlock, 0);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7312): Failed to process the event");

    expect_string(__wrap__mdebug1, formatted_msg, "(7312): Failed to process the event");

    // w_logtest_add_msg_response
    os_analysisd_log_msg_t * message_error;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message_error);
    message_error->level = LOGLEVEL_ERROR;
    message_error->msg = strdup("Test Message");
    message_error->file = NULL;
    message_error->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message_error;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    retval = w_logtest_process_request_log_processing(&json_request, &json_response, list_msg, &connection);

    assert_int_equal(extpect_retval, retval);

    os_free(stored_session->token);
    os_free(stored_session->eventlist);
    os_free(stored_session);
    os_free(token);
    os_free(json_request_token);
    os_free(list_msg);
    os_free(str_location);
    os_free(raw_event);
    os_free(list_msg_node);
    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
    os_free(options.valuestring);
    os_free(rules_debug.valuestring);
    store_session = false;
}

void test_w_logtest_process_request_log_processing_rules_debug_true(void ** state) {
    cJSON json_request = {0};
    cJSON json_response = {0};
    w_logtest_connection_t connection = {0};
    OSList * list_msg;
    os_calloc(1, sizeof(OSList), list_msg);

    const int extpect_retval = -1;
    int retval;

    // get session
    cJSON * json_request_token;
    w_logtest_session_t active_session;
    char * token = strdup("test_token");
    const time_t now = (time_t) 2020;

    os_calloc(1, sizeof(cJSON), json_request_token);
    json_request_token->valuestring = token;
    active_session.last_connection = 0;

    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, json_request_token);

    will_return(__wrap_pthread_rwlock_wrlock, 0);
    expect_value(__wrap_OSHash_Get, key, token);
    will_return(__wrap_OSHash_Get, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "(7003): 'test_token' token expires");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7003): 'test_token' token expires");

    will_return(__wrap_pthread_rwlock_unlock, 0);

    // w_logtest_initialize_session

    /* Generate session token */
    char * decoder_file = "test.xml";
    Config.decoders = calloc(2, sizeof(char *));
    Config.decoders[0] = decoder_file;

    char * cbd_file = "test.xml";
    Config.lists = calloc(2, sizeof(char *));
    Config.lists[0] = cbd_file;

    char * include_file = "test.xml";
    Config.includes = calloc(2, sizeof(char *));
    Config.includes[0] = include_file;

    random_bytes_result = 1234565555; // 0x49_95_f9_b3
    expect_value(__wrap_randombytes, length, W_LOGTEST_TOKEN_LENGH >> 1);

    expect_string(__wrap_OSHash_Get_ex, key, "4995f9b3");
    will_return(__wrap_OSHash_Get_ex, NULL);

    will_return(__wrap_pthread_mutex_init, 0);
    will_return(__wrap_time, 1212);
    will_return(__wrap_ReadDecodeXML, 1);
    will_return(__wrap_SetDecodeXML, 0);
    will_return(__wrap_Lists_OP_LoadList, 0);
    will_return(__wrap_Rules_OP_ReadRules, 0);
    will_return(__wrap__setlevels, 0);
    will_return(__wrap_OSHash_Create, 8);
    will_return(__wrap_AddHash_Rule, 0);

    /* FTS init success */
    OSList * fts_list;
    OSHash * fts_store;
    OSList * list = (OSList *) 8;
    OSHash * hash = (OSHash *) 8;
    will_return(__wrap_getDefine_Int, 5);
    will_return(__wrap_OSList_Create, list);
    will_return(__wrap_OSList_SetMaxSize, 1);
    will_return(__wrap_OSHash_Create, hash);
    expect_value(__wrap_OSHash_setSize, new_size, 2048);
    will_return(__wrap_OSHash_setSize, 1);
    will_return(__wrap_OSHash_SetFreeDataPointer, 1);
    will_return(__wrap_Accumulate_Init, 1);

    will_return(__wrap_pthread_mutex_lock, 0);
    /* w_logtest_register_session */
    will_return(__wrap_pthread_rwlock_wrlock, 0);
    store_session = true;
    expect_string(__wrap_OSHash_Add, key, "4995f9b3");
    expect_any(__wrap_OSHash_Add, data);
    will_return(__wrap_OSHash_Add, 0);
    will_return(__wrap_pthread_rwlock_unlock, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(7202): Session initialized with token '4995f9b3'");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_INFO);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7202): Session initialized with token '4995f9b3'");

    /* now msg w_logtest_add_msg_response */
    OSListNode * list_msg_node;
    os_analysisd_log_msg_t * message;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message);
    message->level = LOGLEVEL_INFO;
    message->msg = strdup("Test Message");
    message->file = NULL;
    message->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message;
    list_msg->cur_node = list_msg_node;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "INFO: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    will_return(__wrap_cJSON_AddStringToObject, NULL);

    // Optional parameters
    cJSON options = {0};
    options.valuestring = strdup("options");
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &options);

    cJSON rules_debug = {0};
    rules_debug.type = 2;
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &rules_debug);

    will_return(__wrap_cJSON_CreateArray, (cJSON*) 8);

    /* Alert w_logtest_process_log */
    Config.decoder_order_size = 1;
    cJSON json_event = {0};
    json_event.child = false;

    char * raw_event = strdup("event");
    char * str_location = strdup("location");

    OSDecoderInfo decoder_info = {0};
    decoder_info.accumulate = 1;
    decoder_info.type = SYSLOG;
    decoder_CleanMSG = &decoder_info;


    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, &json_event);
    will_return(__wrap_cJSON_GetStringValue, raw_event);

    // w_logtest_preprocessing_phase
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);
    will_return(__wrap_cJSON_GetStringValue, str_location);

    refill_OS_CleanMSG = true;
    will_return(__wrap_OS_CleanMSG, 0);

    // w_logtest_decoding_phase
    expect_any(__wrap_DecodeEvent, node);

    // w_logtest_process_request_log_processing
    will_return(__wrap_pthread_mutex_unlock, 0);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(7312): Failed to process the event");

    expect_string(__wrap__mdebug1, formatted_msg, "(7312): Failed to process the event");

    expect_any(__wrap_cJSON_AddItemToObject, object);
    expect_string(__wrap_cJSON_AddItemToObject, string, "rules_debug");

    // w_logtest_add_msg_response
    os_analysisd_log_msg_t * message_error;
    os_calloc(1, sizeof(os_analysisd_log_msg_t), message_error);
    message_error->level = LOGLEVEL_ERROR;
    message_error->msg = strdup("Test Message");
    message_error->file = NULL;
    message_error->func = NULL;
    os_calloc(1, sizeof(OSListNode), list_msg_node);
    list_msg_node->data = message_error;

    will_return(__wrap_OSList_GetFirstNode, list_msg_node);
    will_return(__wrap_cJSON_GetObjectItemCaseSensitive, (cJSON *) 8);

    will_return(__wrap_os_analysisd_string_log_msg, strdup("Test Message"));

    expect_string(__wrap_wm_strcat, str2, "ERROR: ");
    will_return(__wrap_wm_strcat, 0);

    expect_string(__wrap_wm_strcat, str2, "Test Message");
    will_return(__wrap_wm_strcat, 0);

    will_return(__wrap_cJSON_CreateString, (cJSON *) 8);

    will_return(__wrap_OSList_GetFirstNode, NULL);

    retval = w_logtest_process_request_log_processing(&json_request, &json_response, list_msg, &connection);

    assert_int_equal(extpect_retval, retval);

    os_free(stored_session->token);
    os_free(stored_session->eventlist);
    os_free(stored_session);
    os_free(token);
    os_free(json_request_token);
    os_free(list_msg);
    os_free(str_location);
    os_free(raw_event);
    os_free(list_msg_node);
    os_free(Config.includes);
    os_free(Config.decoders);
    os_free(Config.lists);
    os_free(options.valuestring);
    store_session = false;
}

/* w_logtest_ruleset_free_config */
void test_w_logtest_ruleset_free_config_empty_config(void ** state) {
    _Config ruleset_config = {0};
    w_logtest_ruleset_free_config(&ruleset_config);
}

void test_w_logtest_ruleset_free_config_ok(void ** state) {
    _Config ruleset_config = {0};
    os_calloc(2, sizeof(char *), ruleset_config.includes);
    os_strdup("test", ruleset_config.includes[0]);
    os_calloc(3, sizeof(char *), ruleset_config.decoders);
    os_strdup("test", ruleset_config.decoders[0]);
    os_strdup("test", ruleset_config.decoders[1]);
    os_calloc(3, sizeof(char *), ruleset_config.lists);
    os_strdup("test", ruleset_config.lists[0]);
    os_strdup("test", ruleset_config.lists[1]);

    w_logtest_ruleset_free_config(&ruleset_config);
}

/* w_logtest_ruleset_load_config */
void test_w_logtest_ruleset_load_config_empty_element(void ** state) {
    bool retval = true;
    bool EXPECT_RETVAL = false;

    OS_XML xml = {0};
    _Config ruleset_config = {0};
    OSList list_msg = {0};

    /* xml config */
    XML_NODE conf_section_nodes;
    os_calloc(2, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    retval = w_logtest_ruleset_load_config(&xml, conf_section_nodes, &ruleset_config, &list_msg);
    assert_int_equal(retval, EXPECT_RETVAL);

    os_free(conf_section_nodes[0]);
    os_free(conf_section_nodes);
}

void test_w_logtest_ruleset_load_config_empty_option_node(void ** state) {
    bool retval = true;
    bool EXPECT_RETVAL = false;

    OS_XML xml = {0};
    _Config ruleset_config = {0};
    OSList list_msg = {0};

    /* xml config */
    XML_NODE conf_section_nodes;
    os_calloc(2, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    conf_section_nodes[0]->element = (char *) 1;

    will_return(__wrap_OS_GetElementsbyNode, NULL);
    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    retval = w_logtest_ruleset_load_config(&xml, conf_section_nodes, &ruleset_config, &list_msg);
    assert_int_equal(retval, EXPECT_RETVAL);

    os_free(conf_section_nodes[0]);
    os_free(conf_section_nodes);
}

void test_w_logtest_ruleset_load_config_fail_read_rules(void ** state) {
    bool retval = true;
    bool EXPECT_RETVAL = false;

    OS_XML xml = {0};
    _Config ruleset_config = {0};
    OSList list_msg = {0};

    /* xml config */
    XML_NODE conf_section_nodes;
    os_calloc(2, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);

    /* xml ruleset */
    expect_function_call_any(__wrap_OS_ClearNode);
    os_strdup("ruleset", conf_section_nodes[0]->element);

    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, -1);

    retval = w_logtest_ruleset_load_config(&xml, conf_section_nodes, &ruleset_config, &list_msg);
    assert_int_equal(retval, EXPECT_RETVAL);

    os_free(conf_section_nodes[0]->element);
    os_free(conf_section_nodes[0]);
    os_free(conf_section_nodes);
}

void test_w_logtest_ruleset_load_config_fail_read_alerts(void ** state) {
    bool retval = true;
    bool EXPECT_RETVAL = false;

    OS_XML xml = {0};
    _Config ruleset_config = {0};
    OSList list_msg = {0};

    /* xml config */
    XML_NODE conf_section_nodes;
    os_calloc(2, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);

    /* xml ruleset */
    expect_function_call_any(__wrap_OS_ClearNode);
    os_strdup("alerts", conf_section_nodes[0]->element);

    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, -1);

    retval = w_logtest_ruleset_load_config(&xml, conf_section_nodes, &ruleset_config, &list_msg);
    assert_int_equal(retval, EXPECT_RETVAL);

    os_free(conf_section_nodes[0]->element);
    os_free(conf_section_nodes[0]);
    os_free(conf_section_nodes);
}

void test_w_logtest_ruleset_load_config_ok(void ** state) {

    bool retval = false;
    bool EXPECT_RETVAL = true;

    OS_XML xml = {0};
    _Config ruleset_config = {0};
    OSList list_msg = {0};

    /* xml config */
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);

    /* xml ruleset */
    expect_function_call_any(__wrap_OS_ClearNode);
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);

    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);

    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    retval = w_logtest_ruleset_load_config(&xml, conf_section_nodes, &ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
    assert_int_equal(ruleset_config.logbylevel, session_level_alert);
    assert_non_null(ruleset_config.decoders);
    assert_non_null(ruleset_config.decoders[0]);
    assert_non_null(ruleset_config.includes);
    assert_non_null(ruleset_config.includes[0]);
    assert_non_null(ruleset_config.lists);
    assert_non_null(ruleset_config.lists[0]);

    os_free(conf_section_nodes[0]->element);
    os_free(conf_section_nodes[0]);
    os_free(conf_section_nodes[1]->element);
    os_free(conf_section_nodes[1]);
    os_free(conf_section_nodes);
    w_logtest_ruleset_free_config(&ruleset_config);
}

/* w_logtest_ruleset_load */
void test_w_logtest_ruleset_load_fail_readxml(void ** state) {

    bool retval = true;
    bool EXPECT_RETVAL = false;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    will_return(__wrap_OS_ReadXML, -1);
    will_return(__wrap_OS_ReadXML, "unknown");
    will_return(__wrap_OS_ReadXML, 5);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(1226): Error reading XML file 'etc/ossec.conf': "
                  "unknown (line 5).");

    retval = w_logtest_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
}

void test_w_logtest_ruleset_empty_file(void ** state) {

    bool retval = true;
    bool EXPECT_RETVAL = false;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    will_return(__wrap_OS_ReadXML, 0);
    will_return(__wrap_OS_GetElementsbyNode, NULL);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "There are no configuration blocks inside of 'etc/ossec.conf'");

    retval = w_logtest_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
}

void test_w_logtest_ruleset_load_null_element(void ** state) {

    bool retval = true;
    bool EXPECT_RETVAL = false;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    os_calloc(1, sizeof(xml_node), node[0]);

    will_return(__wrap_OS_GetElementsbyNode, node);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    retval = w_logtest_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
}

void test_w_logtest_ruleset_load_empty_ossec_label(void ** state) {

    bool retval = false;
    bool EXPECT_RETVAL = true;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);
    will_return(__wrap_OS_GetElementsbyNode, NULL);

    retval = w_logtest_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
}

void test_w_logtest_ruleset_load_fail_load_ruleset_config(void ** state) {

    bool retval = true;
    bool EXPECT_RETVAL = false;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);

    // Fail w_logtest_ruleset_load_config
    XML_NODE conf_section_nodes;
    os_calloc(2, sizeof(xml_node *), conf_section_nodes);
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1231): Invalid NULL element in the configuration.");

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, "(1202): Configuration error at 'etc/ossec.conf'.");

    retval = w_logtest_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
}

void test_w_logtest_ruleset_load_ok(void ** state) {

    bool retval = false;
    bool EXPECT_RETVAL = true;

    _Config ruleset_config = {0};
    OSList list_msg = {0};

    expect_function_call_any(__wrap_OS_ClearNode);
    will_return(__wrap_OS_ReadXML, 0);
    XML_NODE node;
    os_calloc(2, sizeof(xml_node *), node);
    /* <ossec_config></> */
    os_calloc(1, sizeof(xml_node), node[0]);
    os_strdup("ossec_config", node[0]->element);
    will_return(__wrap_OS_GetElementsbyNode, node);

    // w_logtest_ruleset_load_config ok
    XML_NODE conf_section_nodes;
    os_calloc(3, sizeof(xml_node *), conf_section_nodes);
    // Alert
    os_calloc(1, sizeof(xml_node), conf_section_nodes[0]);
    // Ruleset
    os_calloc(1, sizeof(xml_node), conf_section_nodes[1]);
    will_return(__wrap_OS_GetElementsbyNode, conf_section_nodes);

    /* xml ruleset */
    os_strdup("alerts", conf_section_nodes[0]->element);
    os_strdup("ruleset", conf_section_nodes[1]->element);

    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Alerts, 0);

    will_return(__wrap_OS_GetElementsbyNode, (xml_node **) calloc(1, sizeof(xml_node *)));
    will_return(__wrap_Read_Rules, 0);

    retval = w_logtest_ruleset_load(&ruleset_config, &list_msg);

    assert_int_equal(retval, EXPECT_RETVAL);
    assert_int_equal(ruleset_config.logbylevel, session_level_alert);
    assert_non_null(ruleset_config.decoders);
    assert_non_null(ruleset_config.decoders[0]);
    assert_non_null(ruleset_config.includes);
    assert_non_null(ruleset_config.includes[0]);
    assert_non_null(ruleset_config.lists);
    assert_non_null(ruleset_config.lists[0]);

    w_logtest_ruleset_free_config(&ruleset_config);
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
        cmocka_unit_test(test_w_logtest_init_OSHash_setSize_fail),
        cmocka_unit_test(test_w_logtest_init_pthread_fail),
        cmocka_unit_test(test_w_logtest_init_unlink_fail),
        cmocka_unit_test(test_w_logtest_init_done),
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
        // Test w_logtest_remove_old_session
        cmocka_unit_test(test_w_logtest_remove_old_session_Begin_fail),
        cmocka_unit_test(test_w_logtest_remove_old_session_one),
        cmocka_unit_test(test_w_logtest_remove_old_session_many),
        // Test w_logtest_register_session
        cmocka_unit_test(test_w_logtest_register_session_dont_remove),
        cmocka_unit_test(test_w_logtest_register_session_remove_old),
        // Tests w_logtest_initialize_session
        cmocka_unit_test(test_w_logtest_initialize_session_error_load_ruleset),
        cmocka_unit_test(test_w_logtest_initialize_session_error_decoders),
        cmocka_unit_test(test_w_logtest_initialize_session_error_set_decoders),
        cmocka_unit_test(test_w_logtest_initialize_session_error_cbd_list),
        cmocka_unit_test(test_w_logtest_initialize_session_error_rules),
        cmocka_unit_test(test_w_logtest_initialize_session_error_hash_rules),
        cmocka_unit_test(test_w_logtest_initialize_session_error_fts_init),
        cmocka_unit_test(test_w_logtest_initialize_session_error_accumulate_init),
        cmocka_unit_test(test_w_logtest_initialize_session_success),
        cmocka_unit_test(test_w_logtest_initialize_session_success_duplicate_key),
        // Tests w_logtest_generate_token
        cmocka_unit_test(test_w_logtest_generate_token_success),
        cmocka_unit_test(test_w_logtest_generate_token_success_empty_bytes),
        // Tests w_logtest_add_msg_response
        cmocka_unit_test(test_w_logtest_add_msg_response_null_list),
        cmocka_unit_test(test_w_logtest_add_msg_response_new_field_msg),
        cmocka_unit_test(test_w_logtest_add_msg_response_error_msg),
        cmocka_unit_test(test_w_logtest_add_msg_response_warn_msg),
        cmocka_unit_test(test_w_logtest_add_msg_response_warn_dont_remplaze_error_msg),
        cmocka_unit_test(test_w_logtest_add_msg_response_info_msg),
        // Tests w_logtest_check_input
        cmocka_unit_test(test_w_logtest_check_input_malformed_json_long),
        cmocka_unit_test(test_w_logtest_check_input_malformed_json_short),
        cmocka_unit_test(test_w_logtest_check_input_parameter_not_found),
        cmocka_unit_test(test_w_logtest_check_input_parameter_bad_type),
        cmocka_unit_test(test_w_logtest_check_input_command_not_found),
        cmocka_unit_test(test_w_logtest_check_input_command_bad_type),
        cmocka_unit_test(test_w_logtest_check_input_invalid_command),
        cmocka_unit_test(test_w_logtest_check_input_type_remove_sesion_ok),
        cmocka_unit_test(test_w_logtest_check_input_type_request_ok),
        // Tests w_logtest_check_input_request
        cmocka_unit_test(test_w_logtest_check_input_request_empty_json),
        cmocka_unit_test(test_w_logtest_check_input_request_missing_location),
        cmocka_unit_test(test_w_logtest_check_input_request_missing_log_format),
        cmocka_unit_test(test_w_logtest_check_input_request_missing_event),
        cmocka_unit_test(test_w_logtest_check_input_request_invalid_event),
        cmocka_unit_test(test_w_logtest_check_input_request_full_empty_token),
        cmocka_unit_test(test_w_logtest_check_input_request_full),
        cmocka_unit_test(test_w_logtest_check_input_request_bad_token_lenght),
        cmocka_unit_test(test_w_logtest_check_input_request_bad_token_type),
        cmocka_unit_test(test_w_logtest_check_input_request_debug_rules),
        // Tests w_logtest_check_input_remove_session
        cmocka_unit_test(test_w_logtest_check_input_remove_session_not_string),
        cmocka_unit_test(test_w_logtest_check_input_remove_session_invalid_token),
        cmocka_unit_test(test_w_logtest_check_input_remove_session_ok),
        // Tests w_logtest_process_request
        cmocka_unit_test(test_w_logtest_process_request_error_list),
        cmocka_unit_test(test_w_logtest_process_request_error_check_input),
        cmocka_unit_test(test_w_logtest_process_request_type_remove_session_ok),
        cmocka_unit_test(test_w_logtest_process_request_type_log_processing),
        // Tests w_logtest_generate_error_response
        cmocka_unit_test(test_w_logtest_generate_error_response_ok),
        // Tests w_logtest_preprocessing_phase
        cmocka_unit_test(test_w_logtest_preprocessing_phase_json_location_to_scape_ok),
        cmocka_unit_test(test_w_logtest_preprocessing_phase_json_event_ok),
        cmocka_unit_test(test_w_logtest_preprocessing_phase_json_event_fail),
        cmocka_unit_test(test_w_logtest_preprocessing_phase_str_event_ok),
        cmocka_unit_test(test_w_logtest_preprocessing_phase_str_event_fail),
        // Tests w_logtest_decoding_phase
        cmocka_unit_test(test_w_logtest_decoding_phase_program_name),
        cmocka_unit_test(test_w_logtest_decoding_phase_no_program_name),
        // Tests w_logtest_rulesmatching_phase
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_no_load_rules),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_ossec_alert),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_dont_match_category),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_dont_match),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_match_level_0),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_match_dont_ignore_first_time),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_match_ignore_time_ignore),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_match_dont_ignore_time_out_windows),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_match_ignore_event),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_match_and_if_matched_sid_ok),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_match_and_if_matched_sid_fail),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_match_and_group_prev_matched),
        cmocka_unit_test(test_w_logtest_rulesmatching_phase_match_and_group_prev_matched_fail),
        // Tests w_logtest_process_log
        cmocka_unit_test(test_w_logtest_process_log_preprocessing_fail),
        cmocka_unit_test(test_w_logtest_process_log_rule_match_fail),
        cmocka_unit_test(test_w_logtest_process_log_rule_dont_match),
        cmocka_unit_test(test_w_logtest_process_log_rule_match),
        cmocka_unit_test(test_w_logtest_process_log_rule_match_level_0),
        // Tests w_logtest_process_request_remove_session
        cmocka_unit_test(test_w_logtest_process_request_remove_session_invalid_token),
        cmocka_unit_test(test_w_logtest_process_request_remove_session_session_not_found),
        cmocka_unit_test(test_w_logtest_process_request_remove_session_session_in_use),
        cmocka_unit_test(test_w_logtest_process_request_remove_session_ok),
        // Tests w_logtest_clients_handler
        cmocka_unit_test(test_w_logtest_clients_handler_error_acept),
        cmocka_unit_test(test_w_logtest_clients_handler_error_acept_close_socket),
        cmocka_unit_test(test_w_logtest_clients_handler_recv_error),
        cmocka_unit_test(test_w_logtest_clients_handler_recv_msg_empty),
        cmocka_unit_test(test_w_logtest_clients_handler_recv_msg_oversize),
        cmocka_unit_test(test_w_logtest_clients_handler_ok),
        // w_logtest_process_request_log_processing
        cmocka_unit_test(test_w_logtest_process_request_log_processing_fail_session),
        cmocka_unit_test(test_w_logtest_process_request_log_processing_fail_process_log),
        cmocka_unit_test(test_w_logtest_process_request_log_processing_ok_and_alert),
        cmocka_unit_test(test_w_logtest_process_request_log_processing_ok_session_expired),
        // w_logtest_ruleset_free_config
        cmocka_unit_test(test_w_logtest_ruleset_free_config_empty_config),
        cmocka_unit_test(test_w_logtest_ruleset_free_config_ok),
        // w_logtest_ruleset_load_config
        cmocka_unit_test(test_w_logtest_ruleset_load_config_empty_element),
        cmocka_unit_test(test_w_logtest_ruleset_load_config_empty_option_node),
        cmocka_unit_test(test_w_logtest_ruleset_load_config_fail_read_rules),
        cmocka_unit_test(test_w_logtest_ruleset_load_config_fail_read_alerts),
        cmocka_unit_test(test_w_logtest_ruleset_load_config_ok),
        // w_logtest_ruleset_load
        cmocka_unit_test(test_w_logtest_ruleset_load_fail_readxml),
        cmocka_unit_test(test_w_logtest_ruleset_empty_file),
        cmocka_unit_test(test_w_logtest_ruleset_load_null_element),
        cmocka_unit_test(test_w_logtest_ruleset_load_empty_ossec_label),
        cmocka_unit_test(test_w_logtest_ruleset_load_fail_load_ruleset_config),
        cmocka_unit_test(test_w_logtest_ruleset_load_ok),

    };

    return cmocka_run_group_tests(tests, setup_group, NULL);
}
