/*
 * Copyright (C) 2015, Wazuh Inc.
 * November, 2020.
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
#include <stdio.h>

#include "../external/cJSON/cJSON.h"

#include "../headers/shared.h"
#include "../headers/read-alert.h"
#include "../../os_csyslogd/csyslogd.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/json_queue_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/linux/socket_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/posix/time_wrappers.h"
#include "../wrappers/externals/pcre2/pcre2_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"

#define MAX_FOREVER_ITS (10)

int __wrap_OS_Alert_SendSyslog_JSON(__attribute__((unused)) cJSON *json_data, __attribute__((unused)) SyslogConfig *syslog_config) {
    return mock_type(int);
}

int __wrap_OS_Alert_SendSyslog(__attribute__((unused))alert_data *al_data, __attribute__((unused))SyslogConfig *syslog_config) {
    return mock_type(int);
}

alert_data *__wrap_Read_FileMon(__attribute__((unused))file_queue *fileq, __attribute__((unused))const struct tm *p, __attribute__((unused))unsigned int timeout) {
    return mock_type(alert_data*);
}

int __wrap_Init_FileQueue(__attribute__((unused))file_queue *fileq, __attribute__((unused))const struct tm *p, __attribute__((unused))int flags) {
    return mock_type(int);
}

void __wrap_sleep(__attribute__((unused))unsigned int seconds) {
    check_expected(seconds);
    return;
}

static SyslogConfig *makeSyslogConfig(unsigned int format) {

    SyslogConfig *pRet;
    
    os_calloc(1, sizeof(SyslogConfig), pRet);
    
    pRet->port = 1514;
    pRet->format = format;
    pRet->level = 7;
    pRet->server = "127.0.0.1";

    return pRet;
}

static int test_csyslogd_json_setup(void **state) {
    
    SyslogConfig *pSyslogConfig = makeSyslogConfig(JSON_CSYSLOG);
    
    if (pSyslogConfig) {
        state[0] = pSyslogConfig;          
        return OS_SUCCESS;
    }
    
    return OS_INVALID;
}

static int test_csyslogd_log_setup(void **state) {
    
    SyslogConfig *pSyslogConfig = makeSyslogConfig(DEFAULT_CSYSLOG);
    if (pSyslogConfig) {      
        state[0] = pSyslogConfig;          
        return OS_SUCCESS;
    }
    
    return OS_INVALID;
}

static int test_csyslogd_teardown(void **state) {

    SyslogConfig *pSyslogConfig = state[0];
    os_free(pSyslogConfig);
    return OS_SUCCESS;
}

static void test_csyslogd_json_CSyslogD(void **state) {   
    
    cJSON *pJSON = NULL;
    SyslogConfig *pSyslogConfig[2]; 

    pSyslogConfig[0] = state[0];

    char *ip = pSyslogConfig[0]->server;
    int   port = pSyslogConfig[0]->port;

    pSyslogConfig[1] = NULL;

    will_return(__wrap_jqueue_open, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "JSON file queue connected.");
    
    char strDbgResolving[128];
    sprintf(strDbgResolving, "Resolving server hostname: %s", ip);
    expect_string(__wrap__mdebug2, formatted_msg, strDbgResolving);
        
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
    
    will_return(__wrap_OS_ConnectUDP, 21);

    char strDbgForwarding[128];
    sprintf(strDbgForwarding, "Forwarding alerts via syslog to: '%s:%d'.", ip, port);
    expect_string(__wrap__minfo, formatted_msg, strDbgForwarding); 

    for (int i = 0; i < MAX_FOREVER_ITS; i++) {
        will_return(__wrap_time, 62168472000);

        expect_string(__wrap__mdebug2, formatted_msg, "jqueue_next()");
        
        pJSON = cJSON_Parse((char*)("{\"alert\":\"valid jason description\"}\n"));
        will_return(__wrap_jqueue_next, pJSON);

        will_return(__wrap_OS_Alert_SendSyslog_JSON, 1);
        will_return(__wrap_FOREVER, 1);
    }
    
    will_return(__wrap_FOREVER, 0);

    OS_CSyslogD(pSyslogConfig);
}

void makeAlertData(alert_data *al_data) {

    os_strdup("Alert ID",  al_data->alertid);
    os_strdup("Date", al_data->date);
    os_strdup("Location", al_data->location);
    os_strdup("a comment...", al_data->comment);
    os_strdup("syscheck", al_data->group);
    os_strdup("sript() {break;}", al_data->srcip);
    os_strdup("dstip", al_data->dstip);
    os_strdup("user@mock", al_data->user);
    os_strdup("mock_data", al_data->filename);
    os_strdup("1111", al_data->old_md5);
    os_strdup("2222", al_data->new_md5);
    os_strdup("AAAA", al_data->old_sha1);
    os_strdup("BBBB", al_data->new_sha1);
    os_strdup("qqqq", al_data->old_sha256);
    os_strdup("QQQQ", al_data->new_sha256);
    os_strdup("32", al_data->file_size);
    os_strdup("mock owner", al_data->owner_chg);
    os_strdup("mock group chg", al_data->group_chg);
    os_strdup("mock perm chg", al_data->perm_chg);

    os_calloc(2, sizeof(char *), al_data->log);
    os_strdup("this is a mock data log entry...", al_data->log[0]);
    al_data->log[1] = NULL;
}

static void test_csyslogd_log_CSyslogD(void **state) {   

    alert_data *al_data = NULL;    
    SyslogConfig *pSyslogConfig[2]; 

    pSyslogConfig[0] = state[0];

    char *ip = pSyslogConfig[0]->server;
    int   port = pSyslogConfig[0]->port;

    pSyslogConfig[1] = NULL;

    will_return(__wrap_time, 62168472000);
    will_return(__wrap_Init_FileQueue, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "File queue connected.");
    
    char strDbgResolving[128];
    sprintf(strDbgResolving, "Resolving server hostname: %s", ip);
    expect_string(__wrap__mdebug2, formatted_msg, strDbgResolving);
        
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
    
    will_return(__wrap_OS_ConnectUDP, 21);

    char strDbgForwarding[128];
    sprintf(strDbgForwarding, "Forwarding alerts via syslog to: '%s:%d'.", ip, port);
    expect_string(__wrap__minfo, formatted_msg, strDbgForwarding); 
   
    for (int i = 0; i < MAX_FOREVER_ITS; i++) {       
        will_return(__wrap_time, 62168472000);
        expect_string(__wrap__mdebug2, formatted_msg, "Read_FileMon()");

        os_calloc(1, sizeof(alert_data), al_data);
        makeAlertData(al_data);         
        
        will_return(__wrap_Read_FileMon, al_data);
        will_return(__wrap_OS_Alert_SendSyslog, 1);
    
        will_return(__wrap_FOREVER, 1);
    }

    will_return(__wrap_FOREVER, 0);

    OS_CSyslogD(pSyslogConfig);
}

static void test_csyslogd_log_CSyslogD_max_tries(void **state) {   
    
    SyslogConfig *pSyslogConfig[2]; 

    pSyslogConfig[0] = state[0];

    char *ip = pSyslogConfig[0]->server;
    int   port = pSyslogConfig[0]->port;

    pSyslogConfig[1] = NULL;

    alert_data *al_data;
    os_calloc(1, sizeof(alert_data), al_data);
    makeAlertData(al_data); 

    will_return(__wrap_time, 62168472000);
        
    for (int tries = 0; tries < OS_CSYSLOGD_MAX_TRIES; tries++) {         
        will_return(__wrap_Init_FileQueue, -1);
        expect_value(__wrap_sleep, seconds, 1);
    }
    
    char strMaxTries[128];
    sprintf(strMaxTries, "Could not open queue after %d tries.", OS_CSYSLOGD_MAX_TRIES);
    expect_string(__wrap__merror, formatted_msg, strMaxTries);
    expect_string(__wrap__merror, formatted_msg, "No configurations available. Exiting.");
    
    OS_CSyslogD(pSyslogConfig);

    FreeAlertData(al_data);
}

static void test_csyslogd_json_CSyslogD_max_tries(void **state) {   
    
    SyslogConfig *pSyslogConfig[2]; 

    pSyslogConfig[0] = state[0];

    char *ip = pSyslogConfig[0]->server;
    int   port = pSyslogConfig[0]->port;

    pSyslogConfig[1] = NULL;


    for (int tries = 1; tries < OS_CSYSLOGD_MAX_TRIES; tries++) {
        will_return(__wrap_jqueue_open, -1);
        expect_value(__wrap_sleep, seconds, 1);
    }
    
    char strMaxTries[128];
    sprintf(strMaxTries, "Could not open JSON queue after %d tries.", OS_CSYSLOGD_MAX_TRIES);
    expect_string(__wrap__merror, formatted_msg, strMaxTries);
    expect_string(__wrap__merror, formatted_msg, "No configurations available. Exiting.");
    
    OS_CSyslogD(pSyslogConfig);
}

static void test_csyslogd_json_unableUDP_CSyslogD(void **state) {   
    
    cJSON *pJSON = NULL;
    SyslogConfig *pSyslogConfig[2]; 

    pSyslogConfig[0] = state[0];

    char *ip = pSyslogConfig[0]->server;
    int   port = pSyslogConfig[0]->port;

    pSyslogConfig[1] = NULL;

    will_return(__wrap_jqueue_open, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "JSON file queue connected.");
    
    char strDbgResolving[128];
    sprintf(strDbgResolving, "Resolving server hostname: %s", ip);
    expect_string(__wrap__mdebug2, formatted_msg, strDbgResolving);
        
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
    
    will_return(__wrap_OS_ConnectUDP, OS_SOCKTERR);
    errno = EINVAL;

    char strUnable[256];
    sprintf(strUnable, CONNS_ERROR, ip, port, "udp", strerror(errno));
    expect_string(__wrap__merror, formatted_msg, strUnable); 
   
    for (int i = 0; i < MAX_FOREVER_ITS; i++) {
        will_return(__wrap_time, 62168472000);

        expect_string(__wrap__mdebug2, formatted_msg, "jqueue_next()");

        pJSON = cJSON_Parse((char*)("{\"alert\":\"valid jason description\"}\n"));
        will_return(__wrap_jqueue_next, pJSON);

        will_return(__wrap_OS_Alert_SendSyslog_JSON, 1);
        will_return(__wrap_FOREVER, 1);
    }

    will_return(__wrap_FOREVER, 0);

    OS_CSyslogD(pSyslogConfig);
}

static void test_csyslogd_json_log_no_dataCSyslogD(void **state) {   
    
    SyslogConfig *pSyslogConfig[2]; 

    pSyslogConfig[0] = state[0];

    char *ip = pSyslogConfig[0]->server;
    int   port = pSyslogConfig[0]->port;

    pSyslogConfig[1] = NULL;

    will_return(__wrap_jqueue_open, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "JSON file queue connected.");
    
    char strDbgResolving[128];
    sprintf(strDbgResolving, "Resolving server hostname: %s", ip);
    expect_string(__wrap__mdebug2, formatted_msg, strDbgResolving);
        
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
    
    will_return(__wrap_OS_ConnectUDP, 21);

    char strDbgForwarding[128];
    sprintf(strDbgForwarding, "Forwarding alerts via syslog to: '%s:%d'.", ip, port);
    expect_string(__wrap__minfo, formatted_msg, strDbgForwarding); 
   
    for (int i = 0; i < MAX_FOREVER_ITS; i++) {
        will_return(__wrap_time, 62168472000);
        expect_string(__wrap__mdebug2, formatted_msg, "jqueue_next()");
        will_return(__wrap_jqueue_next, NULL);
        expect_value(__wrap_sleep, seconds, 1);
        will_return(__wrap_FOREVER, 1);
    }
    
    will_return(__wrap_FOREVER, 0);

    OS_CSyslogD(pSyslogConfig);
}

int main() {

    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test_setup_teardown(test_csyslogd_json_CSyslogD, test_csyslogd_json_setup, test_csyslogd_teardown),
        cmocka_unit_test_setup_teardown(test_csyslogd_log_CSyslogD, test_csyslogd_log_setup, test_csyslogd_teardown),
        cmocka_unit_test_setup_teardown(test_csyslogd_log_CSyslogD_max_tries,test_csyslogd_log_setup, test_csyslogd_teardown),
        cmocka_unit_test_setup_teardown(test_csyslogd_json_CSyslogD_max_tries, test_csyslogd_json_setup, test_csyslogd_teardown),
        cmocka_unit_test_setup_teardown(test_csyslogd_json_unableUDP_CSyslogD, test_csyslogd_json_setup, test_csyslogd_teardown),
        cmocka_unit_test_setup_teardown(test_csyslogd_json_log_no_dataCSyslogD, test_csyslogd_json_setup, test_csyslogd_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
