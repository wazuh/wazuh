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


const char      *gIpAddress = {"127.0.0.1"};
int             gPort = 1514;
int             gRuleId[] = {0};

int __wrap_OS_Alert_SendSyslog_JSON(__attribute__((unused)) cJSON *json_data, __attribute__((unused)) SyslogConfig *syslog_config) {
    return mock();
}


static int test_csyslogd_setup(void **state) {
    
    SyslogConfig *pSyslogConfig;
    
    os_calloc(1, sizeof(SyslogConfig), pSyslogConfig);

    if(pSyslogConfig)
    {
        pSyslogConfig->port = gPort;
        pSyslogConfig->format = JSON_CSYSLOG;
        pSyslogConfig->level = 7;
        pSyslogConfig->rule_id = gRuleId;
        pSyslogConfig->server = (char*)gIpAddress;

    
        state[0] = pSyslogConfig;  
        
        return OS_SUCCESS;
    }
    
    return OS_INVALID;
}

static void test_csyslogd_OS_CSyslogD(void **state) {   
    
    SyslogConfig *pSyslogConfig[2]; 

    pSyslogConfig[0] = state[0];

    char *ip = pSyslogConfig[0]->server;
    int   port = pSyslogConfig[0]->port;

    pSyslogConfig[1] = NULL;

    cJSON *pJSON = cJSON_Parse((char*)("{\"alert\":\"valid jason description\"}\n"));

    will_return(__wrap_jqueue_open, 1);
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
   
    will_return(__wrap_time, 62168472000);

    expect_string(__wrap__mdebug2, formatted_msg, "jqueue_next()");

    will_return(__wrap_jqueue_next, pJSON);

    will_return(__wrap_OS_Alert_SendSyslog_JSON, 1);
    will_return(__wrap_FOREVER, 1);
    will_return(__wrap_FOREVER, 0);

    OS_CSyslogD(pSyslogConfig);

    //pJSON is deleted in OS_CSyslogD
}

static int test_csyslogd_teardown(void **state) {

    SyslogConfig *pSyslogConfig = state[0];
    os_free(pSyslogConfig);
    return OS_SUCCESS;
}


int main()
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test_setup_teardown(test_csyslogd_OS_CSyslogD, test_csyslogd_setup, test_csyslogd_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
