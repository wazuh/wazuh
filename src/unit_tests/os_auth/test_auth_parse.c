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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

//Expected log messages to be checked on mocked log functions
typedef struct _mocked_log {
    char* merror;
    char* mwarn;
    char* minfo;
    char* mdebug;    
} mocked_log;

//Sets all the expected log messages
void set_expected_log (mocked_log* log) {
    if(log->merror) {
            expect_string(__wrap__merror, formatted_msg, log->merror);
    }
    if(log->mwarn) {
            expect_string(__wrap__mwarn, formatted_msg, log->mwarn);
    }
    if(log->minfo) {
            expect_string(__wrap__minfo, formatted_msg, log->minfo);
    }
    if(log->mdebug) {
            expect_string(__wrap__mdebug1, formatted_msg, log->mdebug);
    }
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


//parser arguments
typedef struct _parse_evaluator {
    char* buffer;
    char* src_ip;
    char* pass;
    enrollment_param expected_params;
    enrollment_response expected_response;
    mocked_log expected_log;
} parse_evaluator;

parse_evaluator parse_values_default_cfg []={
    { "OSSEC A:'agent1'", "192.0.0.1", NULL,                            {"192.0.0.1", "agent1", NULL},              {OS_SUCCESS,""}, {NULL, NULL, "Received request for a new agent (agent1) from: 192.0.0.1", NULL} },
    { "OSSEC A:'agent2' G:'Group1'", "192.0.0.1", NULL,                 {"192.0.0.1", "agent2", "Group1"},          {OS_SUCCESS,""}, {NULL, NULL, "Received request for a new agent (agent2) from: 192.0.0.1", "Group(s) is: Group1"} },
    { "OSSEC A:'agent3' G:'Group1,Group2'", "192.0.0.1", NULL,          {"192.0.0.1", "agent3", "Group1,Group2"},   {OS_SUCCESS,""}, {NULL, NULL, "Received request for a new agent (agent3) from: 192.0.0.1", "Group(s) is: Group1,Group2"} },
    { "OSSEC A:'agent4' G:'Group1,Group2,Group1'", "192.0.0.1", NULL,   {"192.0.0.1", "agent4", "Group1,Group2"},   {OS_SUCCESS,""}, {NULL, NULL, "Received request for a new agent (agent4) from: 192.0.0.1", "Group(s) is: Group1,Group2"} },
    { "OSSEC PASS: pass123 OSSEC A:'agent5'", "192.0.0.1", "pass123",   {"192.0.0.1", "agent5", NULL},              {OS_SUCCESS,""}, {NULL, NULL, "Received request for a new agent (agent5) from: 192.0.0.1", NULL} },
    { "OSSEC A:'agent6' IP:'192.0.0.2'", "192.0.0.1", NULL,             {"192.0.0.2", "agent6", NULL},              {OS_SUCCESS,""}, {NULL, NULL, "Received request for a new agent (agent6) from: 192.0.0.1", NULL} },

    { "OSSEC A:'agent0'", "192.0.0.1", "pass123",                       {NULL, NULL, NULL}, {OS_INVALID,"ERROR: Invalid password"},              {"Invalid password provided by 192.0.0.1. Closing connection.", NULL, NULL, NULL} },
    { "OSSEC PASS: pass124 OSSEC A:'agent0'", "192.0.0.1", "pass123",   {NULL, NULL, NULL}, {OS_INVALID,"ERROR: Invalid password"},              {"Invalid password provided by 192.0.0.1. Closing connection.", NULL, NULL, NULL} },
    { "OSSEC PASS: pass124 OSSEC A:'agent0'", "192.0.0.1", NULL,        {NULL, NULL, NULL}, {OS_INVALID,"ERROR: Invalid request for new agent"}, {"Invalid request for new agent from: 192.0.0.1", NULL, NULL, NULL} },
    { "OSSEC A:''", "192.0.0.1", NULL,                                  {NULL, NULL, NULL}, {OS_INVALID,"ERROR: Invalid agent name: "},          {"Invalid agent name:  from 192.0.0.1", NULL, "Received request for a new agent () from: 192.0.0.1", NULL} },
    { "OSSEC A:'inv;agent'", "192.0.0.1", NULL,                         {NULL, NULL, NULL}, {OS_INVALID,"ERROR: Invalid agent name: inv;agent"}, {"Invalid agent name: inv;agent from 192.0.0.1", NULL, "Received request for a new agent (inv;agent) from: 192.0.0.1", NULL} },
    
    {0}
};

parse_evaluator parse_values_without_use_src_ip_cfg []={
    {"OSSEC A:'agent1'", "192.0.0.1", NULL,                             {"any", "agent1", NULL},                    {OS_SUCCESS,""}, {NULL, NULL, "Received request for a new agent (agent1) from: 192.0.0.1", NULL} },
    {"OSSEC A:'agent2' IP:'192.0.0.2'", "192.0.0.1", NULL,              {"192.0.0.2", "agent2", NULL},              {OS_SUCCESS,""}, {NULL, NULL, "Received request for a new agent (agent2) from: 192.0.0.1", NULL} },

    {0}
};

parse_evaluator* parse_values = NULL;

/* setup/teardowns */
int setup_parse_default(void **state) {
    config.flags.use_source_ip = 1;
    parse_values = parse_values_default_cfg;
    return 0;
}

int setup_parse_use_src_ip_cfg_0(void **state) {
    config.flags.use_source_ip = 0;
    parse_values = parse_values_without_use_src_ip_cfg;
    return 0;
}

/* tests */
extern w_err_t w_auth_parse_data(const char* buf, char *response, const char *authpass, char *ip, char **agentname, char **groups);

static void test_w_auth_parse_data(void **state) {    

    char response[2048] = {0};
    char ip[IPSIZE + 1];
    char *agentname = NULL;
    char *groups = NULL;    
    w_err_t err;
    
    for(unsigned i=0; parse_values[i].buffer; i++) {
        set_expected_log(&parse_values[i].expected_log);
        response[0] = '\0';
        strncpy(ip, parse_values[i].src_ip, IPSIZE);   

        err = w_auth_parse_data(parse_values[i].buffer, response, parse_values[i].pass, ip, &agentname, &groups);
        
        assert_int_equal(err, parse_values[i].expected_response.err);
        if(err == OS_SUCCESS) {
            assert_string_equal(ip, parse_values[i].expected_params.ip);            
            assert_string_equal(agentname, parse_values[i].expected_params.name);
            if(groups){
                assert_string_equal(groups, parse_values[i].expected_params.groups);
            }
            else{
                assert_null(parse_values[i].expected_params.groups);
            }
        }
        else {
            assert_string_equal(response, parse_values[i].expected_response.response);
        }
        
        os_free(agentname);
        os_free(groups);

    }    
}

int main(void) {     
    const struct CMUnitTest tests[] = {
        /* w_auth_parse_data tests*/
        cmocka_unit_test_setup(test_w_auth_parse_data, setup_parse_default),
        cmocka_unit_test_setup(test_w_auth_parse_data, setup_parse_use_src_ip_cfg_0),        
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
