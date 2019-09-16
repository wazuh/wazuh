/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Unified function to read the configuration */

#include "shared.h"
#include "config/config.h"

int test_manager_conf(const char * path) {
    int type = CLOCAL_CONFIG;

    if(Test_Authd(path) < 0) {
        return -1;
    } else if(Test_WModule(path, type) < 0) {                   // Test WModules, SCA and FluentForwarder
        return -1;
    } else if(Test_Remoted(path) < 0) {
        return -1;
    }
    else if(Test_ActiveResponse(path, type) < 0) {
        return -1;
    } else if(Test_Analysisd(path) < 0) {                       // Test Global, Rules, Alerts, Cluster, CLabels
        return -1;
    } else if(Test_Localfile(path, type) < 0) {                 // Test Localfile and Socket
        return -1;
    } else if(Test_Integratord(path) < 0) {
        return -1;
    } else if(Test_Syscheck(path, type) < 0) {
        return -1;
    } else if(Test_Rootcheck(path, type) < 0) {
        return -1;
    } else if(Test_Maild(path) < 0) {
        return -1;
    } else if(Test_Agentlessd(path) < 0) {
        return -1;
    } else if(Test_DBD(path) < 0) {
        return -1;
    } else if(Test_Labels(path, type) < 0) {
        return -1;
    }// else if(Test_Execd(path) < 0) {
    //     return -1;
    // }

    return 0;
}

int test_agent_conf(const char * path, int type) {

    if(Test_Syscheck(path, type) < 0) {
        return -1;
    } else if(Test_Rootcheck(path, type) < 0) {
        return -1;
    } else if(Test_Localfile(path, type) < 0) {                 // Test Localfile and Socket
        return -1;
    } else if(Test_Labels(path, type) < 0) {
        return -1;
    } else if(Test_ClientBuffer(path, type) < 0) {
        return -1;
    } else if(Test_ActiveResponse(path, type) < 0) {
        return -1;
    } else if(Test_Client(path, type) < 0) {
        return -1;
    } else if(Test_WModule(path, type) < 0) {                   // Test WModules, SCA and FluentForwarder
        return -1;
    }

    return 0;
}

int test_remote_conf(const char * path, int type) {

    if(Test_WModule(path, type) < 0) {                   // Test WModules, SCA
        return -1;
    } else if(Test_Syscheck(path, type) < 0) {
        return -1;
    } else if(Test_Rootcheck(path, type) < 0) {
        return -1;
    } else if(Test_Localfile(path, type) < 0) {                 // Test Localfile
        return -1;
    } else if(Test_Labels(path, type) < 0) {
        return -1;
    } else if(Test_ClientBuffer(path, type) < 0) {
        return -1;
    }

    return 0;
}