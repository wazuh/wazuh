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

#include "check_config.h"

int test_manager_conf(const char * path) {
    int type = CLOCAL_CONFIG;

    if(validate_target(path, type) < 0) {
        return OS_INVALID;
    }

    if(Test_Authd(path) < 0) {
        return OS_INVALID;
    } else if(Test_WModule(path, type) < 0) {                   // Test WModules, SCA and FluentForwarder
        return OS_INVALID;
    } else if(Test_Remoted(path) < 0) {
        return OS_INVALID;
    } else if(Test_ActiveResponse(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_Analysisd(path) < 0) {                       // Test Global, Rules, Alerts, Cluster, CLabels
        return OS_INVALID;
    } else if(Test_Localfile(path, type) < 0) {                 // Test Localfile and Socket
        return OS_INVALID;
    } else if(Test_Integratord(path) < 0) {
        return OS_INVALID;
    } else if(Test_Syscheck(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_Rootcheck(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_Maild(path) < 0) {
        return OS_INVALID;
    } else if(Test_Agentlessd(path) < 0) {
        return OS_INVALID;
    } else if(Test_DBD(path) < 0) {
        return OS_INVALID;
    } else if(Test_Labels(path, type) < 0) {
        return OS_INVALID;
    }

    printf("Test OK!\n");
    return 0;
}

int test_agent_conf(const char * path, int type) {

    if(validate_target(path, type) < 0) {
        return OS_INVALID;
    }

    if(Test_Syscheck(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_Rootcheck(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_Localfile(path, type) < 0) {                 // Test Localfile and Socket
        return OS_INVALID;
    } else if(Test_Labels(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_ClientBuffer(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_ActiveResponse(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_Client(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_WModule(path, type) < 0) {                   // Test WModules, SCA and FluentForwarder
        return OS_INVALID;
    }
    // else if(ExecdConfig(path) < 0) {
    //     return OS_INVALID;
    // }

    printf("Test OK!\n");
    return 0;
}

int test_remote_conf(const char * path, int type) {

    if(validate_target(path, type) < 0) {
        return OS_INVALID;
    }

    if(Test_WModule(path, type) < 0) {                   // Test WModules, SCA
        return OS_INVALID;
    } else if(Test_Syscheck(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_Rootcheck(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_Localfile(path, type) < 0) {                 // Test Localfile and Socket
        return OS_INVALID;
    } else if(Test_Labels(path, type) < 0) {
        return OS_INVALID;
    } else if(Test_ClientBuffer(path, type) < 0) {
        return OS_INVALID;
    }

    printf("Test OK!\n");
    return 0;
}

int validate_target(const char *path, int type) {
    int i;
    OS_XML xml;
    XML_NODE node;

    /** XML definitions **/
    /* Global */
    const char *xml_start_ossec = "ossec_config";
    const char *xml_start_agent = "agent_config";

    if (OS_ReadXML(path, &xml) < 0) {
        if (type & CRMOTE_CONFIG) {
#ifndef CLIENT
            fprintf(stderr, CHK_CONFIG_ERR XML_ERROR "\n", path, xml.err, xml.err_line);
#endif
        } else {
            fprintf(stderr, CHK_CONFIG_ERR XML_ERROR "\n", path, xml.err, xml.err_line);
        }
        return (OS_INVALID);
    }

    node = OS_GetElementsbyNode(&xml, NULL);
    if (!node) {
        return (0);
    }

    /* Read the main configuration */
    i = 0;
    while (node[i]) {
        if (!node[i]->element) {
            fprintf(stderr, CHK_CONFIG_ERR XML_ELEMNULL);
            break;
        } else if (!(type & CRMOTE_CONFIG) && (strcmp(node[i]->element, xml_start_agent) == 0)) {
            fprintf(stderr, CHK_CONFIG_ERR XML_INV_TARGET, node[i]->element, xml_start_ossec);
            break;
        } else if ((type & CRMOTE_CONFIG) && (strcmp(node[i]->element, xml_start_ossec) == 0)) {
            fprintf(stderr, CHK_CONFIG_ERR XML_INV_TARGET, node[i]->element, xml_start_agent);
            break;
        } else {
            OS_ClearNode(node);
            OS_ClearXML(&xml);
            return 0;
        }
        i++;
    }

    /* Clear node and xml */
    OS_ClearNode(node);
    OS_ClearXML(&xml);
    printf("\n");

    return OS_INVALID;
}