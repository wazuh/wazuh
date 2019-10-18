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

int test_manager_conf(const char *path, char **output) {
    int type = CLOCAL_CONFIG;

    if(validate_target(path, type, output) < 0) {
        return OS_INVALID;
    }

    if(Test_Authd(path, output) < 0) {
        return OS_INVALID;
    } else if(Test_WModule(path, type, output) < 0) {                   // Test WModules, SCA and FluentForwarder
        return OS_INVALID;
    } else if(Test_Remoted(path, output) < 0) {
        return OS_INVALID;
    } else if(Test_ActiveResponse(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_Analysisd(path, output) < 0) {                       // Test Global, Rules, Alerts, Cluster, CLabels
        return OS_INVALID;
    } else if(Test_Localfile(path, type, output) < 0) {                 // Test Localfile and Socket
        return OS_INVALID;
    } else if(Test_Integratord(path, output) < 0) {
        return OS_INVALID;
    } else if(Test_Syscheck(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_Rootcheck(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_Maild(path, output) < 0) {
        return OS_INVALID;
    } else if(Test_Agentlessd(path, output) < 0) {
        return OS_INVALID;
    } else if(Test_DBD(path, output) < 0) {
        return OS_INVALID;
    } else if(Test_Labels(path, type, output) < 0) {
        return OS_INVALID;
    }

    return 0;
}

int test_agent_conf(const char *path, int type, char **output) {

    if(validate_target(path, type, output) < 0) {
        return OS_INVALID;
    }

    if(Test_Syscheck(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_Rootcheck(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_Localfile(path, type, output) < 0) {                 // Test Localfile and Socket
        return OS_INVALID;
    } else if(Test_Labels(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_ClientBuffer(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_ActiveResponse(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_Client(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_WModule(path, type, output) < 0) {                   // Test WModules, SCA and FluentForwarder
        return OS_INVALID;
    } else if (Test_Agent_Active_Response(path, output) < 0) {
        return OS_INVALID;
    }

    return 0;
}

int test_remote_conf(const char *path, int type, char **output) {

    if(validate_target(path, type, output) < 0) {
        return OS_INVALID;
    }

    if(Test_WModule(path, type, output) < 0) {                   // Test WModules, SCA
        return OS_INVALID;
    } else if(Test_Syscheck(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_Rootcheck(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_Localfile(path, type, output) < 0) {                 // Test Localfile and Socket
        return OS_INVALID;
    } else if(Test_Labels(path, type, output) < 0) {
        return OS_INVALID;
    } else if(Test_ClientBuffer(path, type, output) < 0) {
        return OS_INVALID;
    }

    return 0;
}

int validate_target(const char *path, int type, char **output) {
    int i;
    OS_XML xml;
    XML_NODE node;
    char message[OS_FLSIZE];

    /** XML definitions **/
    /* Global */
    const char *xml_start_ossec = "ossec_config";
    const char *xml_start_agent = "agent_config";

    if (OS_ReadXML(path, &xml) < 0) {
        if (type & CRMOTE_CONFIG) {
#ifndef CLIENT
            snprintf(message, OS_FLSIZE + 1,
                "Error reading XML file '%s': %s (line %d).", 
                path, xml.err, xml.err_line);
            wm_strcat(output, message, '\n');
#endif
        } else {
            snprintf(message, OS_FLSIZE + 1,
                "Error reading XML file '%s': %s (line %d).", 
                path, xml.err, xml.err_line);
            wm_strcat(output, message, '\n');
        }

        OS_ClearXML(&xml);
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
            wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            break;
        } else if (!(type & CRMOTE_CONFIG) && (strcmp(node[i]->element, xml_start_agent) == 0)) {
            snprintf(message, OS_FLSIZE + 1,
                "Invalid configuration file target: '%s' when expected: '%s'.", 
                node[i]->element, xml_start_ossec);
            wm_strcat(output, message, '\n');
            break;
        } else if ((type & CRMOTE_CONFIG) && (strcmp(node[i]->element, xml_start_ossec) == 0)) {
            snprintf(message, OS_FLSIZE + 1,
                "Invalid configuration file target: '%s' when expected: '%s'.", 
                node[i]->element, xml_start_agent);
            wm_strcat(output, message, '\n');
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

    return OS_INVALID;
}