/*
 * Wazuh Module Configuration
 * Copyright (C) 2016 Wazuh Inc.
 * April 25, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"

static const char *XML_NAME = "name";

// Read wodle element

int Read_WModule(const OS_XML *xml, xml_node *node, void *d1, void *d2)
{
    wmodule **wmodules = (wmodule**)d1;
    int agent_cfg = d2 ? *(int *)d2 : 0;
    wmodule *cur_wmodule;
    xml_node **children = NULL;

    if (!node->attributes[0]) {
        merror("No such attribute '%s' at module.", XML_NAME);
        return OS_INVALID;
    }

    if (strcmp(node->attributes[0], XML_NAME)) {
        merror("Module attribute is not '%s'.", XML_NAME);
        return OS_INVALID;
    }

    // Allocate memory

    if ((cur_wmodule = *wmodules)) {
        while (cur_wmodule->next)
            cur_wmodule = cur_wmodule->next;

        os_calloc(1, sizeof(wmodule), cur_wmodule->next);
        cur_wmodule = cur_wmodule->next;
    } else
        *wmodules = cur_wmodule = calloc(1, sizeof(wmodule));

    if (!cur_wmodule) {
        merror(MEM_ERROR, errno, strerror(errno));
        return (OS_INVALID);
    }

    // Get children

    if (children = OS_GetElementsbyNode(xml, node), !children) {
        mdebug1("Empty configuration for module '%s'.", node->values[0]);
    }

    // Select module by name

   //osQuery monitor module
    if (!strcmp(node->values[0], WM_OSQUERYMONITOR_CONTEXT.name)) {
        if (wm_osquery_monitor_read(children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    }

    else if (!strcmp(node->values[0], WM_OSCAP_CONTEXT.name)) {
        if (wm_oscap_read(xml, children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    }
#ifdef ENABLE_SYSC
    else if (!strcmp(node->values[0], WM_SYS_CONTEXT.name)) {
        if (wm_sys_read(children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    }
#endif
    else if (!strcmp(node->values[0], WM_COMMAND_CONTEXT.name)) {
        if (wm_command_read(children, cur_wmodule, agent_cfg) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    }
#ifdef ENABLE_CISCAT
    else if (!strcmp(node->values[0], WM_CISCAT_CONTEXT.name)) {
        if (wm_ciscat_read(xml, children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    }
#endif
#ifndef WIN32
    else if (!strcmp(node->values[0], WM_AWS_CONTEXT.name)) {
        if (wm_aws_read(children, cur_wmodule, agent_cfg) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    }
#ifndef CLIENT
    else if (!strcmp(node->values[0], WM_VULNDETECTOR_CONTEXT.name)) {
        if (wm_vulnerability_detector_read(xml, children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    }
#endif
#endif
    else {
        merror("Unknown module '%s'", node->values[0]);
    }

    OS_ClearNode(children);
    return 0;
}

int Test_WModule(const char * path) {
    int fail = 0;
    wmodule *test_wmodule;
    os_calloc(1, sizeof(wmodule), test_wmodule);

    if (ReadConfig(CAGENT_CONFIG | CWMODULE, path, &test_wmodule, NULL) < 0) {
        merror(RCONFIG_ERROR,"WModule", path);
        fail = 1;
    }

    wm_free(test_wmodule);

    if (fail) {
        return -1;
    } else {
        return 0;
    }
}
