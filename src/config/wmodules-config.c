/*
 * Wazuh Module Configuration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * April 25, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"
#include "wmodules-config.h"

static const char *XML_NAME = "name";

int Read_WModules_Config(XML_NODE node, void *d1)
{
    int i = 0;

    wmodules_config *wm_config;
    wm_config = (wmodules_config *)d1;

    /* XML Definitions */
    const char *xml_task_nice = "task_nice";
    const char *xml_max_eps = "max_eps";
    const char *xml_kill_timeout = "kill_timeout";
    const char *xml_log_level = "log_level";
    const char *xml_thread_stack_size = "thread_stack_size";

    if (!wm_config) {
        return (0);
    }

    if (!node)
        return 0;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_task_nice) == 0) {
            SetConf(node[i]->content, &wm_cfg.task_nice, options.wazuh_modules.task_nice, xml_task_nice);
        } else if (strcmp(node[i]->element, xml_max_eps) == 0) {
            SetConf(node[i]->content, &wm_cfg.max_eps, options.wazuh_modules.max_eps, xml_max_eps);
        } else if (strcmp(node[i]->element, xml_kill_timeout) == 0) {
            SetConf(node[i]->content, &wm_cfg.kill_timeout, options.wazuh_modules.kill_timeout, xml_kill_timeout);
        } else if (strcmp(node[i]->element, xml_log_level) == 0) {
            SetConf(node[i]->content, &wm_cfg.log_level, options.wazuh_modules.log_level, xml_log_level);
        } else if (strcmp(node[i]->element, xml_thread_stack_size) == 0) {
            SetConf(node[i]->content, &wm_cfg.thread_stack_size, options.global.thread_stack_size, xml_thread_stack_size);
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }

        i++;
    }
    return (0);
}

// Read wodle element

int Read_WModule(const OS_XML *xml, xml_node *node, void *d1, void *d2)
{
    wmodule **wmodules = (wmodule**)d1;
    int agent_cfg = d2 ? *(int *)d2 : 0;
    wmodule *cur_wmodule;
    xml_node **children = NULL;
    wmodule *cur_wmodule_exists;

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
        cur_wmodule_exists = *wmodules;
        int found = 0;

        while (cur_wmodule_exists) {
            if(cur_wmodule_exists->tag) {
                if(strcmp(cur_wmodule_exists->tag,node->values[0]) == 0) {
                    cur_wmodule = cur_wmodule_exists;
                    found = 1;
                    break;
                }
            }
            cur_wmodule_exists = cur_wmodule_exists->next;
        }

        if(!found) {
            while (cur_wmodule->next)
                cur_wmodule = cur_wmodule->next;

            os_calloc(1, sizeof(wmodule), cur_wmodule->next);
            cur_wmodule = cur_wmodule->next;
        }
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
    else if (!strcmp(node->values[0], WM_AWS_CONTEXT.name) || !strcmp(node->values[0], "aws-cloudtrail")) {
#ifndef WIN32
        if (!strcmp(node->values[0], "aws-cloudtrail")) mwarn("Module name 'aws-cloudtrail' is deprecated. Change it to '%s'.", WM_AWS_CONTEXT.name);
        if (wm_aws_read(xml, children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
#else
        mwarn("The '%s' module is not available on Windows systems. Ignoring.", node->values[0]);
#endif
    } else if (!strcmp(node->values[0], "docker-listener")) {
#ifndef WIN32
        if (wm_docker_read(children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
#else
        mwarn("The '%s' module is not available on Windows systems. Ignoring it.", node->values[0]);
#endif
    }
#ifndef WIN32
#ifndef CLIENT
    else if (!strcmp(node->values[0], WM_VULNDETECTOR_CONTEXT.name)) {
        mwarn("This vulnerability-detector declaration is deprecated. Use <vulnerability-detector> instead.");
        if (Read_Vuln(xml, children, cur_wmodule, 0) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    } else if (!strcmp(node->values[0], WM_AZURE_CONTEXT.name)) {
        if (wm_azure_read(xml, children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    } else if (!strcmp(node->values[0], WM_KEY_REQUEST_CONTEXT.name)) {
        if (wm_key_request_read(children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    }
#endif
#endif

    else {
        if(!strcmp(node->values[0], VU_WM_NAME) || !strcmp(node->values[0], AZ_WM_NAME) ||
            !strcmp(node->values[0], KEY_WM_NAME)) {
            mwarn("The '%s' module only works for the manager", node->values[0]);
        } else {
            merror("Unknown module '%s'", node->values[0]);
        }
    }

    OS_ClearNode(children);
    return 0;
}

int Read_SCA(const OS_XML *xml, xml_node *node, void *d1, int modules)
{
    wmodule **wmodules = (wmodule**)d1;
    wmodule *cur_wmodule;
    xml_node **children = NULL;
    wmodule *cur_wmodule_exists;

    // Allocate memory
    if ((cur_wmodule = *wmodules)) {
        cur_wmodule_exists = *wmodules;
        int found = 0;

        while (cur_wmodule_exists) {
            if(cur_wmodule_exists->tag) {
                if(strcmp(cur_wmodule_exists->tag,node->element) == 0) {
                    cur_wmodule = cur_wmodule_exists;
                    found = 1;
                    break;
                }
            }
            cur_wmodule_exists = cur_wmodule_exists->next;
        }

        if(!found) {
            while (cur_wmodule->next)
                cur_wmodule = cur_wmodule->next;

            os_calloc(1, sizeof(wmodule), cur_wmodule->next);
            cur_wmodule = cur_wmodule->next;
        }
    } else
        *wmodules = cur_wmodule = calloc(1, sizeof(wmodule));

    if (!cur_wmodule) {
        merror(MEM_ERROR, errno, strerror(errno));
        return (OS_INVALID);
    }

    // Get children
    if (children = OS_GetElementsbyNode(xml, node), !children) {
        mdebug1("Empty configuration for module '%s'.", node->element);
    }

    //Policy Monitoring Module
    if (!strcmp(node->element, WM_SCA_CONTEXT.name)) {
        if (wm_sca_read(xml,children, cur_wmodule, modules) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    }

    OS_ClearNode(children);
    return 0;
}

#ifndef WIN32
int Read_Fluent_Forwarder(const OS_XML *xml, xml_node *node, void *d1)
{
    wmodule **wmodules = (wmodule**)d1;
    wmodule *cur_wmodule;
    xml_node **children = NULL;
    wmodule *cur_wmodule_exists;

    // Allocate memory
    if ((cur_wmodule = *wmodules)) {
        cur_wmodule_exists = *wmodules;
        int found = 0;

        while (cur_wmodule_exists) {
            if(cur_wmodule_exists->tag) {
                if(strcmp(cur_wmodule_exists->tag,node->element) == 0) {
                    cur_wmodule = cur_wmodule_exists;
                    found = 1;
                    break;
                }
            }
            cur_wmodule_exists = cur_wmodule_exists->next;
        }

        if(!found) {
            while (cur_wmodule->next)
                cur_wmodule = cur_wmodule->next;

            os_calloc(1, sizeof(wmodule), cur_wmodule->next);
            cur_wmodule = cur_wmodule->next;
        }
    } else
        *wmodules = cur_wmodule = calloc(1, sizeof(wmodule));

    if (!cur_wmodule) {
        merror(MEM_ERROR, errno, strerror(errno));
        return (OS_INVALID);
    }

    // Get children
    if (children = OS_GetElementsbyNode(xml, node), !children) {
        mdebug1("Empty configuration for module '%s'.", node->element);
    }

    // Fluent Forwarder Module
    if (!strcmp(node->element, WM_FLUENT_CONTEXT.name)) {
        if (wm_fluent_read(children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    }

    OS_ClearNode(children);
    return 0;
}
#endif

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
