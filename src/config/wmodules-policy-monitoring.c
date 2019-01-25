/* Copyright (C) 2015-2019, Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"
#include <stdio.h>

static const char *XML_ENABLED = "enabled";
static const char *XML_WEEK_DAY = "wday";
static const char *XML_TIME = "time";
static const char *XML_SCAN_ON_START= "scan_on_start";
static const char *XML_PROFILE = "profile";
static const char *XML_SKIP_NFS = "skip_nfs";

static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

// Reading function
int wm_policy_monitoring_read(xml_node **nodes, wmodule *module)
{
    unsigned int i;
    unsigned int profiles = 0;
    wm_policy_monitoring_t *policy_monitoring;

    os_calloc(1, sizeof(wm_policy_monitoring_t), policy_monitoring);
    policy_monitoring->enabled = 1;
    policy_monitoring->scan_on_start = 1;
    policy_monitoring->week_day = NULL;
    policy_monitoring->time = NULL;
    policy_monitoring->skip_nfs = 1;
    policy_monitoring->alert_msg = NULL;
    module->context = &WM_POLICY_MONITORING_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = policy_monitoring;

    if (!nodes)
        return 0;

    /* We store up to 255 alerts in there */
    os_calloc(256, sizeof(char *), policy_monitoring->alert_msg);
    int c = 0;
    while (c <= 255) {
        policy_monitoring->alert_msg[c] = NULL;
        c++;
    }

    for(i = 0; nodes[i]; i++)
    {
        if(!nodes[i]->element)
        {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_ENABLED))
        {
            int enabled = eval_bool(nodes[i]->content);

            if(enabled == OS_INVALID){
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_POLICY_MONITORING_CONTEXT.name);
                return OS_INVALID;
            }

            policy_monitoring->scan_on_start = enabled;
        }
        else if (!strcmp(nodes[i]->element, XML_WEEK_DAY))
        {
            if(strlen(nodes[i]->content) > 9) {
                merror("Week day is too long at module '%s'. Max week day length is %d", WM_POLICY_MONITORING_CONTEXT.name,9);
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content,policy_monitoring->week_day);
        }
        else if (!strcmp(nodes[i]->element, XML_TIME))
        {
            if(strlen(nodes[i]->content) > 5) {
                merror("Time is too long at module '%s'. Max time length is %d", WM_POLICY_MONITORING_CONTEXT.name,5);
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content,policy_monitoring->time);
        }
        else if (!strcmp(nodes[i]->element, XML_SCAN_ON_START))
        {
            int scan_on_start = eval_bool(nodes[i]->content);

            if(scan_on_start == OS_INVALID)
            {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_POLICY_MONITORING_CONTEXT.name);
                return OS_INVALID;
            }

            policy_monitoring->scan_on_start = scan_on_start;
        }
        else if (!strcmp(nodes[i]->element, XML_PROFILE))
        {
            
            if(strlen(nodes[i]->content) >= PATH_MAX) {
                merror("Profile path is too long at module '%s'. Max path length is %d", WM_POLICY_MONITORING_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            }

            os_realloc(policy_monitoring->profile, (profiles + 2) * sizeof(char *), policy_monitoring->profile);
            os_strdup(nodes[i]->content,policy_monitoring->profile[profiles]);
            policy_monitoring->profile[profiles + 1] = NULL;
            profiles++;
        }
        else if (!strcmp(nodes[i]->element, XML_SKIP_NFS))
        {
            int skip_nfs = eval_bool(nodes[i]->content);

            if(skip_nfs == OS_INVALID){
                merror("Invalid content for tag '%s' at module '%s'.", XML_SKIP_NFS, WM_POLICY_MONITORING_CONTEXT.name);
                return OS_INVALID;
            }

            policy_monitoring->skip_nfs = skip_nfs;
        }
        else
        {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_POLICY_MONITORING_CONTEXT.name);
        }

    }
    return 0;
}
