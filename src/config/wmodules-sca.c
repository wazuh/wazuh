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
static const char *XML_SCAN_DAY = "day";
static const char *XML_WEEK_DAY = "wday";
static const char *XML_TIME = "time";
static const char *XML_INTERVAL = "interval";
static const char *XML_SCAN_ON_START= "scan_on_start";
static const char *XML_POLICIES = "policies";
static const char *XML_POLICY = "policy";
static const char *XML_SKIP_NFS = "skip_nfs";
static unsigned int profiles = 0;

static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

// Reading function
int wm_sca_read(const OS_XML *xml,xml_node **nodes, wmodule *module)
{
    unsigned int i;
    int month_interval = 0;
    wm_sca_t *sca;

    if(!module->data) {
        os_calloc(1, sizeof(wm_sca_t), sca);
        sca->enabled = 1;
        sca->scan_on_start = 1;
        sca->scan_wday = -1;
        sca->scan_day = 0;
        sca->scan_time = NULL;
        sca->skip_nfs = 1;
        sca->alert_msg = NULL;
        sca->queue = -1;
        sca->interval = WM_DEF_INTERVAL / 2;
        sca->profile = NULL;
        module->context = &WM_SCA_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = sca;
        profiles = 0;
    } 

    sca = module->data;
    

    if (!nodes)
        return 0;

    if(!sca->alert_msg) {
        /* We store up to 255 alerts in there */
        os_calloc(256, sizeof(char *), sca->alert_msg);
        int c = 0;
        while (c <= 255) {
            sca->alert_msg[c] = NULL;
            c++;
        }
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
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_SCA_CONTEXT.name);
                return OS_INVALID;
            }

            sca->enabled = enabled;
        }
        else if (!strcmp(nodes[i]->element, XML_WEEK_DAY))
        {
            sca->scan_wday = w_validate_wday(nodes[i]->content);
            if (sca->scan_wday < 0 || sca->scan_wday > 6) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            }
        }
        else if (!strcmp(nodes[i]->element, XML_SCAN_DAY)) {
            if (!OS_StrIsNum(nodes[i]->content)) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            } else {
                sca->scan_day = atoi(nodes[i]->content);
                if (sca->scan_day < 1 || sca->scan_day > 31) {
                    merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                    return (OS_INVALID);
                }
            }
        }
        else if (!strcmp(nodes[i]->element, XML_TIME))
        {
            sca->scan_time = w_validate_time(nodes[i]->content);
            if (!sca->scan_time) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            }
        }
        else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            sca->interval = strtoul(nodes[i]->content, &endptr, 0);

            if (sca->interval == 0 || sca->interval == UINT_MAX) {
                merror("Invalid interval at module '%s'", WM_SCA_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'M':
                month_interval = 1;
                sca->interval *= 60; // We can`t calculate seconds of a month
                break;
            case 'w':
                sca->interval *= 604800;
                break;
            case 'd':
                sca->interval *= 86400;
                break;
            case 'h':
                sca->interval *= 3600;
                break;
            case 'm':
                sca->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid interval at module '%s'", WM_SCA_CONTEXT.name);
                return OS_INVALID;
            }

            if (sca->interval < 60) {
                mwarn("At module '%s': Interval must be greater than 60 seconds. New interval value: 60s.", WM_SCA_CONTEXT.name);
                sca->interval = 60;
            }
        }
        else if (!strcmp(nodes[i]->element, XML_SCAN_ON_START))
        {
            int scan_on_start = eval_bool(nodes[i]->content);

            if(scan_on_start == OS_INVALID)
            {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_SCA_CONTEXT.name);
                return OS_INVALID;
            }

            sca->scan_on_start = scan_on_start;
        }
        else if (!strcmp(nodes[i]->element, XML_POLICIES))
        {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, nodes[i]), !children) {
                return OS_INVALID;
            }

            int  j;
            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, XML_POLICY) == 0) {
                    int enabled = 1;
                    int policy_found = 0;

                    if(children[j]->attributes && children[j]->values) {

                        if(strcmp(*children[j]->attributes,XML_ENABLED) == 0){
                            if(strcmp(*children[j]->values,"no") == 0){
                                enabled = 0;
                            }
                        }
                    }

                    
                    if(strlen(children[j]->content) >= PATH_MAX) {
                        merror("Policy path is too long at module '%s'. Max path length is %d", WM_SCA_CONTEXT.name,PATH_MAX);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    } else if (strlen(children[j]->content) == 0) {
                        merror("Empty policy value at '%s'.", WM_SCA_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    if(sca->profile) {
                        int i;
                        for(i = 0; sca->profile[i]; i++) {
                            if(!strcmp(sca->profile[i]->profile,children[j]->content)) {
                                sca->profile[i]->enabled = enabled;
                                policy_found = 1;
                                break;
                            }
                        }
                    }

                    if(!policy_found) {
                        os_realloc(sca->profile, (profiles + 2) * sizeof(wm_sca_profile_t *), sca->profile);
                        wm_sca_profile_t *policy;
                        os_calloc(1,sizeof(wm_sca_profile_t),policy);

                        policy->enabled = enabled;
                        policy->policy_id= NULL;

                        if (strstr(children[j]->content, "etc/shared/") != NULL ) {
                            policy->remote = 1;
                        } else {
                            policy->remote = 0;
                        }
                        
                        os_strdup(children[j]->content,policy->profile);
                        sca->profile[profiles] = policy;
                        sca->profile[profiles + 1] = NULL;
                        profiles++;
                    }
                   
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);

          
        }
        else if (!strcmp(nodes[i]->element, XML_SKIP_NFS))
        {
            int skip_nfs = eval_bool(nodes[i]->content);

            if(skip_nfs == OS_INVALID){
                merror("Invalid content for tag '%s' at module '%s'.", XML_SKIP_NFS, WM_SCA_CONTEXT.name);
                return OS_INVALID;
            }

            sca->skip_nfs = skip_nfs;
        }
        else
        {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_SCA_CONTEXT.name);
        }
    }

    // Validate scheduled scan parameters and interval value

    if (sca->scan_day && (sca->scan_wday >= 0)) {
        merror("At module '%s': 'day' is not compatible with 'wday'.", WM_SCA_CONTEXT.name);
        return OS_INVALID;
    } else if (sca->scan_day) {
        if (!month_interval) {
            mwarn("At module '%s': Interval must be a multiple of one month. New interval value: 1M.", WM_SCA_CONTEXT.name);
            sca->interval = 60; // 1 month
        }
        if (!sca->scan_time)
            sca->scan_time = strdup("00:00");
    } else if (sca->scan_wday >= 0) {
        if (w_validate_interval(sca->interval, 1) != 0) {
            sca->interval = 604800;  // 1 week
            mwarn("At module '%s': Interval must be a multiple of one week. New interval value: 1w.", WM_SCA_CONTEXT.name);
        }
        if (sca->interval == 0)
            sca->interval = 604800;
        if (!sca->scan_time)
            sca->scan_time = strdup("00:00");
    } else if (sca->scan_time) {
        if (w_validate_interval(sca->interval, 0) != 0) {
            sca->interval = WM_DEF_INTERVAL;  // 1 day
            mwarn("At module '%s': Interval must be a multiple of one day. New interval value: 1d.", WM_SCA_CONTEXT.name);
        }
    }

    return 0;
}
