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
static const char *XML_IGNORE = "ignore";
static const char *XML_SCAN_DAY = "day";
static const char *XML_WEEK_DAY = "wday";
static const char *XML_TIME = "time";
static const char *XML_INTERVAL = "interval";
static const char *XML_SCAN_ON_START= "scan_on_start";
static const char *XML_SET = "set";
static const char *XML_RULES = "rules";
static const char *XML_RULE = "rule";
static const char *XML_PATH = "path";
static const char *XML_DESCRIPTION = "description";
static const char *XML_NAME = "name";
static const char *XML_RECURSIVE = "recursive";
static const char *XML_TIMEOUT = "timeout";
static const char *XML_COMPILED_RULES = "compiled_rules_directory";
static const char *XML_PROCESSES = "scan_processes";
static const char *XML_RESTRICT_PROCESS = "restrict";
static const char *XML_EXCLUDE = "exclude";
static const char *XML_EXTERNAL_VARIABLES = "external_variables";
static unsigned int sets = 0;
static unsigned external_variables = 0;

static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

static wm_yara_set_t *init_set() {
    wm_yara_set_t *set;
    
    os_calloc(1, sizeof(wm_yara_set_t), set);
    set->enabled = 1;
    set->scan_processes = 0;
    set->compiled_rules = NULL;
    set->exclude_hash = NULL;
    set->exclude_path = NULL;
    set->path = NULL;
    set->description = NULL;
    set->name = NULL;

    return set;
}

// Reading function
int wm_yara_read(const OS_XML *xml,xml_node **nodes, wmodule *module)
{
    unsigned int i;
    int month_interval = 0;
    wm_yara_t *yara;

    if(!module->data) {
        os_calloc(1, sizeof(wm_yara_t), yara);
        yara->enabled = 1;
        yara->scan_on_start = 1;
        yara->scan_wday = -1;
        yara->scan_day = 0;
        yara->scan_time = NULL;
        yara->alert_msg = NULL;
        yara->queue = -1;
        yara->interval = WM_DEF_INTERVAL / 2;
        yara->compiled_rules_directory = NULL;
        yara->external_variables = NULL;

        os_realloc(yara->set, 2 * sizeof(wm_yara_set_t *), yara->set);

        wm_yara_set_t *set = init_set();

        yara->set[0] = set;
        yara->set[1] = NULL;

        os_realloc(yara->set[0]->compiled_rules, 1 * sizeof(YR_RULES *), yara->set[0]->compiled_rules);
        yara->set[0]->compiled_rules[0] = NULL;

        module->context = &WM_YARA_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = yara;
    } 

    yara = module->data;
    
    if (!nodes)
        return 0;

    if(!yara->alert_msg) {
        /* We store up to 255 alerts in there */
        os_calloc(256, sizeof(char *), yara->alert_msg);
        int c = 0;
        while (c <= 255) {
            yara->alert_msg[c] = NULL;
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
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_YARA_CONTEXT.name);
                return OS_INVALID;
            }

            yara->enabled = enabled;
        }
        else if (!strcmp(nodes[i]->element, XML_WEEK_DAY))
        {
            yara->scan_wday = w_validate_wday(nodes[i]->content);
            if (yara->scan_wday < 0 || yara->scan_wday > 6) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            }
        }
        else if (!strcmp(nodes[i]->element, XML_SCAN_DAY)) {
            if (!OS_StrIsNum(nodes[i]->content)) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            } else {
                yara->scan_day = atoi(nodes[i]->content);
                if (yara->scan_day < 1 || yara->scan_day > 31) {
                    merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                    return (OS_INVALID);
                }
            }
        }
        else if (!strcmp(nodes[i]->element, XML_TIME))
        {
            yara->scan_time = w_validate_time(nodes[i]->content);
            if (!yara->scan_time) {
                merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                return (OS_INVALID);
            }
        }
        else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            yara->interval = strtoul(nodes[i]->content, &endptr, 0);

            if (yara->interval == 0 || yara->interval == UINT_MAX) {
                merror("Invalid interval at module '%s'", WM_YARA_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'M':
                month_interval = 1;
                yara->interval *= 60; // We can`t calculate seconds of a month
                break;
            case 'w':
                yara->interval *= 604800;
                break;
            case 'd':
                yara->interval *= 86400;
                break;
            case 'h':
                yara->interval *= 3600;
                break;
            case 'm':
                yara->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid interval at module '%s'", WM_YARA_CONTEXT.name);
                return OS_INVALID;
            }

            if (yara->interval < 60) {
                mwarn("At module '%s': Interval must be greater than 60 seconds. New interval value: 60s.", WM_YARA_CONTEXT.name);
                yara->interval = 60;
            }
        }
        else if (!strcmp(nodes[i]->element, XML_SCAN_ON_START))
        {
            int scan_on_start = eval_bool(nodes[i]->content);

            if(scan_on_start == OS_INVALID)
            {
                merror("Invalid content for tag '%s' at module '%s'.", XML_SCAN_ON_START, WM_YARA_CONTEXT.name);
                return OS_INVALID;
            }

            yara->scan_on_start = scan_on_start;
        }
        else if (!strcmp(nodes[i]->element, XML_SET))
        {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, nodes[i]), !children) {
                return OS_INVALID;
            }

            /* Alloc memory for set */ 
            if (yara->set[sets] == NULL) {
                os_realloc(yara->set, (sets + 2) * sizeof(wm_yara_set_t *), yara->set);

                wm_yara_set_t *set = init_set();

                yara->set[sets] = set;
                yara->set[sets + 1 ] = NULL;

                os_realloc(yara->set[sets]->compiled_rules, 1 * sizeof(YR_RULES *), yara->set[sets]->compiled_rules);
                yara->set[sets]->compiled_rules[0] = NULL;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, XML_NAME) == 0) {
                    /* Search for repeated set */
                    int z = 0;
                    for (z = 0; yara->set[z]; z++) {
                        if (yara->set[z]->name) {
                            if (strcmp(yara->set[z]->name, children[j]->content) == 0) {
                                wm_yara_read_set(&yara,xml,children,z);
                                goto next_set;
                            }
                        } 
                    }
                }
            }

            wm_yara_read_set(&yara,xml,children,sets);
next_set:
            sets++;
            OS_ClearNode(children);
        }
        else if (!strcmp(nodes[i]->element, XML_COMPILED_RULES))
        {
            if(strlen(nodes[i]->content) >= PATH_MAX) {
                merror("Compiled rules directory is too long at module '%s'. Max directory length is %d", WM_YARA_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty compiled rules directory key value at '%s'.", WM_YARA_CONTEXT.name);
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content,yara->compiled_rules_directory);
        }
        else
        {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_YARA_CONTEXT.name);
        }
    }

    // Validate scheduled scan parameters and interval value

    if (yara->scan_day && (yara->scan_wday >= 0)) {
        merror("At module '%s': 'day' is not compatible with 'wday'.", WM_YARA_CONTEXT.name);
        return OS_INVALID;
    } else if (yara->scan_day) {
        if (!month_interval) {
            mwarn("At module '%s': Interval must be a multiple of one month. New interval value: 1M.", WM_YARA_CONTEXT.name);
            yara->interval = 60; // 1 month
        }
        if (!yara->scan_time)
            yara->scan_time = strdup("00:00");
    } else if (yara->scan_wday >= 0) {
        if (w_validate_interval(yara->interval, 1) != 0) {
            yara->interval = 604800;  // 1 week
            mwarn("At module '%s': Interval must be a multiple of one week. New interval value: 1w.", WM_YARA_CONTEXT.name);
        }
        if (yara->interval == 0)
            yara->interval = 604800;
        if (!yara->scan_time)
            yara->scan_time = strdup("00:00");
    } else if (yara->scan_time) {
        if (w_validate_interval(yara->interval, 0) != 0) {
            yara->interval = WM_DEF_INTERVAL;  // 1 day
            mwarn("At module '%s': Interval must be a multiple of one day. New interval value: 1d.", WM_YARA_CONTEXT.name);
        }
    }
    
    return 0;
}

int wm_yara_read_set(wm_yara_t **yara,const OS_XML *xml,xml_node **nodes,int index) {
    int i;
    int rules = 0;
    int paths = 0;

    for (i = 0; nodes[i]; i++) {

        if (!nodes[i]->element)
        {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_RULES))
        {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, nodes[i]), !children) {
                return OS_INVALID;
            }

            int  j;
            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, XML_RULE) == 0) {
                    int enabled = 1;
                    int rule_found = 0;

                    if (children[j]->attributes && children[j]->values) {

                        int z = 0;
                        for (z = 0; children[j]->attributes[z]; z++) {
                            if(strcmp(children[j]->attributes[z],XML_ENABLED) == 0){
                                if (children[j]->values[z]) {
                                    if(strcmp(children[j]->values[z],"no") == 0){
                                        enabled = 0;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    
                    if (strlen(children[j]->content) >= PATH_MAX) {
                        merror("Rule path is too long at module '%s'. Max path length is %d", WM_YARA_CONTEXT.name,PATH_MAX);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    } else if (strlen(children[j]->content) == 0) {
                        merror("Empty rule value at '%s'.", WM_YARA_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    if ((*yara)->set[index]->rule) {
                        int i;
                        for( i = 0; (*yara)->set[index]->rule[i]; i++) {
                            if (!strcmp((*yara)->set[index]->rule[i]->path,children[j]->content)) {
                                (*yara)->set[index]->rule[i]->enabled = enabled;
                                rule_found = 1;
                                break;
                            }
                        }
                    }

                    if (!rule_found && enabled) {
                        os_realloc((*yara)->set[index]->rule, (rules + 2) * sizeof(wm_yara_rule_t *), (*yara)->set[index]->rule);
                        wm_yara_rule_t *rule;
                        os_calloc(1,sizeof(wm_yara_rule_t),rule);

                        rule->enabled = enabled;

                        if (strstr(children[j]->content, "etc/shared/") != NULL ) {
                            rule->remote = 1;
                        } else {
                            rule->remote = 0;
                        }

                        if (children[j]->attributes && children[j]->values) {

                            int z = 0;
                            for (z = 0; children[j]->attributes[z]; z++) {

                                /* Read description */
                                if (strcmp(children[j]->attributes[z],XML_DESCRIPTION) == 0) {
                                    if (children[j]->values[z]) {
                                        os_strdup(children[j]->values[z],rule->description);
                                    }
                                    continue;
                                }

                                /* Read rule timeout */
                                if (strcmp(children[j]->attributes[z],XML_TIMEOUT) == 0) {
                                    if (children[j]->values[z]) {
                                        rule->timeout = atoi(children[j]->values[z]);
                                    }
                                }
                            }
                        }
                        
                        os_strdup(children[j]->content,rule->path);
                        (*yara)->set[index]->rule[rules] = rule;
                        (*yara)->set[index]->rule[rules + 1] = NULL;
                        rules++;
                    }
                   
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        }
        else if (!strcmp(nodes[i]->element, XML_PATH))
        {
            int ignore = 0;
            int recursive = 1;
            int file_found = 0;

            if(strlen(nodes[i]->content) >= PATH_MAX) {
                merror("Path is too long at module '%s'. Max path length is %d", WM_YARA_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty file value at '%s'.", WM_YARA_CONTEXT.name);
                return OS_INVALID;
            }

            /* Read ignore, recursive attribute */
            if (nodes[i]->attributes && nodes[i]->values) {
                int z = 0;
                for (z = 0; nodes[i]->attributes[z]; z++) {
                    if(strcmp(nodes[i]->attributes[z],XML_IGNORE) == 0){
                        if (nodes[i]->values[z]) {
                            if(strcmp(nodes[i]->values[z],"yes") == 0){
                                ignore = 1;
                            }
                        }
                    }
                    if(strcmp(nodes[i]->attributes[z],XML_RECURSIVE) == 0){
                        if (nodes[i]->values[z]) {
                            if(strcmp(nodes[i]->values[z],"no") == 0){
                                recursive = 0;
                            }
                        }
                    }
                }
            }

            if ((*yara)->set[index]->path) {
                int z;
                for (z = 0; (*yara)->set[index]->path[z]; z++) {
                    if (!strcmp((*yara)->set[index]->path[z]->path,nodes[i]->content)) {
                        (*yara)->set[index]->path[z]->ignore = ignore;
                        file_found = 1;
                        break;
                    }
                }
            }

            if (!file_found) {
                os_realloc((*yara)->set[index]->path, (paths + 2) * sizeof(wm_yara_path_t *), (*yara)->set[index]->path);
                wm_yara_path_t *path;
                os_calloc(1,sizeof(wm_yara_path_t),path);

                path->ignore = ignore;
                path->recursive = recursive;
                os_strdup(nodes[i]->content,path->path);

                (*yara)->set[index]->path[paths] = path;
                (*yara)->set[index]->path[paths + 1] = NULL;
                paths++;
            }
        }
        else if (!strcmp(nodes[i]->element, XML_PROCESSES))
        {
            int scan_processes = eval_bool(nodes[i]->content);

            if (scan_processes == OS_INVALID)
            {
                merror("Invalid content for tag '%s' at module '%s'.", XML_PROCESSES, WM_YARA_CONTEXT.name);
                return OS_INVALID;
            }

            (*yara)->set[index]->scan_processes = scan_processes;

            if(nodes[i]->attributes && nodes[i]->values) {
                if (strcmp(*nodes[i]->attributes,XML_RESTRICT_PROCESS) == 0) {
                    os_strdup(*nodes[i]->values, (*yara)->restrict_processes);
                }
            }
        }
        else if (!strcmp(nodes[i]->element, XML_DESCRIPTION))
        {
            if (strlen(nodes[i]->content) >= OS_SIZE_2048) {
                merror("Description is too long at module '%s'. Max description length is %d", WM_YARA_CONTEXT.name,OS_SIZE_2048);
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content,(*yara)->set[index]->description);
        }
        else if (!strcmp(nodes[i]->element, XML_NAME))
        {
            if (strlen(nodes[i]->content) >= OS_SIZE_2048) {
                merror("Name is too long at module '%s'. Max name length is %d", WM_YARA_CONTEXT.name,OS_SIZE_2048);
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content,(*yara)->set[index]->name);
        }
        else if (!strcmp(nodes[i]->element, XML_ENABLED))
        {
            int enabled = eval_bool(nodes[i]->content);

            if(enabled == OS_INVALID){
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_YARA_CONTEXT.name);
                return OS_INVALID;
            }

            (*yara)->set[index]->enabled = enabled;
        }
        else if (!strcmp(nodes[i]->element, XML_EXCLUDE))
        {
            if(strlen(nodes[i]->content) >= PATH_MAX) {
                merror("Exclude path is too long at module '%s'. Max exclude path length is %d", WM_YARA_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            } else if (strlen(nodes[i]->content) == 0) {
                merror("Empty exclude path value at '%s'.", WM_YARA_CONTEXT.name);
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content,(*yara)->set[index]->exclude_path);
        }
        else
        {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_YARA_CONTEXT.name);
        }
    }

    return 0;
}
