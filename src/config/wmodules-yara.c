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
static const char *XML_RULES = "rules";
static const char *XML_RULE = "rule";
static const char *XML_FILES = "files";
static const char *XML_FILE = "file";
static const char *XML_DESCRIPTION = "description";
static const char *XML_RECURSIVE = "recursive";
static const char *XML_TIMEOUT = "timeout";
static const char *XML_DIRECTORIES = "directories";
static const char *XML_DIRECTORY = "directory";
static const char *XML_COMPILED_RULES = "compiled_rules_directory";
static unsigned int rules = 0;
static unsigned int directories = 0;
static unsigned int files = 0;

static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
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
        yara->skip_nfs = 1;
        yara->alert_msg = NULL;
        yara->queue = -1;
        yara->interval = WM_DEF_INTERVAL / 2;
        yara->rule = NULL;
        yara->directory = NULL;
        yara->compiled_rules_directory = NULL;
        os_realloc(yara->compiled_rules, 1 * sizeof(YR_RULES *), yara->compiled_rules);
        yara->compiled_rules[0] = NULL;
        module->context = &WM_YARA_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = yara;
        rules = 0;
        directories = 0;
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
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_YARA_CONTEXT.name);
                return OS_INVALID;
            }

            yara->scan_on_start = scan_on_start;
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

                    if(children[j]->attributes && children[j]->values) {

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
                    
                    if(strlen(children[j]->content) >= PATH_MAX) {
                        merror("Rule path is too long at module '%s'. Max path length is %d", WM_YARA_CONTEXT.name,PATH_MAX);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    } else if (strlen(children[j]->content) == 0) {
                        merror("Empty rule value at '%s'.", WM_YARA_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    if(yara->rule) {
                        int i;
                        for(i = 0; yara->rule[i]; i++) {
                            if(!strcmp(yara->rule[i]->path,children[j]->content)) {
                                yara->rule[i]->enabled = enabled;
                                rule_found = 1;
                                break;
                            }
                        }
                    }

                    if(!rule_found && enabled) {
                        os_realloc(yara->rule, (rules + 2) * sizeof(wm_yara_rule_t *), yara->rule);
                        wm_yara_rule_t *rule;
                        os_calloc(1,sizeof(wm_yara_rule_t),rule);

                        rule->enabled = enabled;

                        if (strstr(children[j]->content, "etc/shared/") != NULL ) {
                            rule->remote = 1;
                        } else {
                            rule->remote = 0;
                        }

                        if(children[j]->attributes && children[j]->values) {

                            int z = 0;
                            for (z = 0; children[j]->attributes[z]; z++) {

                                /* Read description */
                                if(strcmp(children[j]->attributes[z],XML_DESCRIPTION) == 0) {
                                    if (children[j]->values[z]) {
                                        os_strdup(children[j]->values[z],rule->description);
                                    }
                                    continue;
                                }

                                /* Read rule timeout */
                                if(strcmp(children[j]->attributes[z],XML_TIMEOUT) == 0) {
                                    if (children[j]->values[z]) {
                                        rule->timeout = atoi(children[j]->values[z]);
                                    }
                                }
                            }
                        }
                        
                        os_strdup(children[j]->content,rule->path);
                        yara->rule[rules] = rule;
                        yara->rule[rules + 1] = NULL;
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
        else if (!strcmp(nodes[i]->element, XML_DIRECTORIES))
        {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, nodes[i]), !children) {
                return OS_INVALID;
            }

            int  j;
            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, XML_DIRECTORY) == 0) {
                    int ignore = 0;
                    int directory_found = 0;

                    if(children[j]->attributes && children[j]->values) {

                        int z = 0;
                        for (z = 0; children[j]->attributes[z]; z++) {
                            if(strcmp(children[j]->attributes[z],XML_IGNORE) == 0){
                                if (children[j]->values[z]) {
                                    if(strcmp(children[j]->values[z],"yes") == 0){
                                        ignore = 1;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    
                    if(strlen(children[j]->content) >= PATH_MAX) {
                        merror("Directory path is too long at module '%s'. Max path length is %d", WM_YARA_CONTEXT.name,PATH_MAX);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    } else if (strlen(children[j]->content) == 0) {
                        merror("Empty directory value at '%s'.", WM_YARA_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    if(yara->directory) {
                        int i;
                        for(i = 0; yara->directory[i]; i++) {
                            if(!strcmp(yara->directory[i]->path,children[j]->content)) {
                                yara->directory[i]->ignore = ignore;
                                directory_found = 1;
                                break;
                            }
                        }
                    }

                    if(!directory_found) {
                        os_realloc(yara->directory, (directories + 2) * sizeof(wm_yara_directory_t *), yara->directory);
                        wm_yara_directory_t *directory;
                        os_calloc(1,sizeof(wm_yara_directory_t),directory);

                        if(children[j]->attributes && children[j]->values) {
                            int z = 0;
                            for (z = 0; children[j]->attributes[z]; z++) {
                                if(strcmp(children[j]->attributes[z],XML_RECURSIVE) == 0){
                                    if (children[j]->values[z]) {
                                        if(strcmp(children[j]->values[z],"yes") == 0){
                                            directory->recursive = 1;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        directory->ignore = ignore;
                        
                        os_strdup(children[j]->content,directory->path);
                        yara->directory[directories] = directory;
                        yara->directory[directories + 1] = NULL;
                        directories++;
                    }
                   
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);

          
        }
        else if (!strcmp(nodes[i]->element, XML_FILES))
        {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, nodes[i]), !children) {
                return OS_INVALID;
            }

            int  j;
            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, XML_FILE) == 0) {
                    int ignore = 0;
                    int file_found = 0;

                    if(children[j]->attributes && children[j]->values) {

                        int z = 0;
                        for (z = 0; children[j]->attributes[z]; z++) {
                            if(strcmp(children[j]->attributes[z],XML_IGNORE) == 0){
                                if (children[j]->values[z]) {
                                    if(strcmp(children[j]->values[z],"no") == 0){
                                        ignore = 0;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    
                    if(strlen(children[j]->content) >= PATH_MAX) {
                        merror("File path is too long at module '%s'. Max path length is %d", WM_YARA_CONTEXT.name,PATH_MAX);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    } else if (strlen(children[j]->content) == 0) {
                        merror("Empty file value at '%s'.", WM_YARA_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    if(yara->file) {
                        int i;
                        for(i = 0; yara->file[i]; i++) {
                            if(!strcmp(yara->file[i]->path,children[j]->content)) {
                                yara->file[i]->ignore = ignore;
                                file_found = 1;
                                break;
                            }
                        }
                    }

                    if(!file_found) {
                        os_realloc(yara->file, (files + 2) * sizeof(wm_yara_file_t *), yara->file);
                        wm_yara_file_t *file;
                        os_calloc(1,sizeof(wm_yara_file_t),file);

                        file->ignore = ignore;
                        
                        os_strdup(children[j]->content,file->path);
                        yara->file[files] = file;
                        yara->file[files + 1] = NULL;
                        files++;
                    }
                   
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
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
