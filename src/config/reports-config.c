/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "reports-config.h"
#include "config.h"


/* Filter argument */
static int _filter_arg(char *mystr)
{
    if (!mystr) {
        return (0);
    }

    while (*mystr) {
        if ((*mystr >= 'a' && *mystr <= 'z') ||
                (*mystr >= 'A' && *mystr <= 'Z') ||
                (*mystr >= '0' && *mystr <= '9') ||
                *mystr == '-' || *mystr == '_' || *mystr == '.') {
            mystr++;
        } else {
            *mystr = '-';
            mystr++;
        }
    }

    return (1);
}

int Read_CReports(XML_NODE node, void *config, __attribute__((unused)) void *config2)
{
    unsigned int i = 0, s = 0;

    /* XML definitions */
    const char *xml_title = "title";
    const char *xml_type = "type";
    const char *xml_categories = "category";
    const char *xml_group = "group";
    const char *xml_rule = "rule";
    const char *xml_level = "level";
    const char *xml_location = "location";
    const char *xml_showlogs = "showlogs";
    const char *xml_srcip = "srcip";
    const char *xml_user = "user";
    const char *xml_frequency = "frequency";
    const char *xml_email = "email_to";

    monitor_config *mon_config = (monitor_config *)config;

    /* Get any configured entry */
    if (mon_config->reports) {
        while (mon_config->reports[s]) {
            s++;
        }
    }

    /* Allocate the memory for the config */
    os_realloc(mon_config->reports, (s + 2) * sizeof(report_config *),
               mon_config->reports);
    os_calloc(1, sizeof(report_config), mon_config->reports[s]);
    mon_config->reports[s + 1] = NULL;

    /* Zero the elements */
    mon_config->reports[s]->title = NULL;
    mon_config->reports[s]->args = NULL;
    mon_config->reports[s]->relations = NULL;
    mon_config->reports[s]->type = NULL;
    mon_config->reports[s]->emailto = NULL;

    mon_config->reports[s]->r_filter.group = NULL;
    mon_config->reports[s]->r_filter.rule = NULL;
    mon_config->reports[s]->r_filter.level = NULL;
    mon_config->reports[s]->r_filter.location = NULL;
    mon_config->reports[s]->r_filter.srcip = NULL;
    mon_config->reports[s]->r_filter.user = NULL;
    mon_config->reports[s]->r_filter.related_group = 0;
    mon_config->reports[s]->r_filter.related_rule = 0;
    mon_config->reports[s]->r_filter.related_level = 0;
    mon_config->reports[s]->r_filter.related_location = 0;
    mon_config->reports[s]->r_filter.related_srcip = 0;
    mon_config->reports[s]->r_filter.related_user = 0;
    mon_config->reports[s]->r_filter.report_name = NULL;
    mon_config->reports[s]->r_filter.show_alerts = 0;

    /* Reading the XML */
    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_title) == 0) {
            if (!mon_config->reports[s]->title) {
                os_strdup(node[i]->content, mon_config->reports[s]->title);
            }
        } else if (strcmp(node[i]->element, xml_type) == 0) {
            if (strcmp(node[i]->content, "email") == 0) {
                if (!mon_config->reports[s]->type) {
                    os_strdup(node[i]->content, mon_config->reports[s]->type);
                }
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
            }
        } else if (strcmp(node[i]->element, xml_frequency) == 0) {
        } else if (strcmp(node[i]->element, xml_showlogs) == 0) {
            if (strcasecmp(node[i]->content, "yes") == 0) {
                mon_config->reports[s]->r_filter.show_alerts = 1;
            }
        } else if (strcmp(node[i]->element, xml_categories) == 0) {
            _filter_arg(node[i]->content);

            if (os_report_configfilter("group", node[i]->content,
                                       &mon_config->reports[s]->r_filter, REPORT_FILTER)) {
                merror(CONFIG_ERROR, "user argument");
            }
        } else if ((strcmp(node[i]->element, xml_group) == 0) ||
                   (strcmp(node[i]->element, xml_rule) == 0) ||
                   (strcmp(node[i]->element, xml_level) == 0) ||
                   (strcmp(node[i]->element, xml_location) == 0) ||
                   (strcmp(node[i]->element, xml_srcip) == 0) ||
                   (strcmp(node[i]->element, xml_user) == 0)) {
            int reportf = REPORT_FILTER;
            _filter_arg(node[i]->content);

            if (node[i]->attributes && node[i]->values) {
                if (node[i]->attributes[0] && node[i]->values[0]) {
                    if (strcmp(node[i]->attributes[0], "type") == 0) {
                        if (strcmp(node[i]->values[0], "relation") == 0) {
                            reportf = REPORT_RELATED;
                        } else {
                            mwarn("Invalid value for 'relation' attribute: '%s'. (ignored).", node[i]->values[0]);
                            i++;
                            continue;
                        }
                    } else {
                        mwarn("Invalid attribute: %s (ignored). ", node[i]->attributes[0]);
                        i++;
                        continue;
                    }
                }
            }

            if (os_report_configfilter(node[i]->element, node[i]->content,
                                       &mon_config->reports[s]->r_filter, reportf)) {
                merror("Invalid filter: %s:%s (ignored).", node[i]->element, node[i]->content);
            }
        } else if (strcmp(node[i]->element, xml_email) == 0) {
            mon_config->reports[s]->emailto = os_AddStrArray(node[i]->content, mon_config->reports[s]->emailto);
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    /* Set proper report type */
    mon_config->reports[s]->r_filter.report_type = REPORT_TYPE_DAILY;

    if (mon_config->reports[s]->emailto == NULL) {
        if (mon_config->reports[s]->title) {
            merror("No \"email to\" configured for the report '%s'. Ignoring it.", mon_config->reports[s]->title);
        } else {
            merror("No \"email to\" and title configured for report. Ignoring it.");
        }
    }

    if (!mon_config->reports[s]->title) {
        os_strdup("OSSEC Report (unnamed)", mon_config->reports[s]->title);
    }
    mon_config->reports[s]->r_filter.report_name = mon_config->reports[s]->title;

    return (0);
}

int Read_Monitor(XML_NODE node, void *config, __attribute__((unused)) void *config2) {
    unsigned int i = 0;

    /* XML definitions */
    const char *xml_check_agent_status = "check_agent_status";
    const char *xml_delete_old_agents = "delete_old_agents";
    const char *xml_thread_stack_size = "thread_stack_size";
    const char *xml_log_level = "log_level";

    monitor_config *mond_config = (monitor_config *)config;

    /* Reading the XML */
    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_check_agent_status) == 0) {
            SetConf(node[i]->content, &mond_config->monitor_agents, options.monitor.monitor_agents, xml_check_agent_status);
        } else if (strcmp(node[i]->element, xml_delete_old_agents) == 0) {
            SetConf(node[i]->content, &mond_config->delete_old_agents, options.monitor.delete_old_agents, xml_delete_old_agents);
        } else if (strcmp(node[i]->element, xml_log_level) == 0) {
            SetConf(node[i]->content, &mond_config->log_level, options.monitor.log_level, xml_log_level);
        } else if (strcmp(node[i]->element, xml_thread_stack_size) == 0) {
            SetConf(node[i]->content, &mond_config->thread_stack_size, options.global.thread_stack_size, xml_thread_stack_size);
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    return (0);
}

int Read_RotationMonitord(const OS_XML *xml, XML_NODE node, void *config, __attribute__((unused)) void *config2) {

    unsigned int i = 0;
    unsigned int j = 0;
    unsigned int k = 0;

    /* XML definitions */
    const char *xml_log = "log";
    const char *xml_enabled = "enabled";
    const char *xml_format = "format";
    const char *xml_rotation = "rotation";
    const char *xml_max_size = "max_size";
    const char *xml_min_size = "min_size";
    const char *xml_schedule = "schedule";
    const char *xml_rotate = "rotate";
    const char *xml_compress = "compress";
    const char *xml_maxage = "maxage";
    const char *xml_day_wait = "day_wait";

    XML_NODE children = NULL;
    XML_NODE rotation_children = NULL;

    monitor_config *rotation_config = (monitor_config *)config;

    /* Reading the XML */
    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_log) == 0) {
            // Get children
            if (!(children = OS_GetElementsbyNode(xml, node[i]))) {
                mdebug1("Empty configuration for module '%s'.", node[i]->element);
                return(OS_INVALID);
            }
            /* Read the configuration inside log tag */
            for (j = 0; children[j]; j++) {
                if (strcmp(children[j]->element, xml_enabled) == 0) {
                    if(strcmp(children[j]->content, "yes") == 0) {
                        rotation_config->enabled = 1;
                    } else if(strcmp(children[j]->content, "no") == 0) {
                        rotation_config->enabled = 0;
                    } else {
                        merror(XML_VALUEERR,children[j]->element,children[j]->content);
                        OS_ClearNode(children);
                        return(OS_INVALID);
                    }
                } else if (strcmp(children[j]->element, xml_format) == 0) {
                    const char *delim = ",";
                    char *format = NULL;
                    int format_it = 0;
                    format = strtok(children[j]->content, delim);

                    while (format) {
                        if (*format && !strncmp(format, "json", strlen(format))) {
                            rotation_config->ossec_log_json = 1;
                            format = strtok(NULL, delim);
                            format_it++;
                        } else if (*format && !strncmp(format, "plain", strlen(format))) {
                            rotation_config->ossec_log_plain = 1;
                            format = strtok(NULL, delim);
                            format_it++;
                        } else {
                            merror(XML_VALUEERR,children[j]->element,format);
                            OS_ClearNode(children);
                            return(OS_INVALID);
                        }
                    }
                }
                else if (strcmp(children[j]->element, xml_rotation) == 0) {
                    if (!(rotation_children = OS_GetElementsbyNode(xml, children[j]))) {
                        mdebug1("Empty configuration for module '%s'.", children[j]->element);
                        continue;
                    }
                    /* Read the configuration inside rotation tag */
                    for (k = 0; rotation_children[k]; k++) {
                        if (strcmp(rotation_children[k]->element, xml_max_size) == 0) {
                            char *end;
                            char c;
                            rotation_config->size_rotate = strtol(rotation_children[k]->content, &end, 10);
                            switch (sscanf(rotation_children[k]->content, "%ld%c", &rotation_config->max_size, &c)) {
                                case 1:
                                    break;
                                case 2:
                                    switch (c) {
                                        case 'G':
                                        case 'g':
                                            rotation_config->max_size *= 1073741824;
                                            break;
                                        case 'M':
                                        case 'm':
                                            rotation_config->max_size *= 1048576;
                                            break;
                                        case 'K':
                                        case 'k':
                                            rotation_config->max_size *= 1024;
                                            break;
                                        case 'B':
                                        case 'b':
                                            break;
                                        default:
                                            merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                            OS_ClearNode(rotation_children);
                                            OS_ClearNode(children);
                                            return (OS_INVALID);
                                    }
                                    break;
                                default:
                                    merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                    OS_ClearNode(rotation_children);
                                    OS_ClearNode(children);
                                    return (OS_INVALID);
                            }
                            rotation_config->size_units = c;
                            if (rotation_config->max_size < 1048576) {
                                merror("The minimum allowed value for '%s' is 1 MB.", rotation_children[k]->element);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }
                        } else if (strcmp(rotation_children[k]->element, xml_min_size) == 0) {
                            char *end;
                            char c;
                            rotation_config->min_size_rotate = strtol(rotation_children[k]->content, &end, 10);
                            switch (sscanf(rotation_children[k]->content, "%ld%c", &rotation_config->min_size, &c)) {
                                case 1:
                                    break;
                                case 2:
                                    switch (c) {
                                        case 'G':
                                        case 'g':
                                            rotation_config->min_size *= 1073741824;
                                            rotation_config->min_size_units = 'G';
                                            break;
                                        case 'M':
                                        case 'm':
                                            rotation_config->min_size *= 1048576;
                                            rotation_config->min_size_units = 'M';
                                            break;
                                        case 'K':
                                        case 'k':
                                            rotation_config->min_size *= 1024;
                                            rotation_config->min_size_units = 'K';
                                            break;
                                        case 'B':
                                        case 'b':
                                            rotation_config->min_size_units = 'B';
                                            break;
                                        default:
                                            merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                            OS_ClearNode(rotation_children);
                                            OS_ClearNode(children);
                                            return (OS_INVALID);
                                    }
                                    break;
                                default:
                                    merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                    OS_ClearNode(rotation_children);
                                    OS_ClearNode(children);
                                    return (OS_INVALID);
                            }
                            if (rotation_config->min_size < 1048576) {
                                merror("The minimum allowed value for '%s' is 1 MB.", rotation_children[k]->element);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_schedule) == 0) {
                            char c;
                            char *end;
                            rotation_config->interval = strtol(rotation_children[k]->content, &end, 10);
                            switch (sscanf(rotation_children[k]->content, "%ld%c", &rotation_config->interval, &c)) {
                                case 0:
                                    if (rotation_config->interval =  day_to_int(rotation_children[k]->content), rotation_config->interval) {
                                        rotation_config->interval_units = 'w';
                                    } else {
                                        merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                        OS_ClearNode(rotation_children);
                                        OS_ClearNode(children);
                                        return (OS_INVALID);
                                    }
                                    break;
                                case 2:
                                    switch (c) {
                                        case 'm':
                                            rotation_config->interval_units = 'm';
                                            break;
                                        case 'h':
                                            rotation_config->interval_units = 'h';
                                            break;
                                        default:
                                            merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                            OS_ClearNode(rotation_children);
                                            OS_ClearNode(children);
                                            return (OS_INVALID);
                                    }
                                    break;
                                default:
                                    merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                    OS_ClearNode(rotation_children);
                                    OS_ClearNode(children);
                                    return (OS_INVALID);
                            }
                            if ((24 % rotation_config->interval != 0 && !strcmp(&rotation_config->interval_units, "h"))
                                || (rotation_config->interval > 60 || rotation_config->interval < 1) ||
                                (24*60 % rotation_config->interval != 0 && !strcmp(&rotation_config->interval_units, "m"))) {
                                merror("Value for 'schedule' in <log> not allowed. Allowed values: [1h, 2h, 3h, 4h, 6h, "
                                       "8h, 12h, monday, tuesday, wednesday, thursday, friday, saturday, sunday].");
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }
                        } else if (strcmp(rotation_children[k]->element, xml_rotate) == 0) {
                            char *end;
                            rotation_config->rotate = strtol(rotation_children[k]->content, &end, 10);
                            if (*end != '\0') {
                                merror(XML_VALUEERR, rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return OS_INVALID;
                            }
                            if(rotation_config->rotate < 1 && rotation_config->rotate != -1) {
                                mwarn("Minimum value for 'rotate' in <logs> not allowed. It will be set to 1.");
                                rotation_config->rotate = 1;
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_enabled) == 0) {
                            if(strcmp(rotation_children[k]->content, "yes") == 0) {
                                rotation_config->rotation_enabled = 1;
                            } else if(strcmp(rotation_children[k]->content, "no") == 0) {
                                rotation_config->rotation_enabled = 0;
                            } else {
                                merror(XML_VALUEERR,rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return(OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_compress) == 0) {
                            if(strcmp(rotation_children[k]->content, "yes") == 0) {
                                rotation_config->compress_rotation = 1;
                            } else if(strcmp(rotation_children[k]->content, "no") == 0) {
                                rotation_config->compress_rotation = 0;
                            } else {
                                merror(XML_VALUEERR,rotation_children[k]->element, rotation_children[k]->content);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return(OS_INVALID);
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_maxage) == 0) {
                            char *end;
                            rotation_config->maxage = strtol(rotation_children[k]->content, &end, 10);
                            if (rotation_config->maxage < 0) {
                                merror("The minimum allowed value for '%s' is 0 (disabled).", rotation_children[k]->element);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }  else if (rotation_config->maxage > 500) {
                                mwarn("Maximum value for 'keep' in <logs> not allowed. It will be set to 500 days.");
                                rotation_config->maxage = 500;
                            }
                        } else if(strcmp(rotation_children[k]->element, xml_day_wait) == 0) {
                            char *end;
                            rotation_config->day_wait = strtol(rotation_children[k]->content, &end, 10);
                            if (rotation_config->day_wait < 0) {
                                merror("The minimum allowed value for '%s' is 0 seconds.", rotation_children[k]->element);
                                OS_ClearNode(rotation_children);
                                OS_ClearNode(children);
                                return (OS_INVALID);
                            }  else if (rotation_config->day_wait > 600) {
                                mwarn("Maximum value for 'day_wait' in <logs> not allowed. It will be set to 600 seconds.");
                                rotation_config->day_wait = 500;
                            }
                        } else {
                            merror(XML_ELEMNULL);
                            OS_ClearNode(rotation_children);
                            OS_ClearNode(children);
                            return OS_INVALID;
                        }
                    }
                    OS_ClearNode(rotation_children);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        }
        i++;
    }

    if(!rotation_config->enabled) {
        rotation_config->ossec_log_json = 0;
        rotation_config->ossec_log_plain = 0;
    }

    if(!rotation_config->ossec_log_json && ! rotation_config->ossec_log_plain) {
        rotation_config->ossec_log_plain = 1;
    }

    if (rotation_config->min_size > 0 && rotation_config->max_size > 0) {
        merror("'max_size' and 'min_size' options cannot be used together for log rotation.");
        return OS_INVALID;
    }

    return (0);
}

