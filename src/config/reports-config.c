/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
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
            char *ncat = NULL;
            _filter_arg(node[i]->content);

            os_strdup(node[i]->content, ncat);

            if (os_report_configfilter("group", ncat,
                                       &mon_config->reports[s]->r_filter, REPORT_FILTER) < 0) {
                merror(CONFIG_ERROR, "user argument");
            }
        } else if ((strcmp(node[i]->element, xml_group) == 0) ||
                   (strcmp(node[i]->element, xml_rule) == 0) ||
                   (strcmp(node[i]->element, xml_level) == 0) ||
                   (strcmp(node[i]->element, xml_location) == 0) ||
                   (strcmp(node[i]->element, xml_srcip) == 0) ||
                   (strcmp(node[i]->element, xml_user) == 0)) {
            int reportf = REPORT_FILTER;
            char *ncat = NULL;
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

            os_strdup(node[i]->content, ncat);

            if (os_report_configfilter(node[i]->element, ncat,
                                       &mon_config->reports[s]->r_filter, reportf) < 0) {
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
