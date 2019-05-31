/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 30, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

 #include "wazuh_modules/wmodules.h"
 #include "config.h"

int Read_WDatabase(const OS_XML *xml, XML_NODE node, void *d1)
{
    int i = 0;

    wm_database *wm_db;
    wm_db = (wm_database *) d1;

    /* XML Definitions */
    const char *max_queued_events = "max_queued_events";
    /* Sync Block */
    const char *xml_sync = "sync";
    const char *xml_sync_agents = "agents"; 
    const char *xml_sync_syscheck = "syscheck"; 
    const char *xml_sync_rootcheck = "rootcheck"; 
    const char *xml_full_sync = "full"; 
    const char *xml_real_time = "real_time"; 
    const char *xml_interval = "interval"; 

    if (!wm_db) {
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
        } else if (strcmp(node[i]->element, max_queued_events) == 0) {
            SetConf(node[i]->content, &wm_db->max_queued_events, options.wazuh_database.max_queued_events, max_queued_events);
        } else if (strcmp(node[i]->element, xml_sync) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_sync_agents)) {
                    SetConf(children[j]->content, &wm_db->sync_agents, options.wazuh_database.sync_agents, xml_sync_agents);
                } else if (!strcmp(children[j]->element, xml_sync_syscheck)) {
                    SetConf(children[j]->content, &wm_db->sync_syscheck, options.wazuh_database.sync_syscheck, xml_sync_syscheck);
                } else if (!strcmp(children[j]->element, xml_sync_rootcheck)) {
                    SetConf(children[j]->content, &wm_db->sync_rootcheck, options.wazuh_database.sync_rootcheck, xml_sync_rootcheck);
                } else if (!strcmp(children[j]->element, xml_full_sync)) {
                    SetConf(children[j]->content, &wm_db->full_sync, options.wazuh_database.full_sync, xml_full_sync);
                } else if (!strcmp(children[j]->element, xml_real_time)) {
                    SetConf(children[j]->content, &wm_db->real_time, options.wazuh_database.real_time, xml_real_time);
                } else if (!strcmp(children[j]->element, xml_interval)) {
                    SetConf(children[j]->content, &wm_db->interval, options.wazuh_database.interval, xml_interval);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }

        i++;
    }

    return (0);
}