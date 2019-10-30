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
 #include "wazuh_db/wdb.h"
 #include "config.h"

int Read_WDatabase(const OS_XML *xml, XML_NODE node, void *d1, void *d2)
{
    int i = 0;

    wm_database *wm_db;
    wm_db = (wm_database *) d1;

    wdb_config *db_config;
    db_config = (wdb_config *) d2;

    /* XML Definitions */
    const char *xml_worker_pool_size = "worker_pool_size";
    const char *xml_commit_time = "commit_time";
    const char *xml_open_db_limit = "open_db_limit";
    const char *xml_rlimit_nofile = "rlimit_nofile";
    const char *xml_log_level = "log_level";
    const char *xml_thread_stack_size = "thread_stack_size";
    /* Global DB Block */
    const char *xml_global_db = "global_db";
    const char *xml_sync_agents = "sync_agents";
    const char *xml_sync_rootcheck = "sync_rootcheck";
    const char *xml_full_sync = "full_sync";
    const char *xml_real_time = "real_time";
    const char *xml_interval = "interval";
    const char *max_queued_events = "max_queued_events";

    if (!node)
        return 0;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (!strcmp(node[i]->element, xml_global_db)) {
            if (wm_db) {
                /* Get children */
                xml_node **children = NULL;
                if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                    return OS_INVALID;
                }

                int j;
                for (j = 0; children[j]; j++) {
                    if (!strcmp(children[j]->element, xml_sync_agents)) {
                        SetConf(children[j]->content, &wm_db->sync_agents, options.wazuh_database.sync_agents, xml_sync_agents);
                    } else if (!strcmp(children[j]->element, xml_sync_rootcheck)) {
                        SetConf(children[j]->content, &wm_db->sync_rootcheck, options.wazuh_database.sync_rootcheck, xml_sync_rootcheck);
                    } else if (!strcmp(children[j]->element, xml_full_sync)) {
                        SetConf(children[j]->content, &wm_db->full_sync, options.wazuh_database.full_sync, xml_full_sync);
                    } else if (!strcmp(children[j]->element, xml_real_time)) {
                        SetConf(children[j]->content, &wm_db->real_time, options.wazuh_database.real_time, xml_real_time);
                    } else if (!strcmp(children[j]->element, xml_interval)) {
                        SetConf(children[j]->content, &wm_db->interval, options.wazuh_database.interval, xml_interval);
                    } else if (!strcmp(children[j]->element, max_queued_events)) {
                        SetConf(children[j]->content, &wm_db->max_queued_events, options.wazuh_database.max_queued_events, max_queued_events);
                    } else {
                        merror(XML_ELEMNULL);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                }
                OS_ClearNode(children);
            }
        } else if (!strcmp(node[i]->element, xml_worker_pool_size)) {
            if (db_config)
                SetConf(node[i]->content, &db_config->worker_pool_size, options.wazuh_db.worker_pool_size, xml_worker_pool_size);
        } else if (!strcmp(node[i]->element, xml_commit_time)) {
            if (db_config)
                SetConf(node[i]->content, &db_config->commit_time, options.wazuh_db.commit_time, xml_commit_time);
        } else if (!strcmp(node[i]->element, xml_open_db_limit)) {
            if (db_config)
                SetConf(node[i]->content, &db_config->open_db_limit, options.wazuh_db.open_db_limit, xml_open_db_limit);
        } else if (!strcmp(node[i]->element, xml_rlimit_nofile)) {
            if (db_config)
                SetConf(node[i]->content, (int *) &db_config->rlimit_nofile, options.wazuh_db.rlimit_nofile, xml_rlimit_nofile);
        } else if (!strcmp(node[i]->element, xml_log_level)) {
            if (db_config)
                SetConf(node[i]->content, &db_config->log_level, options.wazuh_db.log_level, xml_log_level);
        } else if (!strcmp(node[i]->element, xml_thread_stack_size)) {
            if (db_config)
                SetConf(node[i]->content, &db_config->thread_stack_size, options.global.thread_stack_size, xml_thread_stack_size);
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }

        i++;
    }

    return (0);
}