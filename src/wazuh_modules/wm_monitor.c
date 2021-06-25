/*
 * Wazuh MONITOR
 * Copyright (C) 2015-2021, Wazuh Inc.
 * April 26, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdlib.h>
#include "wm_monitor.h"
#include "wmodules.h"
#include "defs.h"
#include "os_net/os_net.h"

#define DEFAULT_NO_AGENT 0
#define DEFAULT_DAY_WAIT -1

// Location field for event sending
#define WM_MONITOR_LOCATION "monitor"

static void* wm_monitor_main(wm_monitor_t *data);        // Module main function. It won't return
static void wm_monitor_destroy(wm_monitor_t *data);      // Destroy data
cJSON *wm_monitor_dump(const wm_monitor_t *data);

const wm_context WM_MONITOR_CONTEXT = {
    WM_MONITOR_LOCATION,
    (wm_routine)wm_monitor_main,
    (wm_routine)(void *)wm_monitor_destroy,
    (cJSON * (*)(const void *))wm_monitor_dump,
    NULL,
    NULL,
};

static void wm_monitor_log_config(wm_monitor_t *data)
{
    cJSON * config_json = wm_monitor_dump(data);
    if (config_json) {
        char * config_str = cJSON_PrintUnformatted(config_json);
        if (config_str) {
            mtdebug1(WM_MONITOR_LOGTAG, "%s", config_str);
            cJSON_free(config_str);
        }
        cJSON_Delete(config_json);
    }
}

void* wm_monitor_main(wm_monitor_t *data) {
    /*/if (!data->flags.enabled) {
        mtinfo(WM_MONITOR_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }*/

    mtdebug1(WM_MONITOR_LOGTAG, "Starting Monitor.");

    /* Initialize global variables */
    mond.a_queue = 0;

    data->mond = &mond;
    data->worker_node = &worker_node;
    data->agents_to_alert_hash = agents_to_alert_hash;
    data->mond_time_control = &mond_time_control;

    /* Reading configuration */
    if (MonitordConfig(OSSECCONF, &mond, DEFAULT_NO_AGENT, DEFAULT_DAY_WAIT) != OS_SUCCESS ) {
        mterror(WM_MONITOR_LOGTAG, CONFIG_ERROR, OSSECCONF);
    }

    wm_monitor_log_config(data);

    /* If we have any reports configured, read smtp/emailfrom */
    if (mond.reports) {

        OS_XML xml;
        char *tmpsmtp;

        const char *(xml_smtp[]) = {"wazuh_config", "global", "smtp_server", NULL};
        const char *(xml_from[]) = {"wazuh_config", "global", "email_from", NULL};
        const char *(xml_idsname[]) = {"wazuh_config", "global", "email_idsname", NULL};

        if (OS_ReadXML(OSSECCONF, &xml) < 0) {
            mterror_exit(WM_MONITOR_LOGTAG, CONFIG_ERROR, OSSECCONF);
        }

        tmpsmtp = OS_GetOneContentforElement(&xml, xml_smtp);
        mond.emailfrom = OS_GetOneContentforElement(&xml, xml_from);
        mond.emailidsname = OS_GetOneContentforElement(&xml, xml_idsname);

        if (tmpsmtp && mond.emailfrom) {
            if (tmpsmtp[0] == '/') {
                os_strdup(tmpsmtp, mond.smtpserver);
            } else {
                mond.smtpserver = OS_GetHost(tmpsmtp, 5);
                if (!mond.smtpserver) {
                    mterror(WM_MONITOR_LOGTAG, INVALID_SMTP, tmpsmtp);
                    if (mond.emailfrom) {
                        free(mond.emailfrom);
                    }
                    mond.emailfrom = NULL;
                    mterror(WM_MONITOR_LOGTAG, "Invalid SMTP server.  Disabling email reports.");
                }
            }
        } else {
            if (tmpsmtp) {
                free(tmpsmtp);
            }
            if (mond.emailfrom) {
                free(mond.emailfrom);
            }

            mond.emailfrom = NULL;
            mterror(WM_MONITOR_LOGTAG, "SMTP server or 'email from' missing. Disabling email reports.");
        }

        OS_ClearXML(&xml);
    }

    // Read the cluster status and the node type from the configuration file
    // Do not monitor agents in client/worker nodes
    switch (w_is_worker()){
        case -1:
            mterror(WM_MONITOR_LOGTAG, "Invalid option at cluster configuration");
            break;
        case 0:
            worker_node = false;
            break;
        case 1:
            mtdebug1(WM_MONITOR_LOGTAG, "Cluster client node: Disabled the agent monitoring");
            worker_node = true;
            mond.monitor_agents = 0;
            break;
    }

    /* Starting monitor */
    mtdebug1(WM_MONITOR_LOGTAG, "Module Started.");
    Monitord();
    mtinfo(WM_MONITOR_LOGTAG, "Module finished.");

    return 0;
}

void wm_monitor_destroy(wm_monitor_t *data) {
    mtinfo(WM_MONITOR_LOGTAG, "Destroy received for monitor.");
    os_free(data);
}

cJSON *wm_monitor_dump(const wm_monitor_t *data) {
    (void)data;
    cJSON *root = cJSON_CreateObject();
    cJSON *internal_options = getMonitorInternalOptions();
    cJSON *monitor_global_options = getMonitorGlobalOptions();
    cJSON *report_options = getReportsOptions();
    cJSON_AddItemToObject(root, "internal_options", internal_options);
    cJSON_AddItemToObject(root, "monitor_global_options", monitor_global_options);
    cJSON_AddItemToObject(root, "report_options", report_options);
    return root;
}
