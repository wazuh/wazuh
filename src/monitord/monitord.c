/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "cJSON.h"
#include "debug_op.h"
#include "hash_op.h"
#include "os_err.h"
#include "shared.h"
#include "monitord.h"
#include "config/config.h"
#include "string_op.h"
#include "wazuh_db/wdb.h"

/* Global variables */
monitor_config mond;
OSHash* agents_to_alert_hash;


void Monitord()
{
    int sock = -1;
    mond_counters counters;
    int *agents_array = NULL;
    unsigned int inode_it = 0;
    OSHashNode *agent_hash_node = NULL;
    cJSON *j_agent_info = NULL;
    cJSON *j_agent_status = NULL;
    cJSON *j_agent_lastkeepalive = NULL;
    cJSON *j_agent_name = NULL;
    cJSON *j_agent_ip = NULL;

    time_t tm;
    struct tm tm_result = { .tm_sec = 0 };

    char path[PATH_MAX];
    char path_json[PATH_MAX];
    struct stat buf;
    off_t size;

    int today = 0;
    int thismonth = 0;
    int thisyear = 0;

    char str[OS_SIZE_1024 + 1];

    /* Wait a few seconds to settle */
    sleep(10);

    memset(str, '\0', OS_SIZE_1024 + 1);

    /* Get current time before starting */
    tm = time(NULL);
    localtime_r(&tm, &tm_result);

    today = tm_result.tm_mday;
    thismonth = tm_result.tm_mon;
    thisyear = tm_result.tm_year + 1900;

    /* Set internal log path to rotate them */
#ifdef WIN32
    // ossec.log
    snprintf(path, PATH_MAX, "%s", LOGFILE);
    // ossec.json
    snprintf(path_json, PATH_MAX, "%s", LOGJSONFILE);
#else
    // /var/ossec/logs/ossec.log
    snprintf(path, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGFILE);
    // /var/ossec/logs/ossec.json
    snprintf(path_json, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOGJSONFILE);
#endif

    /* Connect to the message queue or exit */
    if ((mond.a_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
        merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
    }

    /* Send startup message */
    snprintf(str, OS_SIZE_1024 - 1, OS_AD_STARTED);
    if (SendMSG(mond.a_queue, str, ARGV0,
                LOCALFILE_MQ) < 0) {
        merror(QUEUE_SEND);
    }

    // Start com request thread
    w_create_thread(moncom_main, NULL);

    /* Starting counters */
    MonitorStartCounters(&counters);

    agents_to_alert_hash = OSHash_Create();
    if(!agents_to_alert_hash) {
        merror(MEM_ERROR, errno, strerror(errno));
    }

    /* Main monitor loop */
    while (1) {
        tm = time(NULL);
        localtime_r(&tm, &tm_result);

        if (mond.a_queue < 0) {
            /* Connect to the message queue */
            if ((mond.a_queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) > 0) {
                /* Send startup message */
                snprintf(str, OS_SIZE_1024 - 1, OS_AD_STARTED);
                if (SendMSG(mond.a_queue, str, ARGV0,
                            LOCALFILE_MQ) < 0) {
                    mond.a_queue = -1;  // We keep trying to reconnect next time.
                    merror(QUEUE_SEND);
                }
            }
        }

        /* In a local installation, there is no need to check agents */
        #ifndef LOCAL

        switch (MonitorCheckCounters(&counters)) {
            case 1:
                /* agents_disconnection_time counter */
                agents_array = wdb_disconnect_agents(&sock, mond.global.agents_disconnection_time);
                if (agents_array) {
                    for (int i = 0; agents_array[i] != -1; i++) {
                        if (OSHash_Numeric_Add_ex(agents_to_alert_hash, agents_array[i], (void*)1) == 0) {
                            mdebug1("Can't add agent ID '%d' to the alerts hash table",agents_array[i]);
                        }
                    }
                    os_free(agents_array);
                }
                break;
            case 2:
                /* agents_disconnection_alert_time counter */
                agent_hash_node = OSHash_Begin(agents_to_alert_hash, &inode_it);
                while (agent_hash_node) {
                    j_agent_info = wdb_get_agent_info(atoi(agent_hash_node->key), &sock);
                    if (j_agent_info) {
                        j_agent_status = cJSON_GetObjectItem(j_agent_info, "connection_status");
                        j_agent_lastkeepalive = cJSON_GetObjectItem(j_agent_info, "last_keepalive");
                        j_agent_name = cJSON_GetObjectItem(j_agent_info, "name");
                        j_agent_ip = cJSON_GetObjectItem(j_agent_info, "ip");

                        if (cJSON_IsString(j_agent_status) && j_agent_status->valuestring != NULL &&
                            cJSON_IsString(j_agent_name) && j_agent_name->valuestring != NULL &&
                            cJSON_IsString(j_agent_ip) && j_agent_ip->valuestring != NULL &&
                            cJSON_IsNumber(j_agent_lastkeepalive)) {

                                if (strcmp(j_agent_status->valuestring, "active") == 0) {
                                    /* The agent is now connected, removing from table */
                                    OSHash_Delete_ex(agents_to_alert_hash, agent_hash_node->key);
                                }

                                else if (strcmp(j_agent_status->valuestring, "disconnected") == 0 &&
                                        j_agent_lastkeepalive->valueint < (time(0) - mond.global.agents_disconnection_time + mond.global.agents_disconnection_alert_time)) {
                                    /* Generating the disconnection alert */
                                    char *agent_name_ip = NULL;
                                    os_strdup(j_agent_name->valuestring, agent_name_ip);
                                    wm_strcat(&agent_name_ip, j_agent_ip->valuestring, '-');
                                    monitor_agent_disconnection(agent_name_ip);
                                    OSHash_Delete_ex(agents_to_alert_hash, agent_hash_node->key);
                                    os_free(agent_name_ip);
                                }
                            }
                    } else {
                        mdebug1("Unable to retrieve agent's '%s' data from Wazuh DB", agent_hash_node->key);
                    }
                    cJSON_Delete(j_agent_info);
                    agent_hash_node = OSHash_Next(agents_to_alert_hash, &inode_it, agent_hash_node);
                }
                break;
            case 3:
                /* delete_old_agent counter */
                agents_array = wdb_get_agents_by_connection_status("disconnected", &sock);
                if (agents_array) {
                    for (int i = 0; agents_array[i] != -1; i++) {
                        j_agent_info = wdb_get_agent_info(agents_array[i], &sock);
                        if (j_agent_info) {
                            j_agent_name = cJSON_GetObjectItem(j_agent_info, "name");
                            j_agent_lastkeepalive = cJSON_GetObjectItem(j_agent_info, "last_keepalive");
                            j_agent_status = cJSON_GetObjectItem(j_agent_info, "connection_status");
                            j_agent_ip = cJSON_GetObjectItem(j_agent_info, "ip");

                            if (cJSON_IsString(j_agent_status) && j_agent_status->valuestring != NULL &&
                                cJSON_IsString(j_agent_name) && j_agent_name->valuestring != NULL &&
                                cJSON_IsString(j_agent_ip) && j_agent_ip->valuestring != NULL &&
                                cJSON_IsNumber(j_agent_lastkeepalive)) {

                                    if (strcmp(j_agent_status->valuestring, "disconnected") == 0 &&
                                        j_agent_lastkeepalive->valueint < (time(0) - mond.delete_old_agents * 60)) {
                                            char *agent_name_ip = NULL;
                                            os_strdup(j_agent_name->valuestring, agent_name_ip);
                                            wm_strcat(&agent_name_ip, j_agent_ip->valuestring, '-');
                                            if(!delete_old_agent(agent_name_ip)){
                                                snprintf(str, OS_SIZE_1024 - 1, OS_AG_REMOVED, agent_name_ip);

                                                if (SendMSG(mond.a_queue, str, ARGV0, LOCALFILE_MQ) < 0) {
                                                    mond.a_queue = -1;  // set an invalid fd so we can attempt to reconnect later on.
                                                    merror(QUEUE_SEND);
                                                }
                                            }
                                            os_free(agent_name_ip);
                                    }
                            cJSON_Delete(j_agent_info);
                            }
                        } else {
                            mdebug1("Unable to retrieve agent's '%s' data from Wazuh DB", agent_hash_node->key);
                        }
                    }
                os_free(agents_array);
                }
                break;
            default:;
        }
        #endif

        /* Day changed, deal with log files */
        if (today != tm_result.tm_mday) {
            if (mond.rotate_log) {
                sleep(mond.day_wait);
                /* Daily rotation and compression of ossec.log/ossec.json */
                w_rotate_log(mond.compress, mond.keep_log_days, 1, 0, mond.daily_rotations);
            }

            /* Generate reports */
            generate_reports(today, thismonth, thisyear, &tm_result);
            manage_files(today, thismonth, thisyear);

            today = tm_result.tm_mday;
            thismonth = tm_result.tm_mon;
            thisyear = tm_result.tm_year + 1900;
        } else if (mond.rotate_log && mond.size_rotate > 0) {
            if (stat(path, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.log */
                if ( (unsigned long) size >= mond.size_rotate) {
                    w_rotate_log(mond.compress, mond.keep_log_days, 0, 0, mond.daily_rotations);
                }
            }

            if (stat(path_json, &buf) == 0) {
                size = buf.st_size;
                /* If log file reachs maximum size, rotate ossec.json */
                if ( (unsigned long) size >= mond.size_rotate) {
                    w_rotate_log(mond.compress, mond.keep_log_days, 0, 1, mond.daily_rotations);
                }
            }
        }

        sleep(1);
    }
}

cJSON *getMonitorInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *monconf = cJSON_CreateObject();

    cJSON_AddNumberToObject(monconf,"day_wait",mond.day_wait);
    cJSON_AddNumberToObject(monconf,"compress",mond.compress);
    cJSON_AddNumberToObject(monconf,"sign",mond.sign);
    cJSON_AddNumberToObject(monconf,"monitor_agents",mond.monitor_agents);
    cJSON_AddNumberToObject(monconf,"keep_log_days",mond.keep_log_days);
    cJSON_AddNumberToObject(monconf,"rotate_log",mond.rotate_log);
    cJSON_AddNumberToObject(monconf,"size_rotate",mond.size_rotate);
    cJSON_AddNumberToObject(monconf,"daily_rotations",mond.daily_rotations);
    cJSON_AddNumberToObject(monconf,"delete_old_agents",mond.delete_old_agents);

    cJSON_AddItemToObject(root,"monitord",monconf);

    return root;
}

cJSON *getMonitorGlobalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *monconf = cJSON_CreateObject();

    cJSON_AddNumberToObject(monconf,"agents_disconnection_time",mond.global.agents_disconnection_time);
    cJSON_AddNumberToObject(monconf,"agents_disconnection_alert_time",mond.global.agents_disconnection_alert_time);

    cJSON_AddItemToObject(root,"monitord",monconf);

    return root;
}

cJSON *getReportsOptions(void) {

    cJSON *root = cJSON_CreateObject();
    unsigned int i;

    if (mond.reports) {
        cJSON *arr = cJSON_CreateArray();
        for (i=0;mond.reports[i];i++) {
            cJSON *rep = cJSON_CreateObject();
            if (mond.reports[i]->title) cJSON_AddStringToObject(rep,"title",mond.reports[i]->title);
            if (mond.reports[i]->r_filter.group) cJSON_AddStringToObject(rep,"group",mond.reports[i]->r_filter.group);
            if (mond.reports[i]->r_filter.rule) cJSON_AddStringToObject(rep,"rule",mond.reports[i]->r_filter.rule);
            if (mond.reports[i]->r_filter.level) cJSON_AddStringToObject(rep,"level",mond.reports[i]->r_filter.level);
            if (mond.reports[i]->r_filter.srcip) cJSON_AddStringToObject(rep,"srcip",mond.reports[i]->r_filter.srcip);
            if (mond.reports[i]->r_filter.user) cJSON_AddStringToObject(rep,"user",mond.reports[i]->r_filter.user);
            if (mond.reports[i]->r_filter.show_alerts) cJSON_AddStringToObject(rep,"showlogs","yes"); else cJSON_AddStringToObject(rep,"showlogs","no");
            if (mond.reports[i]->emailto) {
                unsigned int j = 0;
                cJSON *email = cJSON_CreateArray();
                while (mond.reports[i]->emailto[j]) {
                    cJSON_AddItemToArray(email, cJSON_CreateString(mond.reports[i]->emailto[j]));
                    j++;
                }
                cJSON_AddItemToObject(rep,"email_to",email);
            }
            cJSON_AddItemToArray(arr, rep);
        }
        cJSON_AddItemToObject(root,"reports",arr);
    }

    return root;
}

int MonitordConfig(const char *cfg, monitor_config *mond, int no_agents, short day_wait) {
    int modules = 0;

    /* Get config options */
    mond->day_wait = day_wait >= 0 ? day_wait : (short)getDefine_Int("monitord", "day_wait", 0, MAX_DAY_WAIT);
    mond->compress = (unsigned int) getDefine_Int("monitord", "compress", 0, 1);
    mond->sign = (unsigned int) getDefine_Int("monitord", "sign", 0, 1);
    mond->monitor_agents = no_agents ? 0 : (unsigned int) getDefine_Int("monitord", "monitor_agents", 0, 1);
    mond->rotate_log = (unsigned int)getDefine_Int("monitord", "rotate_log", 0, 1);
    mond->keep_log_days = getDefine_Int("monitord", "keep_log_days", 0, 500);
    mond->size_rotate = (unsigned long) getDefine_Int("monitord", "size_rotate", 0, 4096) * 1024 * 1024;
    mond->daily_rotations = getDefine_Int("monitord", "daily_rotations", 1, 256);
    mond->delete_old_agents = (unsigned int)getDefine_Int("monitord", "delete_old_agents", 0, 9600);

    mond->agents = NULL;
    mond->smtpserver = NULL;
    mond->emailfrom = NULL;
    mond->emailidsname = NULL;

    /* Setting default agent's global configuration */
    mond->global.agents_disconnection_time = 20;
    mond->global.agents_disconnection_alert_time = 120;

    modules |= CREPORTS;

    if (ReadConfig(modules, cfg, mond, NULL) < 0 ||
        ReadConfig(CGLOBAL, cfg, &mond->global, NULL) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    return OS_SUCCESS;
}

void MonitorStartCounters(mond_counters *counters) {
    if (counters) {
        counters->agents_disconnection = 0;
        counters->agents_disconnection_alert = 0;
        counters->delete_old_agents = 0;
    }
}

int MonitorCheckCounters(mond_counters *counters) {
    if (counters) {
        counters->agents_disconnection++;
        counters->agents_disconnection_alert++;
        if (mond.delete_old_agents != 0){
            counters->delete_old_agents++;
        }

        if (counters->agents_disconnection >= mond.global.agents_disconnection_time) {
            counters->agents_disconnection = 0;
            return 1;
        } else if (counters->agents_disconnection_alert >= mond.global.agents_disconnection_alert_time) {
            counters->agents_disconnection_alert = 0;
            return 2;
        // delete_old_agents is in minutes
        } else if (mond.delete_old_agents != 0 && counters->delete_old_agents >= mond.delete_old_agents * 60) {
            counters->delete_old_agents = 0;
            return 3;
        }
    }

    return 0;
}
