/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015, Wazuh Inc.
 * January 25, 2019.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <os_net/os_net.h>
#include <sys/stat.h>
#include "os_crypto/sha256/sha256_op.h"
#include "expression.h"
#include "shared.h"

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_SCA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

#ifdef WIN32
static DWORD WINAPI wm_sca_main(void *arg);         // Module main function. It won't return
#else
static void * wm_sca_main(wm_sca_t * data);   // Module main function. It won't return
#endif
static void wm_sca_destroy(wm_sca_t * data);  // Destroy data
static int wm_sca_start(wm_sca_t * data);  // Start

static int wm_sca_send_dump_end(wm_sca_t * data, unsigned int elements_sent,char * policy_id,int scan_id);  // Send dump end event

cJSON *wm_sca_dump();     // Read config

const wm_context WM_SCA_CONTEXT = {
    .name = SCA_WM_NAME,
    .start = (wm_routine)wm_sca_main,
    .destroy = (void(*)(void *))wm_sca_destroy,
    .dump = (cJSON * (*)(const void *))wm_sca_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

static wm_sca_t * data_win;

// Module main function. It won't return
#ifdef WIN32
DWORD WINAPI wm_sca_main(void *arg) {
    wm_sca_t *data = (wm_sca_t *)arg;
#else
void * wm_sca_main(wm_sca_t * data) {
#endif
    // If module is disabled, exit
    if (data->enabled) {
        minfo("Module started.");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    data_win = data;

#ifndef WIN32
    w_create_thread(wm_sca_request_thread, data);
    w_create_thread(wm_sca_dump_db_thread, data);
#else
    w_create_thread(NULL,
                    0,
                    (void *)wm_sca_dump_db_thread,
                    data,
                    0,
                    NULL);
#endif

    wm_sca_start(data);

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

static int wm_sca_start(wm_sca_t * data) {
    char * timestamp = NULL;
    time_t time_start = 0;
    time_t duration = 0;

    do {
        const time_t time_sleep = sched_scan_get_time_until_next_scan(&(data->scan_config), WM_SCA_LOGTAG, data->scan_on_start);

        if (time_sleep) {
            const int next_scan_time = sched_get_next_scan_time(data->scan_config);
            timestamp = w_get_timestamp(next_scan_time);
            mtdebug2(WM_SCA_LOGTAG, "Sleeping until: %s", timestamp);
            os_free(timestamp);
            w_sleep_until(next_scan_time);
        }
        mtinfo(WM_SCA_LOGTAG,"Starting Security Configuration Assessment scan.");
        time_start = time(NULL);

        /* Do scan for every policy file */
        wm_sca_read_files(data);

        /* Send policies scanned for database purge on manager side */
        wm_sca_send_policies_scanned(data);

        duration = time(NULL) - time_start;
        mtinfo(WM_SCA_LOGTAG, "Security Configuration Assessment scan finished. Duration: %d seconds.", (int)duration);

    } while(FOREVER());

    return 0;
}

// Destroy data
void wm_sca_destroy(wm_sca_t * data) {
    os_free(data);
}

static int wm_sca_send_dump_end(wm_sca_t * data, unsigned int elements_sent,char * policy_id, int scan_id) {
    cJSON *dump_event = cJSON_CreateObject();

    cJSON_AddStringToObject(dump_event, "type", "dump_end");
    cJSON_AddStringToObject(dump_event, "policy_id", policy_id);
    cJSON_AddNumberToObject(dump_event, "elements_sent", elements_sent);
    cJSON_AddNumberToObject(dump_event, "scan_id", scan_id);

    wm_sca_send_alert(data,dump_event);

    cJSON_Delete(dump_event);

    return 0;
}


cJSON *wm_sca_dump() {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    cJSON_AddStringToObject(wm_wd, "enabled", "yes");

    cJSON_AddItemToObject(root,"sca",wm_wd);


    return root;
}
