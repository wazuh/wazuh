/*
 * Wazuh Module for YARA
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 21, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <os_net/os_net.h>
#include <sys/stat.h>
#include <external/yara/libyara/include/yara.h>
#include "os_crypto/sha256/sha256_op.h"
#include "shared.h"


#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_YARA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_YARA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_YARA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_YARA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_YARA_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

typedef struct rule_db_info_t {
    char *result;
    cJSON *event;
} rule_db_info_t;

typedef struct rule_dbdb_hash_info_t {
    rule_db_info_t **elem;
} rule_db_hash_info_t;

typedef struct request_dump_t {
    int policy_index;
    int first_scan;
} request_dump_t;

static void * wm_yara_main(wm_yara_t * data);   // Module main function. It won't return
static void wm_yara_destroy(wm_yara_t * data); 
static int wm_yara_start(wm_yara_t * data);
static int wm_yara_send_event(wm_yara_t * data,cJSON *event);  
static void wm_yara_read_rules(wm_yara_t * data);
static int wm_yara_do_scan(int rule_db_index,unsigned int remote_rules,int first_scan);  
static int wm_yara_send_alert(wm_yara_t * data,cJSON *json_alert);
static int wm_yara_check_hash(OSHash *rule_db_hash,char *result,cJSON *profile,cJSON *event,int check_index,int file_index);
static char *wm_yara_hash_integrity(int policy_index);
static char *wm_yara_hash_integrity_file(const char *file);
static void wm_yara_free_hash_data(rule_db_info_t *event);
static void * wm_yara_dump_db_thread(wm_yara_t * data);
static void wm_yara_send_rules_scanned(wm_yara_t * data);
static int wm_yara_send_dump_end(wm_yara_t * data, unsigned int elements_sent,char * file_id,int scan_id);

#ifndef WIN32
static void * wm_yara_request_thread(wm_yara_t * data);
#endif

cJSON *wm_yara_dump(const wm_yara_t * data);     // Read config

const wm_context WM_YARA_CONTEXT = {
    YARA_WM_NAME,
    (wm_routine)wm_yara_main,
    (wm_routine)(void *)wm_yara_destroy,
    (cJSON * (*)(const void *))wm_yara_dump
};

static unsigned int summary_passed = 0;
static unsigned int summary_failed = 0;
static unsigned int summary_invalid = 0;

OSHash **rule_db;
char **last_sha256;
rule_db_hash_info_t *rule_db_for_hash;

static w_queue_t * request_queue;
static wm_yara_t * data_win;

static cJSON **last_summary_json = NULL;

/* Multiple readers / one write mutex */
static pthread_rwlock_t dump_rwlock;

// Module main function. It won't return
void * wm_yara_main(wm_yara_t * data) {
    // If module is disabled, exit
    if (data->enabled) {
        minfo("Module started.");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    if (!data->rule || data->rule[0] == NULL) {
        minfo("No rules defined. Exiting.");
        pthread_exit(NULL);
    }

    data->msg_delay = 1000000 / wm_max_eps;
    data->summary_delay = 3; /* Seconds to wait for summary sending */
    data_win = data;

    /* Reading the internal options */

    // Default values
    data->request_db_interval = 300;

    data->request_db_interval = getDefine_Int("yara","request_db_interval", 1, 60) * 60;

    /* Maximum request interval is the scan interval */
    if(data->request_db_interval > data->interval) {
       data->request_db_interval = data->interval;
       minfo("The request_db_interval option cannot be higher than the scan interval. It will be redefined to that value.");
    }

    /* Create Hash for each rule file */
    int i;
    if(data->rule){
        for(i = 0; data->rule[i]; i++) {
            os_realloc(rule_db, (i + 2) * sizeof(OSHash *), rule_db);
            rule_db[i] = OSHash_Create();
            if (!rule_db[i]) {
                merror(LIST_ERROR);
                pthread_exit(NULL);
            }
            OSHash_SetFreeDataPointer(rule_db[i], (void (*)(void *))wm_yara_free_hash_data);

            /* DB for calculating hash only */
            os_realloc(rule_db_for_hash, (i + 2) * sizeof(rule_db_hash_info_t), rule_db_for_hash);

            /* Last summary for each rule */
            os_realloc(last_summary_json, (i + 2) * sizeof(cJSON *), last_summary_json);
            last_summary_json[i] = NULL;

            /* Prepare first ID for each rule file */
            os_calloc(1,sizeof(rule_db_info_t *),rule_db_for_hash[i].elem);
            rule_db_for_hash[i].elem[0] = NULL;
        }
    }

    /* Create summary hash for each rule file */
    if(data->rule){
        for(i = 0; data->rule[i]; i++) {
            os_realloc(last_sha256, (i + 2) * sizeof(char *), last_sha256);
            os_calloc(1,sizeof(os_sha256),last_sha256[i]);
        }
    }

#ifndef WIN32

    for (i = 0; (data->queue = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++)
        wm_delay(1000 * WM_MAX_WAIT);

    if (i == WM_MAX_ATTEMPTS) {
        merror("Can't connect to queue.");
    }

#endif

    request_queue = queue_init(1024);

    w_rwlock_init(&dump_rwlock, NULL);

#ifndef WIN32
    w_create_thread(wm_yara_request_thread, data);
    w_create_thread(wm_yara_dump_db_thread, data);
#else
    if (CreateThread(NULL,
                    0,
                    (LPTHREAD_START_ROUTINE)wm_yara_dump_db_thread,
                    data,
                    0,
                    NULL) == NULL) {
                    merror(THREAD_ERROR);
    }
#endif

    wm_yara_start(data);

    return NULL;
}

static int wm_yara_send_alert(wm_yara_t * data,cJSON *json_alert)
{
    return (0);
}

static void wm_yara_send_rules_scanned(wm_yara_t * data) {

}

static int wm_yara_start(wm_yara_t * data) {

    int status = 0;
    time_t time_start = 0;
    time_t time_sleep = 0;

    if (yr_initialize()) {
        merror("Initializing yara library");
        pthread_exit(NULL);
    }

    if (!data->scan_on_start) {
        time_start = time(NULL);

        if (data->scan_day) {
            do {
                status = check_day_to_scan(data->scan_day, data->scan_time);
                if (status == 0) {
                    time_sleep = get_time_to_hour(data->scan_time);
                } else {
                    wm_delay(1000); // Sleep one second to avoid an infinite loop
                    time_sleep = get_time_to_hour("00:00");
                }

                mdebug2("Sleeping for %d seconds", (int)time_sleep);
                wm_delay(1000 * time_sleep);

            } while (status < 0);

        } else if (data->scan_wday >= 0) {

            time_sleep = get_time_to_day(data->scan_wday, data->scan_time);
            minfo("Waiting for turn to evaluate.");
            mdebug2("Sleeping for %d seconds", (int)time_sleep);
            wm_delay(1000 * time_sleep);

        } else if (data->scan_time) {

            time_sleep = get_time_to_hour(data->scan_time);
            minfo("Waiting for turn to evaluate.");
            mdebug2("Sleeping for %d seconds", (int)time_sleep);
            wm_delay(1000 * time_sleep);

        } else if (data->next_time == 0 || data->next_time > time_start) {

            // On first run, take into account the interval of time specified
            time_sleep = data->next_time == 0 ?
                         (time_t)data->interval :
                         data->next_time - time_start;

            minfo("Waiting for turn to evaluate.");
            mdebug2("Sleeping for %ld seconds", (long)time_sleep);
            wm_delay(1000 * time_sleep);

        }
    }

    while(1) {
        // Get time and execute
        time_start = time(NULL);

        minfo("Starting Yara scan.");

        /* Do scan for every rule file */
        wm_yara_read_rules(data);

        /* Send rules scanned for database purge on manager side */
        wm_yara_send_rules_scanned(data);

        wm_delay(1000); // Avoid infinite loop when execution fails
        time_sleep = time(NULL) - time_start;

        minfo("Yara scan finished. Duration: %d seconds.", (int)time_sleep);

        if (data->scan_day) {
            int interval = 0, i = 0;
            interval = data->interval / 60;   // interval in num of months

            do {
                status = check_day_to_scan(data->scan_day, data->scan_time);
                if (status == 0) {
                    time_sleep = get_time_to_hour(data->scan_time);
                    i++;
                } else {
                    wm_delay(1000);
                    time_sleep = get_time_to_hour("00:00");     // Sleep until the start of the next day
                }

                mdebug2("Sleeping for %d seconds", (int)time_sleep);
                wm_delay(1000 * time_sleep);

            } while ((status < 0) && (i < interval));

        } else {

            if (data->scan_wday >= 0) {
                time_sleep = get_time_to_day(data->scan_wday, data->scan_time);
                time_sleep += WEEK_SEC * ((data->interval / WEEK_SEC) - 1);
                data->next_time = (time_t)time_sleep + time_start;
            } else if (data->scan_time) {
                time_sleep = get_time_to_hour(data->scan_time);
                time_sleep += DAY_SEC * ((data->interval / DAY_SEC) - 1);
                data->next_time = (time_t)time_sleep + time_start;
            } else if ((time_t)data->interval >= time_sleep) {
                time_sleep = data->interval - time_sleep;
                data->next_time = data->interval + time_start;
            } else {
                merror("Interval overtaken.");
                time_sleep = data->next_time = 0;
            }

            mdebug2("Sleeping for %d seconds", (int)time_sleep);
            wm_delay(1000 * time_sleep);
        }
    }

    return 0;
}

static void wm_yara_read_rules(wm_yara_t * data) {
  
}

static int wm_yara_check_rule() {
    int retval = 0;
   
    return retval;
}

static int wm_yara_do_scan(int rule_db_index,unsigned int remote_rules,int first_scan)
{
    int ret_val = 0;
    return ret_val;
}

// Destroy data
void wm_yara_destroy(wm_yara_t * data) {
    yr_finalize();
    os_free(data);
}

static void wm_yara_free_hash_data(rule_db_info_t *event) {

    if(event) {
        if(event->result){
            os_free(event->result);
        }

        if(event->event) {
            cJSON_Delete(event->event);
        }
        os_free(event);
    }
}

static char *wm_yara_hash_integrity(int policy_index) {
    char *str = NULL;
    return NULL;
}

static char *wm_yara_hash_integrity_file(const char *file) {

    char *hash_file = NULL;
    return hash_file;
}

static void *wm_yara_dump_db_thread(wm_yara_t * data) {
    return NULL;
}


static int wm_yara_send_dump_end(wm_yara_t * data, unsigned int elements_sent,char * file_id, int scan_id) {
    return 0;
}

#ifdef WIN32
void wm_yara_push_request_win(char * msg){
}

#endif

#ifndef WIN32
static void * wm_yara_request_thread(wm_yara_t * data) {
    return NULL;
}
#endif
static void wm_yara_summary_increment_passed() {
    summary_passed++;
}

static void wm_yara_summary_increment_failed() {
    summary_failed++;
}

static void wm_yara_summary_increment_invalid() {
    summary_invalid++;
}

static void wm_yara_reset_summary() {
    summary_failed = 0;
    summary_passed = 0;
    summary_invalid = 0;
}

cJSON *wm_yara_dump(const wm_yara_t *data) {
    cJSON *root = cJSON_CreateObject();
    return root;
}
