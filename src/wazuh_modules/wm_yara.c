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
static int wm_yara_send_event(wm_yara_t * data, cJSON *event);  
static int wm_yara_create_compiler(wm_yara_t * data);
static void wm_yara_destroy_compiler(wm_yara_t * data);
static int wm_yara_read_and_compile_rules(wm_yara_t * data);
static void wm_yara_scan_file(wm_yara_t * data,char *filename);
static void wm_yara_read_scan_directory(wm_yara_t * data,char *dir_name, int recursive, int max_depth);
static int wm_yara_scan_results_callback(int message, void *message_data, void *user_data);
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

#ifndef WIN32

    int i = 0;
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
        merror("Failed initializing YARA library");
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
        wm_yara_read_and_compile_rules(data);

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

static int wm_yara_read_and_compile_rules(wm_yara_t * data) {

    int ret_val = 0;
    int rules = 0;

    if (data->rule) {

        int i = 0;
        for (i = 0; data->rule[i]; i++) {

            if (!data->compiled_rules[i]) {
                os_realloc(data->compiled_rules[i], sizeof(YR_RULES *) * (rules + 2), data->compiled_rules[i]);

                int fd = open(data->rule[i]->path, O_RDONLY);

                if (fd < 0) {
                    merror("Rule '%s' not found",data->rule[i]->path);
                    ret_val = 1;
                    goto end;
                }

                if (yr_compiler_add_fd(data->compiler,fd,NULL,data->rule[i]->path)) {
                    merror("Couldn't compile rule '%s'",data->rule[i]->path);
                    ret_val = 1;
                    close(fd);
                    goto end;
                }

                close(fd);
            }
            rules++;
        }
    }

end:
    return ret_val;
}

static void wm_yara_scan_file(wm_yara_t * data, char *filename) {
    
    int scan_result = 0;

    int i = 0;
    for (i = 0; data->compiled_rules[i]; i++)
    {
        if (scan_result = yr_rules_scan_file(data->compiled_rules[i], filename, SCAN_FLAGS_FAST_MODE, NULL, filename, data->rule[i]->timeout), scan_result)
        {
            switch (scan_result)
            {
            case ERROR_INSUFFICIENT_MEMORY:
                merror("Insufficient memory for running the scan");
                goto end;
            
            case ERROR_COULD_NOT_OPEN_FILE:
                merror("Could not open file: '%s'",filename);
                goto end;

            case ERROR_COULD_NOT_MAP_FILE:
                merror("Could not map file to memory: '%s'",filename);
                break;

            case ERROR_TOO_MANY_SCAN_THREADS:
                merror("Too many scan threads");
                goto end;

            case ERROR_SCAN_TIMEOUT:
                merror("Too many scan threads");
                goto end;

            case ERROR_CALLBACK_ERROR:
                merror("Too many scan threads");
                goto end;

            case ERROR_TOO_MANY_MATCHES:
                merror("Too many matches for file: '%s'",filename);
                goto end;

            default:
                break;
            }
        }
    }

end:
    return scan_result;
}

static int wm_yara_create_compiler(wm_yara_t * data) {

    int ret_val = 0;

    ret_val = yr_compiler_create(&data->compiler);

    return ret_val;
}

static void wm_yara_destroy_compiler(wm_yara_t * data) {
    yr_compiler_destroy(data->compiler);
}

static int wm_yara_scan_results_callback(int message, void *message_data, void *user_data)
{

   switch (message)
   {
   case CALLBACK_MSG_RULE_MATCHING:
      printf("Rule matched \n");
      break;

   case CALLBACK_MSG_RULE_NOT_MATCHING:
      printf("Rule not matched \n");
      break;

   case CALLBACK_MSG_SCAN_FINISHED:
      printf("Scan finished \n");
      break;

   default:
      break;
   }
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

static void wm_yara_read_scan_directory(wm_yara_t * data,char *dir_name, int recursive, int max_depth) {

    DIR *dp;
    struct dirent *entry;
    char *path;

    /* Directory should be valid */
    if (strlen(dir_name) > PATH_MAX) {
        return;
    }

    if (max_depth < 0) {
        return;
    }

    dp = opendir(dir_name);

    if (!dp) {
        mdebug1("Path '%s' is not a directory. Skipping",dir_name);
        return;
    }

    os_calloc(PATH_MAX + 2, sizeof(char), path);

    while ((entry = readdir(dp)) != NULL) {

        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        snprintf(path,PATH_MAX,"%s%s",dir_name,entry->d_name);

        
        DIR *child_dp;
        child_dp = opendir(path);

        if (child_dp) {
            if (recursive) {
                wm_yara_read_scan_directory(data,path,recursive,max_depth-1);
            }
            closedir(child_dp);
        } else {
            /* Is a file, launch YARA scan */
            wm_yara_scan_file(data,path);
        }
    }

    closedir(dp);
    os_free(path);
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

cJSON *wm_yara_dump(const wm_yara_t *data) {
    cJSON *root = cJSON_CreateObject();
    return root;
}
