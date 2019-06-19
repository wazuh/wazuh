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

static void * wm_yara_main(wm_yara_t * data);   // Module main function. It won't return
static void wm_yara_destroy(wm_yara_t * data); 
static int wm_yara_start(wm_yara_t * data);
static int wm_yara_create_compiler(wm_yara_t * data);
static void wm_yara_compiler_callback_function(int error_level, const char *file_name, int line_number, const char *message, __attribute__((unused)) void *user_data);
static void wm_yara_destroy_compiler(wm_yara_t * data);
static int wm_yara_read_and_compile_rules(wm_yara_t * data, wm_yara_rule_t **rules, wm_yara_set_t *set);
static int wm_yara_get_compiled_rules(wm_yara_t * data, wm_yara_rule_t **rules, wm_yara_set_t *set);
static void wm_yara_read_and_set_external_variables(wm_yara_t *data);
static int wm_yara_scan_file(YR_RULES **compiled_rules, char *filename, unsigned int timeout);
static void wm_yara_prepare_excluded_files(wm_yara_set_t *set);
static void wm_yara_free_excluded_files(wm_yara_set_t *set);
static void wm_yara_add_rule_string(wm_yara_t *data, char *rule, char *namespace);
static OSHash *wm_yara_get_excluded_files(char *path);
static int wm_yara_excluded_file(OSHash *excluded_hash, char *filename);
static void wm_yara_scan_process(YR_RULES **compiled_rules,int pid, unsigned int timeout);
static void wm_yara_scan_processes(YR_RULES **compiled_rules, char *filter, unsigned int timeout);
static void wm_yara_read_scan_directory(YR_RULES **compiled_rules,char *dir_name, int recursive, int max_depth, unsigned int timeout, OSHash *excluded_files);
static void wm_yara_read_scan_files(YR_RULES **compiled_rules,wm_yara_path_t **paths, OSHash *excluded_files, unsigned int timeout);
static int wm_yara_scan_results_file_callback(int message, void *message_data, void *user_data);
static int wm_yara_scan_results_process_callback(int message, void *message_data, void *user_data);
static void wm_yara_add_matched_file(OSHash *table, char *filename, const char *rulename);
static void wm_yara_add_matched_file_integrity(values_t *file_values, char *str);
static void wm_yara_reset_files_existance(OSHash *table);
static void wm_yara_remove_non_existing_files(OSHash *table);
static void wm_yara_destroy_rules(YR_RULES **compiled_rules);
static char *wm_yara_checksum_integrity(values_t *val);
static void wm_yara_init_integrity(int rows);
static void wm_yara_reset_matched_rules(OSHash *table);
static void wm_yara_do_scan(wm_yara_t *data);

static cJSON *wm_yara_get_set_data(wm_yara_set_t *set);
static cJSON *wm_yara_get_rule_data(YR_RULE *rule);
static cJSON *wm_yara_get_rule_strings(YR_RULE *rule);
static cJSON *wm_yara_get_rule_metas(YR_RULE *rule);

static int wm_yara_send_msg(wm_yara_t * data, char *msg);
static void wm_yara_send_set(wm_yara_t * data, wm_yara_set_t *set);
static void wm_yara_send_sets(wm_yara_t *data);
static void wm_yara_send_file(wm_yara_t *data, char *filename);
static void wm_yara_send_files(wm_yara_t *data, OSHash *table);
static void wm_yara_send_scan_info(wm_yara_t *data, wm_yara_set_t *set, int start_time, int end_time);
static void wm_yara_send_integrity(wm_yara_t *data);
static void wm_yara_send_enabled_sets(wm_yara_t *data);
static void wm_yara_send_rules(wm_yara_t *data);
static void *wm_yara_dump_db_thread();

#ifndef WIN32
static void * wm_yara_request_thread(wm_yara_t * data);
#endif

cJSON *wm_yara_dump(const wm_yara_t * data);

const wm_context WM_YARA_CONTEXT = {
    YARA_WM_NAME,
    (wm_routine)wm_yara_main,
    (wm_routine)(void *)wm_yara_destroy,
    (cJSON * (*)(const void *))wm_yara_dump
};

static w_queue_t * request_queue;
static wm_yara_t * data_win;

/* Hash table for files and struct*/
static OSHash * files_hash_table = NULL;
static integrity *integrity_struct = NULL;

/* Multiple readers / one write mutex */
static pthread_rwlock_t dump_rwlock;

/* TODO: fill needed fields for db dumping */
typedef struct request_dump_t {
    char *integrity_blocks;
} request_dump_t;

// Module main function. It won't return
void * wm_yara_main(wm_yara_t * data) {
    // If module is disabled, exit
    if (data->enabled) {
        minfo("Module started.");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    if (!data->set || data->set[0] == NULL) {
        minfo("No sets defined. Exiting.");
        pthread_exit(NULL);
    }

    data->msg_delay = 1000000 / wm_max_eps;
    data->summary_delay = 3; /* Seconds to wait for summary sending */
    data_win = data;

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

    /* Init files hash table */
    files_hash_table = OSHash_Create_Custom(0, 0);
    if (!files_hash_table) {
        merror(LIST_ERROR);
        pthread_exit(NULL);
    }

    /* Initialize hash integrity */
    wm_yara_init_integrity(files_hash_table->rows);

#ifndef WIN32
    w_create_thread(wm_yara_request_thread, data);
    w_create_thread(wm_yara_dump_db_thread, NULL);
#else
    if (CreateThread(NULL,
                    0,
                    (LPTHREAD_START_ROUTINE)wm_yara_dump_db_thread,
                    NULL,
                    0,
                    NULL) == NULL) {
                    merror(THREAD_ERROR);
    }
#endif

    w_rwlock_init(&dump_rwlock, NULL);

    wm_yara_start(data);

    return NULL;
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

    /* Create YARA compiler */
    if (wm_yara_create_compiler(data)) {
        merror("Failed initializing YARA compiler");
        pthread_exit(NULL);
    }

    /* Set external variables if any */
    wm_yara_read_and_set_external_variables(data);

    /* Send sets */
    wm_yara_send_sets(data);

    /* First scan, do not send files */
    int first_scan = 1;

    while (1) {

        // Get time and execute
        time_start = time(NULL);

        minfo("Starting Yara scan.");

        /* Reset file existance */
        wm_yara_reset_files_existance(files_hash_table);

        /* Scan for each set */
        wm_yara_do_scan(data);
       
        if (!first_scan) {
            /* Send files that have changed */
            wm_yara_send_files(data, files_hash_table);
        }

        /* Delete non existing files */
        wm_yara_remove_non_existing_files(files_hash_table);

        /* Reset matched rules */
        wm_yara_reset_matched_rules(files_hash_table);
        
        first_scan = 0;

        wm_delay(1000); // Avoid infinite loop when execution fails
        time_sleep = time(NULL) - time_start;

        minfo("Yara scan finished. Duration: %d seconds.", (int)time_sleep);

        /* Send enabled sets */
        wm_yara_send_enabled_sets(data);

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

    /* Destroy compiler */
    wm_yara_destroy_compiler(data);

    return 0;
}

static int wm_yara_read_and_compile_rules(wm_yara_t * data, wm_yara_rule_t **rule, wm_yara_set_t *set) {
    assert(data);

    int ret_val = 0;
    int rules = 0;

    if (rule) {

        int i = 0;
        for (i = 0; rule[i]; i++) {

            /* Ignore the rule if it is disabled */
            if (!rule[i]->enabled) {
                continue;
            }

            if (!set->compiled_rules[rules]) {
                os_realloc(set->compiled_rules, sizeof(YR_RULES *) * (rules + 2), set->compiled_rules);

                set->compiled_rules[rules] = NULL;
                set->compiled_rules[rules + 1] = NULL;

#ifndef WIN32
                int fd = open(rule[i]->path, O_RDONLY);
#else
                HANDLE fd;

                fd = CreateFile(rule[i]->path, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
#endif

#ifndef WIN32
                if (fd < 0) {
#else
                if(fd == INVALID_HANDLE_VALUE) {
#endif
                    merror("Rule '%s' not found",rule[i]->path);
                    ret_val = 1;
                    goto end;
                }

                int add_rule_result = yr_compiler_add_fd(data->compiler, fd, NULL, rule[i]->path);

                if (add_rule_result) {
                    merror("Couldn't compile rule '%s'", rule[i]->path);
                    ret_val = 1;
#ifndef WIN32
                    close(fd);
#else
                    CloseHandle(fd);
#endif
                    goto end;
                }

#ifndef WIN32
                close(fd);
#else
                CloseHandle(fd);
#endif
            }
            rules++;
        }
    }

end:
    return ret_val;
}

static int wm_yara_get_compiled_rules(wm_yara_t * data, wm_yara_rule_t **rule, wm_yara_set_t *set) {
    assert(data);
    assert(rule);

    int ret_val = 0;
    int rules = 0;

    if (rule) {

        int i = 0;
        for (i = 0; rule[i]; i++) {

            /* Ignore the rule if it is disabled */
            if (!rule[i]->enabled) {
                continue;
            }

            int get_rules_result = yr_compiler_get_rules(data->compiler, &set->compiled_rules[rules]);

            switch (get_rules_result)
            {
            case ERROR_INSUFFICIENT_MEMORY:
                merror("Insufficient memory while getting compiled rules");
                ret_val = 1;
                goto end;
            
            default:
                break;
            }
            
            rules++;
        }
    }

end:

    return ret_val;
}

static int wm_yara_scan_file(YR_RULES **compiled_rules, char *filename, unsigned int timeout) {
    assert(compiled_rules);

    int scan_result = 0;

    int i = 0;
    for (i = 0; compiled_rules[i]; i++)
    {
        if (scan_result = yr_rules_scan_file(compiled_rules[i], filename, SCAN_FLAGS_FAST_MODE, wm_yara_scan_results_file_callback, filename, timeout), scan_result)
        {
            switch (scan_result)
            {
            case ERROR_INSUFFICIENT_MEMORY:
                mdebug1("Insufficient memory for running the scan");
                goto end;
            
            case ERROR_COULD_NOT_OPEN_FILE:
                mdebug1("Could not open file: '%s'", filename);
                goto end;

            case ERROR_COULD_NOT_MAP_FILE:
                mdebug1("Could not map file to memory: '%s'", filename);
                goto end;

            case ERROR_TOO_MANY_SCAN_THREADS:
                mdebug1("Too many scan threads");
                goto end;

            case ERROR_SCAN_TIMEOUT:
                mdebug1("Timeout reached");
                goto end;

            case ERROR_CALLBACK_ERROR:
                mdebug1("Call back error");
                goto end;

            case ERROR_TOO_MANY_MATCHES:
                mdebug1("Too many matches for file: '%s'", filename);
                goto end;

            default:
                break;
            }
        }
    }

end:
    return scan_result;
}

static void wm_yara_scan_process(YR_RULES **compiled_rules,int pid,unsigned int timeout) {
    assert(compiled_rules);
    mdebug1("Scanning process with pid '%d'", pid);

    int scan_result = 0;

    int i = 0;
    for (i = 0; compiled_rules[i]; i++)
    {
        if (scan_result = yr_rules_scan_proc(compiled_rules[i], pid, 0, wm_yara_scan_results_process_callback, &pid, timeout), scan_result)
        {
            switch (scan_result)
            {
            case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
                mdebug1("Could not attach to process: '%d'", pid);
                break;

            default:
                break;
            }
        }
    }
}

static void wm_yara_scan_processes(YR_RULES **compiled_rules, char *filter_process, unsigned int timeout) {

mdebug1("Start processes scan");
#if defined(__FreeBSD__) || defined(__MACH__) 
    unsigned int max_pids = 99999;
#elif defined(__sun__) 
    unsigned int max_pids = 29999;
#elif !defined(WIN32)
    unsigned int max_pids = 32768;

    FILE *fp = NULL;

    fp = fopen("/proc/sys/kernel/pid_max","r");

    if (!fp) {
        mdebug2("Could not open '/proc/sys/kernel/pid_max'. Setting maximum pid to 32768");
    } else {
        char buffer[OS_SIZE_128] = {0};

        if (fgets(buffer,OS_SIZE_128,fp)) {
            if (OS_StrIsNum(buffer)) {
                max_pids = atoi(buffer);
            }
        }

        fclose(fp);
    }

#endif

#ifndef WIN32

    char ps[OS_SIZE_1024 + 1];
    memset(ps, '\0', OS_SIZE_1024 + 1);

    if (filter_process) {
        /* Check where ps is */
        strncpy(ps, "/bin/ps", OS_SIZE_1024);
        if (!w_is_file(ps)) {
            strncpy(ps, "/usr/bin/ps", OS_SIZE_1024);
            if (!w_is_file(ps)) {
                mdebug2("'ps' not found.");
                return;
            }
        }   
    }
  
    unsigned int i = 1;
    int pid = getpid();

    for (i = 1; i < max_pids; i++) {

        if (filter_process && (!((getsid(i) == -1) && (errno == ESRCH))) &&
                (!((getpgid(i) == -1) && (errno == ESRCH)))) {
            char *p_name;

            p_name = w_os_get_runps(ps, (int)i);
            if (!p_name) {
                continue;
            }

            if (!OS_Regex(filter_process, p_name)) {
                mdebug2("Regex %s doesn't match with process '%s'", filter_process, p_name);
                continue;
            }

            /* Do not scan our own memory */
            if ((unsigned int)pid != i) {
                wm_yara_scan_process(compiled_rules, i, timeout);
            }
           
            continue;
        }
        
        /* Do not scan our own memory */
        if ((unsigned int)pid != i) {
            wm_yara_scan_process(compiled_rules, i, timeout);
        }
    }
#else

    OSList *p_list = w_os_get_process_list();

    if (p_list == NULL) {
        merror("Could not get process list");
        return;
    }

    OSListNode *l_node;
    l_node = OSList_GetFirstNode(p_list);

    while (l_node) {
        W_Proc_Info *pinfo;

        pinfo = (W_Proc_Info *)l_node->data;

        if (filter_process) {
            if (!OS_Regex(filter_process,pinfo->p_name)) {
                mdebug2("Regex %s doesn't match with process '%s'", filter_process, pinfo->p_name);
                continue;
            }
        }

        /* Do not scan our own memory */
        if (GetCurrentProcessId() != pinfo->pid) {
            wm_yara_scan_process(compiled_rules, pinfo->pid, timeout);
        }

        l_node = OSList_GetNextNode(p_list);
    }

    w_del_plist(p_list);

#endif
mdebug1("End processes scan");
}

static int wm_yara_create_compiler(wm_yara_t * data) {
    assert(data);

    int ret_val = 0;

    ret_val = yr_compiler_create(&data->compiler);

    yr_compiler_set_callback(data->compiler, wm_yara_compiler_callback_function, NULL);

    return ret_val;
}

static void wm_yara_destroy_compiler(wm_yara_t * data) {
    yr_compiler_destroy(data->compiler);
}

static void wm_yara_compiler_callback_function(int error_level, const char *file_name, int line_number, const char *message, __attribute__((unused)) void *user_data) {

    switch (error_level) {
        case YARA_ERROR_LEVEL_ERROR:
            merror("Compiler error on line %d: [(%s)] - '%s'", line_number, message, file_name);
            break;

        case YARA_ERROR_LEVEL_WARNING:
            mwarn("Compiler warning on line %d: [(%s)] - '%s'", line_number, message, file_name);
            break;
    }
}

static int wm_yara_scan_results_file_callback(int message, void *message_data, void *user_data)
{
    int result = 0;

    switch (message) {
    case CALLBACK_MSG_RULE_MATCHING:
        mdebug1("Rule matched '%s' for file: '%s'", ((YR_RULE *)message_data)->identifier, (char *)user_data);
        wm_yara_add_matched_file(files_hash_table, (char *)user_data, ((YR_RULE *)message_data)->identifier);
        result = CALLBACK_MSG_RULE_MATCHING; 
        break;

    case CALLBACK_MSG_RULE_NOT_MATCHING:
        mdebug2("Rule not matched '%s' for file: '%s'", ((YR_RULE *)message_data)->identifier, (char *)user_data);
        result = CALLBACK_MSG_RULE_NOT_MATCHING;
        break;

    case CALLBACK_MSG_SCAN_FINISHED:
        mdebug2("Scan finished");
        result = CALLBACK_MSG_SCAN_FINISHED;
        break;

    default:
        break;
    }

    return result;
}

static int wm_yara_scan_results_process_callback(int message, void *message_data, void *user_data)
{

    switch (message) {
    case CALLBACK_MSG_RULE_MATCHING:
        mdebug1("Rule matched '%s' for process: '%d'", ((YR_RULE *)message_data)->identifier, *(int *)(user_data));
        break;

    case CALLBACK_MSG_RULE_NOT_MATCHING:
        mdebug2("Rule not matched '%s' for process: '%d'", ((YR_RULE *)message_data)->identifier, *(int *)(user_data));
        break;

    case CALLBACK_MSG_SCAN_FINISHED:
        mdebug2("Scan finished");
        break;

    default:
        break;
    }

    return 0;
}

static void wm_yara_do_scan(wm_yara_t *data)
{
    assert(data);

    int index = 0;
    wm_yara_set_t *set;

    wm_yara_set_foreach(data, set, index) {
            
        /* Skip set if disabled */
        if (!set->enabled) {
            continue;
        }

        time_t time_start = time(NULL);

        /* Read and compile rules */
        if (wm_yara_read_and_compile_rules(data, set->rule, set)) {
            merror("Could not compile rules. Aborting");
            pthread_exit(NULL);
        }
        
        /* Get compiled rules */
        if (wm_yara_get_compiled_rules(data, set->rule, set)) {
            merror("Could not get compiled rules. Aborting");
            pthread_exit(NULL);
        }

        /* Send rules */
        wm_yara_send_rules(data);
       
        /* Expand files and fill excluded files hash table */
        wm_yara_prepare_excluded_files(set);

        /* Do scan for files and directories */
        wm_yara_read_scan_files(set->compiled_rules, set->path, set->exclude_hash, set->timeout);

        /* Do scan for processes */
        if (set->scan_processes) {
            wm_yara_scan_processes(set->compiled_rules, NULL, set->timeout);
        }

        /* Destroy rules to avoid memleak */
        wm_yara_destroy_rules(set->compiled_rules);

        /* Free excluded files hash table */
        wm_yara_free_excluded_files(set);

        /* Generate Hash integrity */
        generate_integrity(files_hash_table, integrity_struct);

        /* Send integrity */
        wm_yara_send_integrity(data);

        time_t time_end = time(NULL);
        
        /* Send scan information */
        wm_yara_send_scan_info(data, set, (int)time_start, (int)time_end);
    }
}

static void wm_yara_destroy_rules(YR_RULES **compiled_rules) {
    assert(compiled_rules);

    if (compiled_rules) {

        int i = 0;
        for (i = 0; compiled_rules[i]; i++) {
            yr_rules_destroy(compiled_rules[i]);
        }
    }
}

// Destroy data
void wm_yara_destroy(wm_yara_t * data) {
    yr_finalize();
    os_free(data);
}

static void wm_yara_read_scan_directory(YR_RULES **compiled_rules,char *dir_name, int recursive, int max_depth, unsigned int timeout, OSHash *excluded_files) {
    assert(compiled_rules);
    assert(dir_name);

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

#ifndef WIN32
        snprintf(path,PATH_MAX,"%s/%s",dir_name,entry->d_name);
#else
        snprintf(path,PATH_MAX,"%s\\%s",dir_name,entry->d_name);
#endif
        DIR *child_dp;
        child_dp = opendir(path);

        if (child_dp) {
            if (recursive) {
                wm_yara_read_scan_directory(compiled_rules, path, recursive, max_depth - 1, timeout, excluded_files);
            }
            closedir(child_dp);
        } else {

            /* Check if the file is excluded */
            if (!wm_yara_excluded_file(excluded_files, path)) {
                mdebug1("Excluding file from scan: '%s'", path);
                continue;
            }

            /* Is a file, launch YARA scan */
            wm_yara_scan_file(compiled_rules, path, timeout);
        }
    }

    closedir(dp);
    os_free(path);
}

static void wm_yara_read_scan_files(YR_RULES **compiled_rules,wm_yara_path_t **paths,OSHash *excluded_files,unsigned int timeout) {
    assert(compiled_rules);

    if (paths) {

        int i = 0;
        for (i = 0; paths[i]; i++) {

            if (paths[i]->ignore) {
                continue;
            }

            mdebug1("Start path scan: '%s'", paths[i]->path);

            /* Check if the path is a directory */
            DIR *dp;

            if (strlen(paths[i]->path) > PATH_MAX) {
                return;
            }

            dp = opendir(paths[i]->path);

            if (!dp) {
                /* Check if the file is excluded */
                if (wm_yara_excluded_file(excluded_files, paths[i]->path)) {
                    wm_yara_scan_file(compiled_rules, paths[i]->path, timeout);
                }
            } else {
                wm_yara_read_scan_directory(compiled_rules, paths[i]->path, paths[i]->recursive, 125, timeout, excluded_files);
                closedir(dp);
            }

            mdebug1("End path scan: '%s'", paths[i]->path);
        }
    }
}

static int wm_yara_excluded_file(OSHash *excluded_hash, char *filename) {
    int ret_val = 1;

    if (excluded_hash) {
        if (OSHash_Get(excluded_hash,filename)) {
            ret_val = 0;
        }
    }

    return ret_val;
}

static void wm_yara_prepare_excluded_files(wm_yara_set_t *set) {
    assert(set);

    if (set->exclude_path) {
        set->exclude_hash = wm_yara_get_excluded_files(set->exclude_path);
    }
}

static void wm_yara_free_excluded_files(wm_yara_set_t *set) {
    assert(set);

    if (set->exclude_path && set->exclude_hash) {
        OSHash_Free(set->exclude_hash);
    }
}

static void wm_yara_read_and_set_external_variables(wm_yara_t *data) {
    int error_val = 0;

    if (data->external_variables) {

        int index;
        wm_yara_external_variable_t *var;

        wm_yara_external_var_foreach(data,var,index) {

            if (var->ignore) {
                continue;
            }

            /* Check if boolean */
            if (!strcmp(var->value, "true")) {
                error_val = yr_compiler_define_boolean_variable(data->compiler, var->name, 1);

                if (error_val) {
                    merror("Adding boolean external variable '%s'", var->name);
                    break;
                }
                continue;
            }

            if (!strcmp(var->value, "false")) {
                error_val = yr_compiler_define_boolean_variable(data->compiler, var->name, 0);

                if (error_val) {
                    merror("Adding boolean external variable '%s'", var->name);
                    break;
                }
                continue;
            }

            /* Check if floating point */
            if (w_StrIsFloat(var->value)) {
                double d = strtod(var->value, NULL);
                error_val = yr_compiler_define_float_variable(data->compiler, var->name, d);

                if (error_val) {
                    merror("Adding float external variable '%s'", var->name);
                    break;
                }
                continue;
            }

             /* Check if integer */
            if (OS_StrIsNum(var->value)) {
                int64_t i = strtol (var->value,NULL,10);
                error_val = yr_compiler_define_integer_variable(data->compiler, var->name, i);

                if (error_val) {
                    merror("Adding integer external variable '%s'", var->name);
                    break;
                }
                continue;
            }

            /* Is string */
            error_val = yr_compiler_define_string_variable(data->compiler, var->name, var->value);

            if (error_val) {
                merror("Adding string external variable '%s'", var->name);
                break;
            }
        }
    }
}

static void wm_yara_add_rule_string(wm_yara_t *data, char *rule, char *namespace) {
    yr_compiler_add_string(data->compiler, rule, namespace);
}

static cJSON *wm_yara_get_set_data(wm_yara_set_t *set) {
    assert(set);

    cJSON *object = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "set-data");

    if (set->name) {
        cJSON_AddStringToObject(object, "name", set->name);
    }

    if (set->description) {
        cJSON_AddStringToObject(object, "description", set->description);
    }

    if (set->rule) {

        cJSON *object_rules = cJSON_CreateArray();

        int i = 0;
        for (i = 0; set->rule[i]; i++) {
            cJSON *object_rule = cJSON_CreateObject();
            cJSON_AddStringToObject(object_rule, "path", set->rule[i]->path);
            cJSON_AddStringToObject(object_rule, "description", set->rule[i]->description);
            cJSON_AddItemToObject(object_rules, "rules", object_rule);
        }
       cJSON_AddItemToObject(object, "rules", object_rules);
    }

    return object;
}

static cJSON *wm_yara_get_rule_data(YR_RULE *rule) {
    cJSON *object = cJSON_CreateObject();

    cJSON *rule_strings = wm_yara_get_rule_strings(rule);
    cJSON *rule_metas = wm_yara_get_rule_metas(rule);

    cJSON_AddItemToObject(object, "strings", rule_strings);
    cJSON_AddItemToObject(object, "meta", rule_metas);
    cJSON_AddStringToObject(object, "name", rule->identifier);
    cJSON_AddStringToObject(object, "namespace", rule->ns->name);

    return object;
}

static int wm_yara_send_msg(wm_yara_t * data, char *msg)
{

#ifdef WIN32
    int queue_fd = 0;
#else
    int queue_fd = data->queue;
#endif

    mdebug2("Sending message: %s",msg);

    if (wm_sendmsg(data->msg_delay, queue_fd, msg, WM_YARA_STAMP, YARA_MQ) < 0) {
        merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

        if (data->queue >= 0) {
            close(data->queue);
        }

        if ((data->queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            mwarn("Can't connect to queue.");
        } else if (wm_sendmsg(data->msg_delay, data->queue, msg, WM_YARA_STAMP, YARA_MQ) < 0) {
            merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
            close(data->queue);
        }
    }

    os_free(msg);

    return (0);
}

static void wm_yara_send_set(wm_yara_t * data, wm_yara_set_t *set) {
    cJSON *object = wm_yara_get_set_data(set);
    char *msg = cJSON_PrintUnformatted(object);

    cJSON_Delete(object);
    wm_yara_send_msg(data,msg);
}

static void wm_yara_send_sets(wm_yara_t *data) {
    wm_yara_set_t *set;
    int index = 0;

    wm_yara_set_foreach(data,set,index) {
        if (set->enabled) {
            wm_yara_send_set(data,set);
        }
    }
}

static OSHash *wm_yara_get_excluded_files(char *path) {

    OSHash *excluded_files = OSHash_Create();

    if (!excluded_files) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
        return (0);
    }

    if (!path) {
        return NULL;
    }

    /* Check for wildcards */
    if (strchr(path, '*') || strchr(path, '?')) {
#ifndef WIN32

        glob_t g;
        int err;
        int glob_offset;

        glob_offset = 0;
        if (err = glob(path, 0, NULL, &g), err) {
            if (err == GLOB_NOMATCH) {
                mdebug1(GLOB_NFOUND, path);
            } else {
                mdebug1(GLOB_ERROR, path);
            }
        } else {

            while (g.gl_pathv[glob_offset] != NULL) {

                int hash_result = OSHash_Add(excluded_files, g.gl_pathv[glob_offset], (void *)1);

                switch (hash_result) {
                case 0:
                    merror("Could not add file '%s' to excluded hash table", g.gl_pathv[glob_offset]);
                    break;
                default:
                    break;
                }

                glob_offset++;
            }
            globfree(&g);
        }

        return excluded_files;
#else

    char *global_path = NULL;
    char *wildcard = NULL;
    os_strdup(path,global_path);

    wildcard = strrchr(global_path,'\\');

    if (wildcard) {

        DIR *dir = NULL;
        struct dirent *dirent;

        *wildcard = '\0';
        wildcard++;

        if (dir = opendir(global_path), !dir) {
            merror("Couldn't open directory '%s' due to: %s", global_path, strerror(errno));
            os_free(global_path);
            return excluded_files;
        }

        while (dirent = readdir(dir), dirent) {

            // Skip "." and ".."
            if (dirent->d_name[0] == '.' && (dirent->d_name[1] == '\0' || (dirent->d_name[1] == '.' && dirent->d_name[2] == '\0'))) {
                continue;
            }

            char full_path[PATH_MAX] = {0};
            snprintf(full_path, PATH_MAX, "%s\\%s", global_path, dirent->d_name);

            /* Skip file if it is a directory */
            DIR *is_dir = NULL;

            if (is_dir = opendir(full_path), is_dir) {
                mdebug2("File %s is a directory. Skipping it.", full_path);
                closedir(is_dir);
                continue;
            }

            /* Match wildcard */
            char *regex = NULL;
            regex = wstr_replace(wildcard, ".", "\\p");
            os_free(regex);
            regex = wstr_replace(wildcard, "*", "\\.*");

            /* Add the starting ^ regex */
            {
                char p[PATH_MAX] = {0};
                snprintf(p,PATH_MAX,"^%s",regex);
                os_free(regex);
                os_strdup(p, regex);
            }

            /* If wildcard is only ^\.* add another \.* */
            if (strlen(regex) == 4) {
                char *rgx = NULL;
                rgx = wstr_replace(regex, "\\.*", "\\.*\\.*");
                os_free(regex);
                regex = rgx;
            }

            /* Add $ at the end of the regex */
            wm_strcat(&regex, "$", 0);

            if(!OS_Regex(regex,dirent->d_name)) {
                mdebug2("Regex %s doesn't match with file '%s'", regex, dirent->d_name);
                os_free(regex);
                continue;
            }

            os_free(regex);

            /* Add the excluded file to the hash table */
            OSHash_Add(excluded_files, full_path, (void *)1);
        }
        closedir(dir);
    }
    os_free(global_path);

    return excluded_files;
#endif

    }

    /* Check if the path is a single file */
    DIR *dp;

    dp = opendir(path);

    if (!dp) {
        OSHash_Add(excluded_files,path,(void *)1);
    } else {
        closedir(dp);
    }

    return excluded_files;
}

static void wm_yara_add_matched_file(OSHash *table, char *filename, const char *rulename) {
    assert(table);
    assert(filename);
    assert(rulename);

    values_t *file_values = OSHash_Get_ex(table, filename);

    if (file_values) {
        file_values->file_exists = 1;

        if (!file_values->rules_matched) {
            wm_strcat(&file_values->rules_matched, rulename, 0);
            return;
        }

        /* Add the rule if its new match */
        if (strstr(rulename,file_values->rules_matched)) {
            wm_strcat(&file_values->rules_matched, rulename, WM_YARA_RULE_SEPARATOR);
            wm_yara_add_matched_file_integrity(file_values, file_values->rules_matched);
            OSHash_Add_ex(table, filename, file_values);
            mdebug1("File '%s' added. Matched rule '%s'", filename, rulename);
        }
        return;
    }

    os_calloc(1, sizeof(values_t), file_values);
    os_calloc(1, sizeof(char), file_values->rules_matched);
    file_values->file_exists = 1;
    wm_strcat(&file_values->rules_matched, rulename, 0);
    wm_yara_add_matched_file_integrity(file_values, file_values->rules_matched);
    OSHash_Add_ex(table,filename,file_values);
}

static void wm_yara_add_matched_file_integrity(values_t *file_values, char *str) {
    OS_SHA256_String(str, file_values->integrity);
}

static void wm_yara_reset_files_existance(OSHash *table) {
    OSHashNode *node;
    unsigned int *i;
    os_calloc(1, sizeof(unsigned int), i);

    for (node = OSHash_Begin(table, i); node; node = OSHash_Next(table, i, node)) {
        if(node->data){
            values_t *file_values = node->data;
            file_values->file_exists = 0;
        }
    }
    os_free(i);
}

static void wm_yara_remove_non_existing_files(OSHash *table) {
    OSHashNode *node;
    unsigned int *i;
    unsigned int num_files_to_remove = 0;

    os_calloc(1, sizeof(unsigned int), i);

    char **files_to_remove = NULL;
    os_realloc(files_to_remove, (2) * sizeof(char *), files_to_remove);

    for (node = OSHash_Begin(table, i); node; node = OSHash_Next(table, i, node)) {
        if(node->data){
            values_t *file_values = node->data;
            
            if (!file_values->file_exists) {
                os_realloc(files_to_remove, (num_files_to_remove + 2) * sizeof(char *), files_to_remove);
                os_strdup(node->key, files_to_remove[num_files_to_remove]);
                os_free(file_values->rules_matched);
                os_free(file_values->rules_matched_previous);
                os_free(file_values);
                num_files_to_remove++;
            }
        }
    }
    os_free(i);

    unsigned int index = 0;
    for (index = 0; index < num_files_to_remove; index++) {
        OSHash_Delete(table, files_to_remove[index]);
        os_free(files_to_remove[index]);
    }

    os_free(files_to_remove);
}

static void wm_yara_send_enabled_sets(wm_yara_t *data) {
    assert(data);
    int index = 0;
    wm_yara_set_t *set;

    cJSON *object = cJSON_CreateObject();
    cJSON *sets = cJSON_CreateArray();

    wm_yara_set_foreach(data, set, index) {
        if (!set->enabled) {
            continue;
        }
        cJSON_AddStringToObject(sets, "set", set->name ? set->name : NULL);
    }

    cJSON_AddStringToObject(object, "type", "sets-enabled");
    cJSON_AddItemToObject(object, "sets", sets);

    char *msg = cJSON_PrintUnformatted(object);

    cJSON_Delete(object);
    wm_yara_send_msg(data, msg);
}

static void wm_yara_send_rules(wm_yara_t *data) {
    int index = 0;
    wm_yara_set_t *set;

     wm_yara_set_foreach(data, set, index) {
        if (!set->enabled) {
            continue;
        }

        if (set->compiled_rules) {
            int i = 0;
            for (i = 0; set->compiled_rules[i]; i++) {

                YR_RULE *rule;
                yr_rules_foreach(set->compiled_rules[i], rule) {
                    cJSON *object = cJSON_CreateObject();
                    cJSON_AddStringToObject(object, "type", "rule-info");
                    cJSON_AddStringToObject(object, "set", set->name);

                    cJSON *rule_data = wm_yara_get_rule_data(rule);

                    cJSON_AddItemToObject(object, "data", rule_data);
                    char *msg = cJSON_PrintUnformatted(object);
                    
                    cJSON_Delete(object);
                    wm_yara_send_msg(data, msg);
                }
            }
        }
    }
}

static cJSON *wm_yara_get_rule_strings(YR_RULE *rule) {
    assert(rule);

    YR_STRING *string = NULL;
    cJSON *item = cJSON_CreateObject();

    yr_rule_strings_foreach(rule,string) {
        cJSON_AddStringToObject(item, string->identifier, (char *)string->string);
    }

    return item;
}

static cJSON *wm_yara_get_rule_metas(YR_RULE *rule) {
    assert(rule);

    YR_META *meta = NULL;
    cJSON *item = cJSON_CreateObject();

    yr_rule_metas_foreach(rule, meta) {
        char data[OS_SIZE_1024] = {0};
        
        if (!meta->string) {
            /* Integer */
            if (meta->type == 1) {
                snprintf(data, OS_SIZE_1024, "%ld", meta->integer);
            } else if (meta->type == 3) { /* Boolean*/

                if (meta->integer) {
                    snprintf(data, OS_SIZE_1024, "true");
                } else {
                    snprintf(data, OS_SIZE_1024, "false");
                }
            }
        } else {
            snprintf(data, OS_SIZE_1024, "%s", meta->string);
        }
        cJSON_AddStringToObject(item, meta->identifier, data);
    }

    return item;
}

static char *wm_yara_checksum_integrity(values_t *val) {
    return val ? val->integrity : NULL;
}

static void wm_yara_init_integrity(int rows) {
    integrity_struct = initialize_integrity(rows, (char * (*)(void *))wm_yara_checksum_integrity);
}

static void wm_yara_send_integrity(wm_yara_t *data) {
    cJSON * object = cJSON_CreateObject();

    /* TODO: Adjust index for blocks*/
    cJSON_AddStringToObject(object, "type", "files-integrity");
    cJSON_AddStringToObject(object, "block-name-l0", integrity_struct->level0->block_name);
    cJSON_AddStringToObject(object, "block-checksum-l0", integrity_struct->level0->checksum);
    cJSON_AddStringToObject(object, "block-name-l1", integrity_struct->level1->block_name);
    cJSON_AddStringToObject(object, "block-checksum-l1", integrity_struct->level1->checksum);
    cJSON_AddStringToObject(object, "block-name-l2", integrity_struct->level2->block_name);
    cJSON_AddStringToObject(object, "block-checksum-l2", integrity_struct->level2->checksum);

    char *msg = cJSON_PrintUnformatted(object);
    cJSON_Delete(object);
    wm_yara_send_msg(data, msg);
}

static void wm_yara_send_file(wm_yara_t *data, char *filename) {
    values_t * val = OSHash_Get(files_hash_table, filename);

    if (!val) {
        mdebug1("File '%s' not found on hash table", filename);
        return;
    }

    if (!val->rules_matched) {
        mdebug1("File '%s' has no rule match", filename);
        return;
    }

    if (!val->integrity) {
        mdebug1("File '%s' has no integrity", filename);
        return;
    }

    /* TODO: Adjust index for blocks*/  
    cJSON * object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "file");
    cJSON_AddStringToObject(object, "file-name", filename);
    cJSON_AddStringToObject(object, "checksum", val->integrity);
    cJSON_AddStringToObject(object, "rules-matched", val->rules_matched);
    cJSON_AddStringToObject(object, "level0", integrity_struct->level0->block_name);
    cJSON_AddStringToObject(object, "checksum-l0", integrity_struct->level0->checksum);
    cJSON_AddStringToObject(object, "level1", integrity_struct->level1->block_name);
    cJSON_AddStringToObject(object, "checksum-l1", integrity_struct->level1->checksum);
    cJSON_AddStringToObject(object, "level2", integrity_struct->level2->block_name);
    cJSON_AddStringToObject(object, "checksum-l2", integrity_struct->level2->checksum);

    char *msg = cJSON_PrintUnformatted(object);
    cJSON_Delete(object);
    wm_yara_send_msg(data, msg);
}

static void wm_yara_send_files(wm_yara_t *data, OSHash *table) {
    assert(data);
    assert(table);

    OSHashNode *node;
    unsigned int *i;
    os_calloc(1, sizeof(unsigned int), i);

    for (node = OSHash_Begin(table, i); node; node = OSHash_Next(table, i, node)) {
        if (node->data) {
            values_t *val = node->data;
            if (!val->rules_matched_previous) {
                wm_yara_send_file(data, node->key);
                minfo("RULES NOT MATCHED PREVIOUS : '%s'",val->rules_matched);
            } else if (strcmp(val->rules_matched, val->rules_matched_previous)) {
                minfo("RULES MATCHED : '%s'   '%s'",val->rules_matched,val->rules_matched_previous);
                wm_yara_send_file(data, node->key);
            }
        }
    }
    os_free(i);
}

static void wm_yara_send_scan_info(wm_yara_t *data, wm_yara_set_t *set, int start_time, int end_time) {
    assert(data);
    assert(set);

    cJSON *object = cJSON_CreateObject();

    cJSON_AddStringToObject(object, "type", "scan-info");
    cJSON_AddStringToObject(object, "set-name", set->name);
    cJSON_AddStringToObject(object, "set-description", set->description);
    cJSON_AddNumberToObject(object, "start", start_time);
    cJSON_AddNumberToObject(object, "end", end_time);

    char *msg = cJSON_PrintUnformatted(object);
    cJSON_Delete(object);
    wm_yara_send_msg(data, msg);
}

static void *wm_yara_dump_db_thread() {

    while (1) {
        request_dump_t *request;

        if (request = queue_pop_ex(request_queue), request) {
            char *integrity_block = request->integrity_blocks;
            char *saveptr = integrity_block; 
            char *next_block;

            while ((next_block = strtok_r(saveptr, ":", &saveptr))) {
               mdebug1("Sending blocks from integrity block name: '%s'", next_block);

               /* TODO: send files corresponding to each block */
            }

            os_free(request->integrity_blocks);
            os_free(request);
        }
    }
    return NULL;
}

#ifdef WIN32
void wm_yara_push_request_win(char * msg) {
    char *integrity_block = strchr(msg,':');

    if (!strncmp(msg, WM_YARA_DB_DUMP, strlen(WM_YARA_DB_DUMP)) && integrity_block) {

        request_dump_t *request;
        os_calloc(1, sizeof(request_dump_t), request);
        os_strdup(msg, request->integrity_blocks);

        if (queue_push_ex(request_queue, request) < 0) {
            os_free(request->integrity_blocks);
            os_free(request);
            mdebug1("Could not push yara integrity blocks to queue");
        }
    }
}
#endif

#ifndef WIN32
static void * wm_yara_request_thread(wm_yara_t * data) {

    /* Create request socket */
    int yara_queue;
    if ((yara_queue = StartMQ(YARAQUEUEPATH, READ)) < 0) {
        merror(QUEUE_ERROR, YARAQUEUEPATH, strerror(errno));
        pthread_exit(NULL);
    }

    int recv = 0;
    char *buffer = NULL;
    os_calloc(OS_MAXSTR + 1, sizeof(char), buffer);

    while (1) {
        if (recv = OS_RecvUnix(yara_queue, OS_MAXSTR, buffer),recv) {
            buffer[recv] = '\0';

            char *integrity_block = strchr(buffer, ':');

            if (!strncmp(buffer, WM_YARA_DB_DUMP, strlen(WM_YARA_DB_DUMP)) && integrity_block) {
                request_dump_t *request;
                os_calloc(1, sizeof(request_dump_t), request);
                os_strdup(buffer, request->integrity_blocks);

                if (queue_push_ex(request_queue, request) < 0) {
                    os_free(request->integrity_blocks);
                    os_free(request);
                    mdebug1("Could not push yara integrity blocks to queue");
                }
            }
        }
    }

    return NULL;
}
#endif

static void wm_yara_reset_matched_rules(OSHash *table) {
    assert(table);

    OSHashNode *node;
    unsigned int *i;
    os_calloc(1, sizeof(unsigned int), i);

    for (node = OSHash_Begin(table, i); node; node = OSHash_Next(table, i, node)) {
        if(node->data){
            values_t *val = node->data;
            if (val->rules_matched) {
                os_free(val->rules_matched_previous);
                os_strdup(val->rules_matched, val->rules_matched_previous);
                os_free(val->rules_matched);
            }
        }
    }
    os_free(i);
}

cJSON *wm_yara_dump(const wm_yara_t *data) {
    cJSON *root = cJSON_CreateObject();
    return root;
}
