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

static void * wm_yara_main(wm_yara_t * data);   // Module main function. It won't return
static void wm_yara_destroy(wm_yara_t * data); 
static int wm_yara_start(wm_yara_t * data);
static int wm_yara_send_event(wm_yara_t * data, cJSON *event);  
static int wm_yara_create_compiler(wm_yara_t * data);
static void wm_yara_destroy_compiler(wm_yara_t * data);
static int wm_yara_read_and_compile_rules(wm_yara_t * data, wm_yara_rule_t **rules, wm_yara_set_t *set);
static int wm_yara_save_compiled_rules(YR_RULES **compiled_rules,wm_yara_rule_t **rules, char *dir_name);
static int wm_yara_get_compiled_rules(wm_yara_t * data, wm_yara_rule_t **rules, wm_yara_set_t *set);
static int wm_yara_scan_file(YR_RULES **compiled_rules, char *filename, unsigned int timeout);
static void wm_yara_scan_process(YR_RULES **compiled_rules,int pid, unsigned int timeout);
static void wm_yara_scan_processes(YR_RULES **compiled_rules, char *filter, unsigned int timeout);
static void wm_yara_read_scan_directory(YR_RULES **compiled_rules,char *dir_name, int recursive, int max_depth, unsigned int timeout);
static void wm_yara_read_scan_files(YR_RULES **compiled_rules,wm_yara_path_t **paths, unsigned int timeout);
static int wm_yara_scan_results_file_callback(int message, void *message_data, void *user_data);
static int wm_yara_scan_results_process_callback(int message, void *message_data, void *user_data);
static int wm_yara_do_scan(int rule_db_index, unsigned int remote_rules, int first_scan);  
static int wm_yara_send_alert(wm_yara_t * data, cJSON *json_alert);
static int wm_yara_check_hash(OSHash *rule_db_hash, char *result, cJSON *profile,cJSON *event, int check_index, int file_index);
static char *wm_yara_hash_integrity(int policy_index);
static int wm_yara_hash_integrity_files(const char *file);
static char wm_yara_hash_integrity_file(const char *file);
static void wm_yara_send_rules_scanned(wm_yara_t * data);
static cJSON *wm_yara_get_rule_strings(YR_RULE *rule);
static cJSON *wm_yara_get_rule_metas(YR_RULE *rule);

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

    if (!data->set || data->set[0] == NULL) {
        minfo("No sets defined. Exiting.");
        pthread_exit(NULL);
    }

    data->msg_delay = 1000000 / wm_max_eps;
    data->summary_delay = 3; /* Seconds to wait for summary sending */
    data_win = data;

    /* Reading the internal options */

    // Default values
    data->request_db_interval = 300;

    data->request_db_interval = getDefine_Int("yara","request_db_interval", 1, 60) * 60;

    if (data->compiled_rules_directory == NULL) {
        mwarn("No directory for compiled rules defined. Compiled rules will not be saved");
    }

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


    /* Create YARA compiler */
    if (wm_yara_create_compiler(data)) {
        merror("Failed initializing YARA compiler");
        pthread_exit(NULL);
    }

    /* Read and compile rules */
    wm_yara_set_t *set;
    int i = 0;

    for ( i = 0; data->set[i]; i++) {
        wm_yara_set_t *set = data->set[i];
        if (wm_yara_read_and_compile_rules(data,set->rule,set)) {
            merror("Could not compile rules. Aborting");
            pthread_exit(NULL);
        }
    }
   
    /* Get compiled rules */
    for ( i = 0; data->set[i]; i++) {
        wm_yara_set_t *set = data->set[i];
        if (wm_yara_get_compiled_rules(data,set->rule,set)) {
            merror("Could not get compiled rules. Aborting");
            pthread_exit(NULL);
        }
    }

    /* Save compiled rules */
    /*if (data->compiled_rules_directory) {
        if (wm_yara_save_compiled_rules(set->compiled_rules,set->rule,data->compiled_rules_directory)){
            merror("Could not save compiled rules. Check folder permissions");
        }
    }*/

    while (1) {

        // Get time and execute
        time_start = time(NULL);

        minfo("Starting Yara scan.");

        /* Scan for each set */
        for (i = 0; data->set[i]; i++) {
            wm_yara_set_t *set = data->set[i];

            /* Skip set if disabled */
            if (!set->enabled) {
                continue;
            }

            /* Do scan for files adn directories */
            wm_yara_read_scan_files(set->compiled_rules,set->path,set->timeout);

            /* Do scan for processes */
            if (set->scan_processes) {
                wm_yara_scan_processes(set->compiled_rules,NULL,set->timeout);
            }
        }

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

    /* Destroy compiler */
    wm_yara_destroy_compiler(data);

    return 0;
}

static int wm_yara_read_and_compile_rules(wm_yara_t * data, wm_yara_rule_t **rule, wm_yara_set_t *set) {

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

                int add_rule_result = yr_compiler_add_fd(data->compiler,fd,NULL,rule[i]->path);

                if (add_rule_result) {
                    merror("Compiler error on line %d: [(%d)-(%s)]",data->compiler->last_error_line,data->compiler->last_error,data->compiler->last_error_extra_info);
                    merror("Couldn't compile rule '%s'",rule[i]->path);
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
    int ret_val = 0;
    int rules = 0;

    if (rule) {

        int i = 0;
        for (i = 0; rule[i]; i++) {

            /* Ignore the rule if it is disabled */
            if (!rule[i]->enabled) {
                continue;
            }

            int get_rules_result = yr_compiler_get_rules(data->compiler,&set->compiled_rules[rules]);

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

static int wm_yara_save_compiled_rule(YR_RULES *rules, char *filename) {
    return yr_rules_save(rules,filename);
}

static int wm_yara_scan_file(YR_RULES **compiled_rules, char *filename, unsigned int timeout) {
    
    int scan_result = 0;

    int i = 0;
    for (i = 0; compiled_rules[i]; i++)
    {
        if (scan_result = yr_rules_scan_file(compiled_rules[i], filename, SCAN_FLAGS_FAST_MODE, wm_yara_scan_results_file_callback, filename, timeout), scan_result)
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
                goto end;

            case ERROR_TOO_MANY_SCAN_THREADS:
                merror("Too many scan threads");
                goto end;

            case ERROR_SCAN_TIMEOUT:
                merror("Timeout reached");
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

static void wm_yara_scan_process(YR_RULES **compiled_rules,int pid,unsigned int timeout) {

    int scan_result = 0;

    int i = 0;
    for (i = 0; compiled_rules[i]; i++)
    {
        if (scan_result = yr_rules_scan_proc(compiled_rules[i], pid, 0, wm_yara_scan_results_process_callback, pid, timeout), scan_result)
        {
            switch (scan_result)
            {
            case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
                mdebug1("Could not attach to process: '%d'",pid);
                break;

            default:
                break;
            }
        }
    }
}

static void wm_yara_scan_processes(YR_RULES **compiled_rules, char *filter_process, unsigned int timeout) {

mdebug1("Start processes scan");
#if defined(__FreeBSD__) || defined(WIN32) || defined(__MACH__) 
    unsigned int max_pids = 99999;
#elif defined(__sun__) 
    unsigned int max_pids = 29999;
#else
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

    for (i = 1; i < max_pids; i++) {

        if (filter_process && (!((getsid(i) == -1) && (errno == ESRCH))) &&
                (!((getpgid(i) == -1) && (errno == ESRCH)))) {
            char *p_name;

            p_name = w_os_get_runps(ps, (int)i);
            if (!p_name) {
                continue;
            }

            if (!OS_Regex(filter_process, p_name)) {
                mdebug2("Regex %s doesn't match with process '%s'",filter_process, p_name);
                continue;
            }
            wm_yara_scan_process(compiled_rules,i,timeout);
            continue;
        }

        wm_yara_scan_process(compiled_rules,i,timeout);
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
                mdebug2("Regex %s doesn't match with process '%s'",filter_process, pinfo->p_name);
                continue;
            }
        }

        wm_yara_scan_process(compiled_rules,pinfo->pid,timeout);

        l_node = OSList_GetNextNode(p_list);
    }

    w_del_plist(p_list);

#endif
mdebug1("End processes scan");
}

static int wm_yara_create_compiler(wm_yara_t * data) {

    int ret_val = 0;

    ret_val = yr_compiler_create(&data->compiler);

    return ret_val;
}

static void wm_yara_destroy_compiler(wm_yara_t * data) {
    yr_compiler_destroy(data->compiler);
}

static int wm_yara_scan_results_file_callback(int message, void *message_data, void *user_data)
{

   switch (message)
   {
    case CALLBACK_MSG_RULE_MATCHING:
        mdebug1("Rule matched '%s' for file: '%s'",((YR_RULE *)message_data)->identifier,(char *)user_data);
        break;

    case CALLBACK_MSG_RULE_NOT_MATCHING:
        mdebug2("Rule not matched '%s' for file: '%s'",((YR_RULE *)message_data)->identifier,(char *)user_data);
        break;

    case CALLBACK_MSG_SCAN_FINISHED:
        mdebug2("Scan finished");
        break;

   default:
      break;
   }
}

static int wm_yara_scan_results_process_callback(int message, void *message_data, void *user_data)
{

   switch (message)
   {
    case CALLBACK_MSG_RULE_MATCHING:
        mdebug1("Rule matched '%s' for process: '%d'",((YR_RULE *)message_data)->identifier,(int)user_data);
        break;

    case CALLBACK_MSG_RULE_NOT_MATCHING:
        mdebug2("Rule not matched '%s' for process: '%d'",((YR_RULE *)message_data)->identifier,(int)user_data);
        break;

    case CALLBACK_MSG_SCAN_FINISHED:
        mdebug2("Scan finished");
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

static char wm_yara_hash_integrity_file(const char *file) {
    os_sha256 hash_file;

    if(OS_SHA256_File(file, hash_file, OS_TEXT) != 0){
        merror("Unable to calculate SHA256 for file '%s'", file);
        return NULL;
    }

    return hash_file;
}

static void wm_yara_read_scan_directory(YR_RULES **compiled_rules,char *dir_name, int recursive, int max_depth, unsigned int timeout) {

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

        snprintf(path,PATH_MAX,"%s/%s",dir_name,entry->d_name);

        DIR *child_dp;
        child_dp = opendir(path);

        if (child_dp) {
            if (recursive) {
                wm_yara_read_scan_directory(compiled_rules,path,recursive,max_depth-1,timeout);
            }
            closedir(child_dp);
        } else {
            /* Is a file, launch YARA scan */
            wm_yara_scan_file(compiled_rules,path,timeout);
        }
    }

    closedir(dp);
    os_free(path);
}

static int wm_yara_save_compiled_rules(YR_RULES **compiled_rules,wm_yara_rule_t **rules, char *dir_name) {
    int ret_val = 0;
    int rule = 0;

    if (rules) {

        int i = 0;
        for (i = 0; rules[i]; i++) {

            /* Ignore the rule if it is disabled */
            if (!rules[i]->enabled) {
                continue;
            }

            char filename[PATH_MAX] = {0};

#ifndef WIN32
            char *f = strrchr(rules[i]->path,'/');
#else
            char *f = strrchr(rules[i]->path,'\\');
#endif

            if (f) {

                f++;

#ifndef WIN32
                snprintf(filename,PATH_MAX,"%s/%s",dir_name,f);
#else
                snprintf(filename,PATH_MAX,"%s\\%s",dir_name,f);
#endif

                int save_rules_result = yr_rules_save(compiled_rules[rule],filename);

                switch (save_rules_result)
                {
                case ERROR_COULD_NOT_OPEN_FILE:
                    merror("Could not open file: '%s'",filename);
                    ret_val = 1;
                    goto end;
                
                default:
                    break;
                }
            }
           
            rule++;
        }
    }

end:

    return ret_val;
}

static void wm_yara_read_scan_files(YR_RULES **compiled_rules,wm_yara_path_t **paths,unsigned int timeout) {

    if (paths) {

        int i = 0;
        for (i = 0; paths[i]; i++) {

            if (paths[i]->ignore) {
                continue;
            }

            /* Check if the path is a directory */
            DIR *dp;

            if (strlen(paths[i]->path) > PATH_MAX) {
                return;
            }

            dp = opendir(paths[i]->path);

            if (!dp) {
                wm_yara_scan_file(compiled_rules,paths[i]->path,timeout);
            }
            else {
                
                wm_yara_read_scan_directory(compiled_rules,paths[i]->path,paths[i]->recursive,125,timeout);
                closedir(dp);
            }

            mdebug1("Start path scan: '%s'", paths[i]->path);
            wm_yara_scan_file(compiled_rules,paths[i]->path,timeout);
            mdebug1("End path scan: '%s'", paths[i]->path);
        }
    }
}

static cJSON *wm_yara_get_rule_strings(YR_RULE *rule) {

    YR_STRING *string = NULL;
    cJSON *obj = cJSON_CreateObject();
    cJSON *item = cJSON_CreateObject();

    yr_rule_strings_foreach(rule,string) {
        cJSON_AddStringToObject(item,string->identifier,string->string);
    }

    cJSON_AddItemToObject(obj,"strings",item);

    return obj;
}

static cJSON *wm_yara_get_rule_metas(YR_RULE *rule) {

    YR_META *meta = NULL;
    cJSON *obj = cJSON_CreateObject();
    cJSON *item = cJSON_CreateObject();

    yr_rule_metas_foreach(rule,meta) {
        cJSON_AddStringToObject(item,meta->identifier,meta->string);
    }

    cJSON_AddItemToObject(obj,"metadata",item);

    return obj;
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
