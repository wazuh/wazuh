/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015-2019, Wazuh Inc.
 * January 25, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <os_net/os_net.h>
#include "os_crypto/sha256/sha256_op.h"
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

typedef struct cis_db_info_t {
    char *result;
    cJSON *event;
} cis_db_info_t;

typedef struct cis_db_hash_info_t {
    cis_db_info_t **elem;
} cis_db_hash_info_t;

typedef struct request_dump_t {
    int policy_index;
    int first_scan;
} request_dump_t;

static void * wm_sca_main(wm_sca_t * data);   // Module main function. It won't return
static void wm_sca_destroy(wm_sca_t * data);  // Destroy data
static int wm_sca_start(wm_sca_t * data);  // Start
static cJSON *wm_sca_build_event(cJSON *profile,cJSON *policy,char **p_alert_msg,int id,char *result);
static int wm_sca_send_event_check(wm_sca_t * data,cJSON *event);  // Send check event
static void wm_sca_read_files(wm_sca_t * data);  // Read policy monitoring files
static int wm_sca_do_scan(OSList *plist,cJSON *profile_check,OSStore *vars,wm_sca_t * data,int id,cJSON *policy,int requirements_scan,int cis_db_index,unsigned int remote_policy,int first_scan);  // Do scan
static int wm_sca_send_summary(wm_sca_t * data, int scan_id,unsigned int passed, unsigned int failed,cJSON *policy,int start_time,int end_time, char * integrity_hash, int first_scan,int id);  // Send summary
static int wm_sca_check_policy(cJSON *policy, cJSON *profiles);
static int wm_sca_check_requirements(cJSON *requirements);
static void wm_sca_summary_increment_passed();
static void wm_sca_summary_increment_failed();
static void wm_sca_reset_summary();
static int wm_sca_send_alert(wm_sca_t * data,cJSON *json_alert); // Send alert
static int wm_sca_check_hash(OSHash *cis_db_hash,char *result,cJSON *profile,cJSON *event,int check_index,int policy_index);
static char *wm_sca_hash_integrity(int policy_index);
static void wm_sca_free_hash_data(cis_db_info_t *event);
static void * wm_sca_dump_db_thread(wm_sca_t * data);
static void wm_sca_send_policies_scanned(wm_sca_t * data);
static int wm_sca_send_dump_end(wm_sca_t * data, unsigned int elements_sent,char * policy_id,int scan_id);  // Send dump end event
static int append_msg_to_vm_scat (wm_sca_t * const data, const char * const msg);

#ifndef WIN32
static void * wm_sca_request_thread(wm_sca_t * data);
#endif

/* Extra functions */
static int wm_sca_get_vars(cJSON *variables,OSStore *vars);
static void wm_sca_set_condition(char *c_cond, int *condition); // Set condition
static char * wm_sca_get_value(char *buf, int *type); // Get value
static char * wm_sca_get_pattern(char *value); // Get pattern
static int wm_sca_check_file(char *file, char *pattern); // Check file
static int wm_sca_read_command(char *command, char *pattern,wm_sca_t * data); // Read command output
static int wm_sca_pt_check_negate(const char *pattern); // Check pattern negate
static int wm_sca_pt_matches(const char *str, char *pattern); // Check pattern match
static int wm_sca_check_dir(const char *dir, const char *file, char *pattern); // Check dir
static int wm_sca_is_process(char *value, OSList *p_list); // Check is a process

#ifdef WIN32
static int wm_check_registry_entry(char * const value);
static int wm_sca_is_registry(char *entry_name, char *reg_option, char *reg_value);
static char *wm_sca_os_winreg_getkey(char *reg_entry);
static int wm_sca_test_key(char *subkey, char *full_key_name, unsigned long arch,char *reg_option, char *reg_value, int * test_result);
static int wm_sca_winreg_querykey(HKEY hKey,__attribute__((unused))char *p_key,__attribute__((unused)) char *full_key_name,char *reg_option, char *reg_value);
static char *wm_sca_getrootdir(char *root_dir, int dir_size);
#endif

cJSON *wm_sca_dump(const wm_sca_t * data);     // Read config

const wm_context WM_SCA_CONTEXT = {
    SCA_WM_NAME,
    (wm_routine)wm_sca_main,
    (wm_routine)wm_sca_destroy,
    (cJSON * (*)(const void *))wm_sca_dump
};

static unsigned int summary_passed = 0;
static unsigned int summary_failed = 0;

OSHash **cis_db;
char **last_sha256;
cis_db_hash_info_t *cis_db_for_hash;

static w_queue_t * request_queue;
static wm_sca_t * data_win;

cJSON **last_summary_json = NULL;

// Module main function. It won't return
void * wm_sca_main(wm_sca_t * data) {
    // If module is disabled, exit
    if (data->enabled) {
        minfo("Module started.");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    if (!data->profile || data->profile[0] == NULL) {
        minfo("No policies defined. Exiting.");
        pthread_exit(NULL);
    }     

    data->msg_delay = 1000000 / wm_max_eps;
    data->summary_delay = 3; /* Seconds to wait for summary sending */
    data_win = data;

    /* Reading the internal options */

    // Default values
    data->request_db_interval = 300;
    data->remote_commands = 0;
    data->commands_timeout = 30;

    data->request_db_interval = getDefine_Int("sca","request_db_interval", 0, 60) * 60;
    data->commands_timeout = getDefine_Int("sca", "commands_timeout", 1, 300);
#ifdef CLIENT
    data->remote_commands = getDefine_Int("sca", "remote_commands", 0, 1);
#else
    data->remote_commands = 1;  // Only for agents
#endif

    /* Maximum request interval is the scan interval */
    if(data->request_db_interval > data->interval) {
       data->request_db_interval = data->interval;
       minfo("The request_db_interval option cannot be higher than the scan interval. It will be redefined to that value.");
    }

    /* Create Hash for each policy file */
    int i;
    if(data->profile){
        for(i = 0; data->profile[i]; i++) {
            os_realloc(cis_db, (i + 2) * sizeof(OSHash *), cis_db);
            cis_db[i] = OSHash_Create();
            if (!cis_db[i]) {
                merror(LIST_ERROR);
                return (0);
            }
            OSHash_SetFreeDataPointer(cis_db[i], (void (*)(void *))wm_sca_free_hash_data);

            /* DB for calculating hash only */
            os_realloc(cis_db_for_hash, (i + 2) * sizeof(cis_db_hash_info_t), cis_db_for_hash);

            /* Last summary for each policy */
            os_realloc(last_summary_json, (i + 2) * sizeof(cJSON *), last_summary_json);
            last_summary_json[i] = NULL;

            /* Prepare first ID for each policy file */
            os_calloc(1,sizeof(cis_db_info_t *),cis_db_for_hash[i].elem);
            cis_db_for_hash[i].elem[0] = NULL;
        }
    }

    /* Create summary hash for each policy file */
    if(data->profile){
        for(i = 0; data->profile[i]; i++) {
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

#ifndef WIN32
    w_create_thread(wm_sca_request_thread, data);
    w_create_thread(wm_sca_dump_db_thread, data);
#else
    if (CreateThread(NULL,
                    0,
                    (LPTHREAD_START_ROUTINE)wm_sca_dump_db_thread,
                    data,
                    0,
                    NULL) == NULL) {
                    merror(THREAD_ERROR);
    }
#endif

    wm_sca_start(data);

    return NULL;
}

static int wm_sca_send_alert(wm_sca_t * data,cJSON *json_alert)
{

#ifdef WIN32
    int queue_fd = 0;
#else
    int queue_fd = data->queue;
#endif

    char *msg = cJSON_PrintUnformatted(json_alert);
    mdebug2("Sending event: %s",msg);

    if (wm_sendmsg(data->msg_delay, queue_fd, msg,WM_SCA_STAMP, SCA_MQ) < 0) {
        merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));

        if(data->queue >= 0){
            close(data->queue);
        }

        if ((data->queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            mwarn("Can't connect to queue.");
        } else {
            if(wm_sendmsg(data->msg_delay, data->queue, msg,WM_SCA_STAMP, SCA_MQ) < 0) {
                merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                close(data->queue);
            }
        }
    }

    os_free(msg);

    return (0);
}

static void wm_sca_send_policies_scanned(wm_sca_t * data) {
    cJSON *policies_obj = cJSON_CreateObject();
    cJSON *policies = cJSON_CreateArray();

    int i;
    if(data->profile) {
        for(i = 0; data->profile[i]; i++) {
            if(data->profile[i]->enabled) {
                cJSON_AddStringToObject(policies,"policy",data->profile[i]->policy_id);
            }
        }
    }

    cJSON_AddStringToObject(policies_obj, "type", "policies");
    cJSON_AddItemToObject(policies_obj,"policies",policies);

    mdebug2("Sending scanned policies.");
    wm_sca_send_alert(data,policies_obj);
    cJSON_Delete(policies_obj);
}

static int wm_sca_start(wm_sca_t * data) {

    int status = 0;
    time_t time_start = 0;
    time_t time_sleep = 0;

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

        minfo("Starting Security Configuration Assessment scan.");

        /* Do scan for every policy file */
        wm_sca_read_files(data);

        /* Send policies scanned for database purge on manager side */
        wm_sca_send_policies_scanned(data);

        wm_delay(1000); // Avoid infinite loop when execution fails
        time_sleep = time(NULL) - time_start;

        minfo("Security Configuration Assessment scan finished. Duration: %d seconds.", (int)time_sleep);

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

static void wm_sca_read_files(wm_sca_t * data) {
    FILE *fp;
    int i = 0;
    static int first_scan = 1;

    /* Read every policy monitoring file */
    if(data->profile){
        for(i = 0; data->profile[i]; i++) {
            if(!data->profile[i]->enabled){
                continue;
            }

            char path[PATH_MAX] = {0};
            OSStore *vars = NULL;
            cJSON * object = NULL;
            OSList *plist = NULL;
            cJSON *requirements_array = NULL;
            int cis_db_index = i;

#ifdef WIN32
            if (data->profile[i]->profile[1] && data->profile[i]->profile[2]) {
                if ((data->profile[i]->profile[1] == ':') || (data->profile[i]->profile[0] == '\\' && data->profile[i]->profile[1] == '\\')) {
                    sprintf(path,"%s", data->profile[i]->profile);
                } else{
                    sprintf(path,"%s\\%s",SECURITY_CONFIGURATION_ASSESSMENT_DIR_WIN, data->profile[i]->profile);
                }
            }
#else
            if(data->profile[i]->profile[0] == '/') {
                sprintf(path,"%s", data->profile[i]->profile);
            } else {
                sprintf(path,"%s/%s",DEFAULTDIR SECURITY_CONFIGURATION_ASSESSMENT_DIR, data->profile[i]->profile);
            }
#endif

            fp = fopen(path,"r");

            if(!fp) {
                mwarn("Policy file not found: '%s'. Skipping it.",path);
                goto next;
            }

            /* Yaml parsing */
            yaml_document_t document;

            if (yaml_parse_file(path, &document)) {
                mwarn("Policy file could not be parsed: '%s'. Skipping it.",path);
                goto next;
            }

            if (object = yaml2json(&document,1), !object) {
                mwarn("Transforming yaml to json: '%s'. Skipping it.",path);
                goto next;
            }

            yaml_document_delete(&document);

            plist = w_os_get_process_list();
            cJSON *policy = cJSON_GetObjectItem(object, "policy");
            cJSON *variables = cJSON_GetObjectItem(object, "variables");
            cJSON *profiles = cJSON_GetObjectItem(object, "checks");
            requirements_array = cJSON_CreateArray();
            cJSON *requirements = cJSON_GetObjectItem(object, "requirements");
            cJSON_AddItemReferenceToArray(requirements_array, requirements);

            if(wm_sca_check_policy(policy, profiles)) {
                mwarn("Validating policy file: '%s'. Skipping it.", path);
                goto next;
            }

            if(requirements && wm_sca_check_requirements(requirements)) {
                mwarn("Reading 'requirements' section of file: '%s'. Skipping it.", path);
                goto next;
            }

            if(!data->profile[i]->policy_id) {
                cJSON *id = cJSON_GetObjectItem(policy, "id");
                os_strdup(id->valuestring,data->profile[i]->policy_id);
            }

            if(!profiles){
                mwarn("Reading 'checks' section of file: '%s'. Skipping it.", path);
                goto next;
            }

            vars = OSStore_Create();

            if( wm_sca_get_vars(variables,vars) != 0 ){
                mwarn("Reading 'variables' section of file: '%s'. Skipping it.", path);
                goto next;
            }

            // Set unique ID for each scan
#ifndef WIN32
                int id = os_random();
                if (id < 0)
                    id = -id;
#else
                unsigned int id1 = os_random();
                unsigned int id2 = os_random();

                char random_id[OS_MAXSTR];
                snprintf(random_id, OS_MAXSTR - 1, "%u%u", id1, id2);

                int id = atoi(random_id);
                if (id < 0)
                    id = -id;
#endif
            int requirements_satisfied = 0;

            if(!requirements) {
                requirements_satisfied = 1;
            }

            if(requirements) {
                if(wm_sca_do_scan(plist,requirements_array,vars,data,id,policy,1,cis_db_index,data->profile[i]->remote,first_scan) == 0){
                    requirements_satisfied = 1;
                }
            }

            if(!requirements_satisfied) {
                cJSON *title = cJSON_GetObjectItem(requirements,"title");
                minfo("Skipping policy '%s': '%s'.",data->profile[i]->profile,title->valuestring);
            }

            if(requirements_satisfied) {
                time_t time_start = 0;
                time_t time_end = 0;
                time_start = time(NULL);

                minfo("Starting evaluation of policy: '%s", data->profile[i]->profile);

                if (wm_sca_do_scan(plist,profiles,vars,data,id,policy,0,cis_db_index,data->profile[i]->remote,first_scan) != 0) {
                    merror("Evaluating the policy file: '%s. Set debug mode for more detailed information.", data->profile[i]->profile);
                }
                mdebug1("Calculating hash for scanned results.");
                char * integrity_hash = wm_sca_hash_integrity(cis_db_index);
                time_end = time(NULL);

                /* Send summary */
                if(integrity_hash) {
                    wm_delay(1000 * data->summary_delay);
                    wm_sca_send_summary(data,id,summary_passed,summary_failed,policy,time_start,time_end,integrity_hash,first_scan,cis_db_index);
                    snprintf(last_sha256[cis_db_index] ,sizeof(os_sha256),"%s",integrity_hash);
                    os_free(integrity_hash);
                }

                minfo("Evaluation finished for policy '%s'.",data->profile[i]->profile);
                wm_sca_reset_summary();
            }

            w_del_plist(plist);
            plist = NULL;

    next:
            if(fp){
                fclose(fp);
            }

            if(object) {
                cJSON_Delete(object);
            }

            if(requirements_array){
                cJSON_Delete(requirements_array);
            }

            if(vars) {
                OSStore_Free(vars);
            }

            if(plist) {
                w_del_plist(plist);
            }
        }
        first_scan = 0;
    }
}

static int wm_sca_check_policy(cJSON *policy, cJSON *profiles) {
    int retval, i;
    cJSON *id;
    cJSON *name;
    cJSON *file;
    cJSON *description;
    cJSON *check;
    cJSON *check_id;
    cJSON *rule;
    cJSON *rules_id;
    int * read_id;

    retval = 1;

    if(!policy) {
        return retval;
    }

    id = cJSON_GetObjectItem(policy, "id");
    if(!id) {
        mwarn("Field 'id' not found in policy header.");
        return retval;
    }

    if(!id->valuestring){
        mwarn("Invalid format for field 'id'.");
        return retval;
    }

    name = cJSON_GetObjectItem(policy, "name");
    if(!name) {
        mwarn("Field 'name' not found in policy header.");
        return retval;
    }

    if(!name->valuestring){
        mwarn("Invalid format for field 'name'.");
        return retval;
    }

    file = cJSON_GetObjectItem(policy, "file");
    if(!file) {
        mwarn("Field 'file' not found in policy header.");
        return retval;
    }

    if(!file->valuestring){
        mwarn("Invalid format for field 'file'.");
        return retval;
    }

    description = cJSON_GetObjectItem(policy, "description");
    if(!description) {
        mwarn("Field 'description' not found in policy header.");
        return retval;
    }

    if(!description->valuestring) {
        mwarn("Invalid format for field 'description'.");
        return retval;
    }

    // Check for policy rules with duplicated IDs */
    if (!profiles) {
        mwarn("Section 'checks' not found.");
        return retval;
    } else {
        os_calloc(1, sizeof(int), read_id);
        read_id[0] = 0;
        int rules_n = 0;

        cJSON_ArrayForEach(check, profiles){

            check_id = cJSON_GetObjectItem(check, "id");

            if (check_id == NULL) {
                mwarn("Check ID not found.");
                free(read_id);
                return retval;
            } else if (check_id->valueint <= 0) {
                // Invalid ID
                mwarn("Invalid check ID: %d", check_id->valueint);
                free(read_id);
                return retval;
            }

            for (i = 0; read_id[i] != 0; i++) {
                if (check_id->valueint == read_id[i]) {
                    // Duplicated ID
                    mwarn("Duplicated check ID: %d", check_id->valueint);
                    free(read_id);
                    return retval;
                }
            }
            os_realloc(read_id, sizeof(int) * (i + 2), read_id);
            read_id[i] = check_id->valueint;
            read_id[i + 1] = 0;

            rules_id = cJSON_GetObjectItem(check, "rules");

            if (rules_id == NULL) {
                mwarn("Invalid check %d: no rules found.", check_id->valueint);
                free(read_id);
                return retval;
            }

            cJSON_ArrayForEach(rule, rules_id){

                if (!rule->valuestring) {
                    mwarn("Invalid check %d: Empty rule.", check_id->valueint);
                    free(read_id);
                    return retval;
                } else {
                    switch (rule->valuestring[0]) {
                        case 'f':
                            break;
                        case 'd':
                            break;
                        case 'p':
                            break;
                        case 'r':
                            break;
                        case 'c':
                            break;
                        case '\0':
                            mwarn("Invalid check %d: Empty rule.", check_id->valueint);
                            free(read_id);
                            return retval;
                        default:
                            mwarn("Invalid check %d: Invalid rule format.", check_id->valueint);
                            free(read_id);
                            return retval;
                    }
                }

                rules_n++;

                if (rules_n > 255) {
                    free(read_id);
                    mwarn("Invalid check %d: Maximum number of rules is 255.", check_id->valueint);
                    return retval;
                }
            }

            if (rules_n == 0) {
                mwarn("Invalid check %d: no rules found.", check_id->valueint);
                free(read_id);
                return retval;
            }

            rules_n = 0;
        }
        free(read_id);
    }

    retval = 0;
    return retval;
}

static int wm_sca_check_requirements(cJSON *requirements) {
    int retval;
    cJSON *title;
    cJSON *description;
    cJSON *condition;

    retval = 1;

    if(!requirements) {
        return retval;
    }

    title = cJSON_GetObjectItem(requirements, "title");
    if(!title) {
        merror("Field 'title' not found on requirements.");
        return retval;
    }

    if(!title->valuestring){
        merror("Field 'title' must be a string.");
        return retval;
    }

    description = cJSON_GetObjectItem(requirements, "description");
    if(!description) {
        merror("Field 'description' not found on policy.");
        return retval;
    }

    if(!description->valuestring){
        merror("Field 'description' must be a string.");
        return retval;
    }

    condition = cJSON_GetObjectItem(requirements, "condition");
    if(!condition) {
        merror("Field 'condition' not found on policy.");
        return retval;
    }

    if(!condition->valuestring){
        merror("Field 'condition' must be a string.");
        return retval;
    }

    retval = 0;
    return retval;
}

static int wm_sca_do_scan(OSList *p_list,cJSON *profile_check,OSStore *vars,wm_sca_t * data,int id,cJSON *policy,int requirements_scan,int cis_db_index,unsigned int remote_policy,int first_scan) {

    int type = 0, condition = 0, invalid = 0;
    char *nbuf = NULL;
    char buf[OS_SIZE_1024 + 2];
    char root_dir[OS_SIZE_1024 + 2];
    char final_file[2048 + 1];
    char *name = NULL;
    int ret_val = 0;
    int id_check_p = 0;
    cJSON *c_title = NULL;
    cJSON *c_condition = NULL;

    /* Initialize variables */
    memset(buf, '\0', sizeof(buf));
    memset(root_dir, '\0', sizeof(root_dir));
    memset(final_file, '\0', sizeof(final_file));

#ifdef WIN32
    /* Get Windows rootdir */
    wm_sca_getrootdir(root_dir, sizeof(root_dir) - 1);
    if (root_dir[0] == '\0') {
        merror(INVALID_ROOTDIR);
    }
#endif
    cJSON *profile = NULL;
    int check_count = 0;

    cJSON_ArrayForEach(profile,profile_check){

        if(!cis_db_for_hash[cis_db_index].elem[check_count]) {
            os_realloc(cis_db_for_hash[cis_db_index].elem, sizeof(cis_db_info_t *) * (check_count + 2), cis_db_for_hash[cis_db_index].elem);
            cis_db_for_hash[cis_db_index].elem[check_count] = NULL;
            cis_db_for_hash[cis_db_index].elem[check_count + 1] = NULL;
        }

        check_count++;
        invalid = 0;

        c_title = cJSON_GetObjectItem(profile, "title");
        c_condition = cJSON_GetObjectItem(profile, "condition");
        cJSON *p_checks = cJSON_GetObjectItem(profile, "rules");

        /* Get first name */
        if(c_title) {
            if(!c_title->valuestring) {
                mdebug1("Field 'title' must be a string.");
                ret_val = 1;
                goto clean_return;
            }
            name = strdup(c_title->valuestring);
        } else {
            os_free(name);
        }

        /* Get condition */
        if(c_condition) {
            if(!c_condition->valuestring) {
                mdebug1("Field 'condition' must be a string.");
                ret_val = 1;
                goto clean_return;
            }
            wm_sca_set_condition(c_condition->valuestring,&condition);
        } else {
            wm_sca_set_condition("invalid",&condition);
        }

        if (name == NULL || condition == WM_SCA_COND_INV) {
            merror(WM_SCA_INVALID_RKCL_NAME, name ? name : "NULL!");
            ret_val = 1;
            goto clean_return;
        }

        if(p_checks){
            cJSON *p_check;

            int g_found = 0;
            int not_found = 0;
            char *rule_cp = NULL;
            cJSON_ArrayForEach(p_check,p_checks)
            {
                /* this free is responsible of freeing the copy of the previous rule if
                the loop 'continues', i.e, does not reach the end of its block. */
                os_free(rule_cp);
                mdebug2("Checking entry: '%s'.", name);

                int negate = 0;
                int found = 0;

                if(!p_check->valuestring) {
                    mdebug1("Field 'rule' must be a string.");
                    ret_val = 1;
                    goto clean_return;
                }
                nbuf = p_check->valuestring;
                mdebug2("Rule is: %s",nbuf);

                /* Make a copy of the rule */
                os_strdup(nbuf, rule_cp);

                /* Get value to look for. char *value is a reference
                to rule_cp memory. Do not release value!  */
                char *value = wm_sca_get_value(rule_cp, &type);
                if (value == NULL) {
                    merror(WM_SCA_INVALID_RKCL_VALUE, nbuf);
                    os_free(rule_cp);
                    goto clean_return;
                }

                /* Get negate value */
                if (*value == '!') {
                    negate = 1;
                    value++;
                }

                /* Check for a file */
                if (type == WM_SCA_TYPE_FILE) {
                    char *pattern = NULL;
                    char *f_value = NULL;

                    pattern = wm_sca_get_pattern(value);
                    f_value = value;

                    /* Get any variable */
                    if (value[0] == '$') {
                        f_value = (char *) OSStore_Get(vars, value);
                        if (!f_value) {
                            merror(WM_SCA_INVALID_RKCL_VAR, value);
                            continue;
                        }
                    }

    #ifdef WIN32
                    else if (value[0] == '\\') {
                        final_file[0] = '\0';
                        final_file[sizeof(final_file) - 1] = '\0';

                        snprintf(final_file, sizeof(final_file) - 2, "%s%s",
                                root_dir, value);
                        f_value = final_file;
                    } else {
                        final_file[0] = '\0';
                        final_file[sizeof(final_file) - 1] = '\0';

                        ExpandEnvironmentStrings(value, final_file,
                                                sizeof(final_file) - 2);
                        f_value = final_file;
                    }
    #endif

                    mdebug2("Checking file: '%s'.", f_value);
                    if (wm_sca_check_file(f_value, pattern)) {
                        mdebug2("Found file.");
                        found = 1;
                    }
                    char _b_msg[OS_SIZE_1024 + 1];
                    _b_msg[OS_SIZE_1024] = '\0';
                    snprintf(_b_msg, OS_SIZE_1024, " File: %s", f_value);
                    append_msg_to_vm_scat(data, _b_msg);
                }
                /* Check for a command */
                else if (type == WM_SCA_TYPE_COMMAND) {

                    if (!data->remote_commands && remote_policy) {
                        mwarn("Ignoring check for policy '%s'. The internal option 'sca.remote_commands' is disabled.", cJSON_GetObjectItem(policy, "name")->valuestring);
                        invalid = 1;
                        break;
                    }

                    char *pattern = NULL;
                    char *f_value = NULL;

                    pattern = wm_sca_get_pattern(value);
                    f_value = value;

                    /* Get any variable */
                    if (value[0] == '$') {
                        f_value = (char *) OSStore_Get(vars, value);
                        if (!f_value) {
                            merror(WM_SCA_INVALID_RKCL_VAR, value);
                            continue;
                        }
                    }

                    mdebug2("Running command: '%s'.", f_value);
                    if (wm_sca_read_command(f_value, pattern,data)) {
                        mdebug2("Command returned found.");
                        found = 1;
                    } else {
                        mdebug2("Command returned not found.");
                    }
                    char _b_msg[OS_SIZE_1024 + 1];
                    _b_msg[OS_SIZE_1024] = '\0';
                    snprintf(_b_msg, OS_SIZE_1024, " Command: %s", f_value);
                    append_msg_to_vm_scat(data, _b_msg);
                }

    #ifdef WIN32
                /* Check for a registry entry */
                else if (type == WM_SCA_TYPE_REGISTRY) {
                    found = wm_check_registry_entry(value);

                    char _b_msg[OS_SIZE_1024 + 1];
                    _b_msg[OS_SIZE_1024] = '\0';
                    snprintf(_b_msg, OS_SIZE_1024, " Registry: %s", value);
                    append_msg_to_vm_scat(data, _b_msg);
                }
    #endif
                /* Check for a directory */
                else if (type == WM_SCA_TYPE_DIR) {
                    char *file = NULL;
                    char *pattern = NULL;
                    char *f_value = NULL;
                    char *dir = NULL;

                    file = wm_sca_get_pattern(value);
                    if (!file) {
                        merror(WM_SCA_INVALID_RKCL_VAR, value);
                        continue;
                    }

                    pattern = wm_sca_get_pattern(file);

                    /* Get any variable */
                    if (value[0] == '$') {
                        f_value = (char *) OSStore_Get(vars, value);
                        if (!f_value) {
                            merror(WM_SCA_INVALID_RKCL_VAR, value);
                            continue;
                        }
                    } else {
                        f_value = value;
                    }

                    /* Check for multiple comma separated directories */
                    dir = f_value;
                    f_value = strchr(dir, ',');
                    if (f_value) {
                        *f_value = '\0';
                    }

                    while (dir) {
                        mdebug2("Checking dir: %s", dir);

                        short is_nfs = IsNFS(dir);
                        if( is_nfs == 1 && data->skip_nfs ) {
                            mdebug2("skip_nfs enabled and %s is flagged as NFS.", dir);
                        } else {
                            mdebug2("%s => is_nfs=%d, skip_nfs=%d", dir, is_nfs, data->skip_nfs);
                            if (wm_sca_check_dir(dir, file, pattern)) {
                                mdebug2("Found dir.");
                                found = 1;
                            }
                        }

                        char _b_msg[OS_SIZE_1024 + 1];
                        _b_msg[OS_SIZE_1024] = '\0';
                        snprintf(_b_msg, OS_SIZE_1024, " Directory: %s", dir);
                        append_msg_to_vm_scat(data, _b_msg);
                        if (f_value) {
                            *f_value = ',';
                            f_value++;

                            dir = f_value;

                            f_value = strchr(dir, ',');
                            if (f_value) {
                                *f_value = '\0';
                            }
                        } else {
                            dir = NULL;
                        }
                    }
                }

                /* Check for a process */
                else if (type == WM_SCA_TYPE_PROCESS) {
                    mdebug2("Checking process: '%s'", value);
                    if (wm_sca_is_process(value, p_list)) {
                        mdebug2("Process found.");
                        found = 1;
                    } else {
                        mdebug2("Process not found.");
                    }
                    char _b_msg[OS_SIZE_1024 + 1];
                    _b_msg[OS_SIZE_1024] = '\0';
                    snprintf(_b_msg, OS_SIZE_1024, " Process: %s", value);
                    append_msg_to_vm_scat(data, _b_msg);
                }

                /* Switch the values if ! is present */
                if (negate) {
                    if (found) {
                        found = 0;
                    } else {
                        found = 1;
                    }
                }

                /* Check the conditions */
                if (condition & WM_SCA_COND_ANY) {
                    mdebug2("Condition ANY.");
                    if (found) {
                        g_found = 1;
                    }
                } else if (condition & WM_SCA_COND_NON) {
                    mdebug2("Condition NON.");
                    if (!found && (not_found != -1)) {
                        mdebug2("Condition NON setze not_found=1.");
                        not_found = 1;
                    } else {
                        not_found = -1;
                    }
                } else {
                    /* Condition for ALL */
                    mdebug2("Condition ALL.");
                    if (found && (g_found != -1)) {
                        g_found = 1;
                    } else {
                        g_found = -1;
                    }
                }
            }

            /* if the loop breaks, rule_cp shall be released.
               Also frees the the memory for the last iteration */
            os_free(rule_cp);

            if (condition & WM_SCA_COND_NON) {
                if (not_found == -1){ g_found = 0;} else {g_found = 1;}
            }

            /* Alert if necessary */
            int i = 0;
            if (g_found == 1) {
                char **p_alert_msg = data->alert_msg;
                if (!requirements_scan) {
                    wm_sca_summary_increment_failed();
                    cJSON *event = wm_sca_build_event(profile,policy,p_alert_msg,id,"failed");

                    if(event){
                        if(wm_sca_check_hash(cis_db[cis_db_index],"failed",profile,event,id_check_p,cis_db_index) && !requirements_scan && !first_scan) {
                            wm_sca_send_event_check(data,event);
                        }
                        cJSON_Delete(event);
                    } else {
                        merror("Building event for check: %s. Set debug mode for more information.", name);
                        ret_val = 1;
                    }
                }

                for (i=0; data->alert_msg[i]; i++){
                    free(data->alert_msg[i]);
                    data->alert_msg[i] = NULL;
                }

                if (requirements_scan == 1){
                    wm_sca_reset_summary();
                    goto clean_return;
                }
            } else {
                char **p_alert_msg = data->alert_msg;
                if (!requirements_scan) {
                    wm_sca_summary_increment_passed();
                    cJSON *event = wm_sca_build_event(profile,policy,p_alert_msg,id,"passed");

                    if(event){
                        if(wm_sca_check_hash(cis_db[cis_db_index],"passed",profile,event,id_check_p,cis_db_index) && !requirements_scan && !first_scan) {
                            wm_sca_send_event_check(data,event);
                        }
                        cJSON_Delete(event);
                    } else {
                        merror("Building event for check: %s. Set debug mode for more information.", name);
                        ret_val = 1;
                    }
                }

                for (i=0; data->alert_msg[i]; i++){
                    free(data->alert_msg[i]);
                    data->alert_msg[i] = NULL;
                }

                    if (condition & WM_SCA_COND_REQ) {
                        if (requirements_scan == 1){
                            ret_val = 1;
                        }
                        goto clean_return;
                    }

                if (requirements_scan == 1){
                    wm_sca_reset_summary();
                    goto clean_return;
                }
            }

            if (invalid) {  // Ignore this check
                check_count--;
                // Free resources
                int j = 0;
                while (data->alert_msg[j]) {
                    free(data->alert_msg[j]);
                    data->alert_msg[j] = NULL;
                    j++;
                }
                if (!nbuf) {
                    goto clean_return;
                }
                os_free(name);
                continue;
            }

            /* End if we don't have anything else */
            if (!nbuf) {
                goto clean_return;
            }
        }
        /* Clean up name */
        os_free(name);

        id_check_p++;
    }

/* Clean up memory */
clean_return:
    os_free(name);

    return ret_val;

}

static void wm_sca_set_condition(char *c_cond, int *condition) {
    /* Get condition */
    if (strcmp(c_cond, "all") == 0) {
        *condition |= WM_SCA_COND_ALL;
    } else if (strcmp(c_cond, "any") == 0) {
        *condition |= WM_SCA_COND_ANY;
    } else if (strcmp(c_cond, "none") == 0) {
        *condition |= WM_SCA_COND_NON;
    } else if (strcmp(c_cond, "any required") == 0) {
        *condition |= WM_SCA_COND_ANY;
        *condition |= WM_SCA_COND_REQ;
    } else if (strcmp(c_cond, "all required") == 0) {
        *condition |= WM_SCA_COND_ALL;
        *condition |= WM_SCA_COND_REQ;
    } else {
        *condition = WM_SCA_COND_INV;
    }
}

static int wm_sca_get_vars(cJSON *variables,OSStore *vars) {

    cJSON *variable;
    cJSON_ArrayForEach(variable,variables){

        /* If not a variable, return 0 */
        if (*variable->string != '$') {
            merror(WM_SCA_INVALID_RKCL_VAR, variable->string);
            return (0);
        }

        /* Remove semicolon from the end */
        char *tmp = strchr(variable->valuestring, ';');
        if (tmp) {
            *tmp = '\0';
        } else {
            return (-1);
        }

        char * var_value;
        os_strdup(variable->valuestring,var_value);
        OSStore_Put(vars, variable->string, var_value);
    }

    return 0;
}

static char *wm_sca_get_value(char *buf, int *type)
{
    char *tmp_str;
    char *value;

    /* Zero type before using it to make sure return is valid
     * in case of error.
     */
    *type = 0;

    value = strchr(buf, ':');
    if (value == NULL) {
        return (NULL);
    }

    *value = '\0';
    value++;

    tmp_str = strchr(value, ';');
    if (tmp_str == NULL) {
        return (NULL);
    }
    *tmp_str = '\0';

    /* Get types - removing negate flag (using later) */
    if (*buf == '!') {
        buf++;
    }

    if (strcmp(buf, "f") == 0) {
        *type = WM_SCA_TYPE_FILE;
    } else if (strcmp(buf, "r") == 0) {
        *type = WM_SCA_TYPE_REGISTRY;
    } else if (strcmp(buf, "p") == 0) {
        *type = WM_SCA_TYPE_PROCESS;
    } else if (strcmp(buf, "d") == 0) {
        *type = WM_SCA_TYPE_DIR;
    } else if (strcmp(buf, "c") == 0) {
        *type = WM_SCA_TYPE_COMMAND;
    } else {
        return (NULL);
    }

    return (value);
}

static char *wm_sca_get_pattern(char *value)
{
    while (*value != '\0') {
        if ((*value == ' ') && (value[1] == '-') &&
                (value[2] == '>') && (value[3] == ' ')) {
            *value = '\0';
            value += 4;

            return (value);
        }
        value++;
    }

    return (NULL);
}

static int wm_sca_check_file(char *file, char *pattern)
{
    char *split_file;
    int full_negate = 0;
    int pt_result = 0;
    FILE *fp;
    char buf[OS_SIZE_2048 + 1];

    if (file == NULL) {
        return (0);
    }

    /* Check if the file is divided */
    split_file = strchr(file, ',');
    if (split_file) {
        *split_file = '\0';
        split_file++;
    }

    /* Get each file */
    do {
        /* If we don't have a pattern, just check if the file/dir is there */
        if (pattern == NULL) {
            if (w_is_file(file)) {
                return (1);
            }
        } else {
            full_negate = wm_sca_pt_check_negate(pattern);
            /* Check for content in the file */
            fp = fopen(file, "r");
            if (fp) {

                buf[OS_SIZE_2048] = '\0';
                while (fgets(buf, OS_SIZE_2048, fp) != NULL) {
                    char *nbuf;

                    /* Remove end of line */
                    nbuf = strchr(buf, '\n');
                    if (nbuf) {
                        *nbuf = '\0';
                    }
#ifdef WIN32
                    /* Remove end of line */
                    nbuf = strchr(buf, '\r');
                    if (nbuf) {
                        *nbuf = '\0';
                    }
#endif
                    /* Matched */
                    pt_result = wm_sca_pt_matches(buf, pattern);
                    if ((pt_result == 1 && full_negate == 0) ) {
                        mdebug2("Alerting file %s on line %s", file, buf);
                        fclose(fp);
                        return (1);
                    } else if ((pt_result == 0 && full_negate == 1) ) {
                        /* Found a full+negate match so no longer need to search
                         * break out of loop and make sure the full negate does
                         * not alert.
                         */
                        mdebug2("Found a complete match for full_negate");
                        full_negate = 0;
                        break;
                    }
                }

                fclose(fp);

                if (full_negate == 1) {
                    mdebug2("Full_negate alerting - file %s", file);
                    return (1);
                }
            }
        }

        if (split_file) {
            file = split_file;
            split_file = strchr(split_file, ',');
            if (split_file) {
                split_file++;
            }
        }


    } while (split_file);

    return (0);
}

static int wm_sca_read_command(char *command, char *pattern,wm_sca_t * data)
{
    int full_negate = 0;
    int pt_result = 0;

    if (command == NULL) {
        return (0);
    }

    /* If we don't have a pattern, just check if the file/dir is there */
    if (pattern == NULL) {
        return (1);
    } else {
        full_negate = wm_sca_pt_check_negate(pattern);
        /* Check for content in the file */
        char *cmd_output = NULL;
        int result_code;

        if( wm_exec(command,&cmd_output,&result_code,data->commands_timeout,NULL) < 0 )  {
            if (result_code == EXECVE_ERROR) {
                mdebug1("Can't run command(%s): path is invalid or file has insufficient permissions.",command);
            } else {
                mdebug1("Error executing [%s]", command);
            }
            return 0;
        } else if (result_code != 0) {
            mdebug1("Command (%s) returned code %d.", command, result_code);
        }

        if(!cmd_output) {
            return 0;
        }

        char **output_line;
        output_line = OS_StrBreak('\n', cmd_output, 256);

        if(!output_line) {
            mdebug1("Command output '%s' has not ending line  '\n' character",cmd_output);
            os_free(cmd_output);
            return 0;
        }

        os_free(cmd_output);

        int i;
        for (i=0; output_line[i] != NULL; i++) {
            char *buf = output_line[i];
            mdebug2("Checking output '%s' for pattern match",buf);

#ifdef WIN32
            char *nbuf;
            /* Remove end of line */
            nbuf = strchr(buf, '\r');
            if (nbuf) {
                *nbuf = '\0';
            }
#endif
            /* Matched */
            pt_result = wm_sca_pt_matches(buf, pattern);
            if ((pt_result == 1 && full_negate == 0) ) {
                free_strarray(output_line);
                return (1);
            } else if ((pt_result == 0 && full_negate == 1) ) {
                /* Found a full+negate match so no longer need to search
                    * break out of loop and make sure the full negate does
                    * not alert.
                    */
                mdebug2("Found a complete match for full_negate");
                full_negate = 0;
                break;
            }
         
        }

        if (full_negate == 1) {
            free_strarray(output_line);
            return (1);
        }

        free_strarray(output_line);
    }

    return (0);
}

/* Check if the pattern is all negate values */
static int wm_sca_pt_check_negate(const char *pattern)
{
    char *mypattern = NULL;
    os_strdup(pattern, mypattern);
    char *tmp_pt = mypattern;
    char *tmp_pattern = mypattern;

    while (tmp_pt != NULL) {
        /* First look for " && " */
        tmp_pt = strchr(tmp_pattern, ' ');
        if (tmp_pt && tmp_pt[1] == '&' && tmp_pt[2] == '&' && tmp_pt[3] == ' ') {
            *tmp_pt = '\0';
            tmp_pt += 4;
        } else {
            tmp_pt = NULL;
        }

        if (*tmp_pattern != '!') {
            free(mypattern);
            return 0;
        }

        tmp_pattern = tmp_pt;
    }

    mdebug2("Pattern: %s is fill_negate", pattern);
    free(mypattern);
    return (1);
}

static int wm_sca_pt_matches(const char *str, char *pattern)
{
    int neg = 0;
    int ret_code = 0;
    char *tmp_pt = pattern;
    char *tmp_ret = NULL;

    if (str == NULL) {
        return (0);
    }

    while (tmp_pt != NULL) {
        /* First look for " && " */
        tmp_pt = strchr(pattern, ' ');
        if (tmp_pt && tmp_pt[1] == '&' && tmp_pt[2] == '&' && tmp_pt[3] == ' ') {
            /* Mark pointer to clean it up */
            tmp_ret = tmp_pt;

            *tmp_pt = '\0';
            tmp_pt += 4;
        } else {
            tmp_pt = NULL;
        }

        /* Check for negate values */
        neg = 0;
        ret_code = 0;
        if (*pattern == '!') {
            pattern++;
            neg = 1;
        }

        /* Do the actual comparison */
        if (strncasecmp(pattern, "=:", 2) == 0) {
            pattern += 2;
            if (strcasecmp(pattern, str) == 0) {
                ret_code = 1;
            }
        } else if (strncasecmp(pattern, "r:", 2) == 0) {
            pattern += 2;
            if (OS_Regex(pattern, str)) {
                ret_code = 1;
            }
        } else if (strncasecmp(pattern, "<:", 2) == 0) {
            pattern += 2;
            if (strcmp(pattern, str) < 0) {
                ret_code = 1;
            }
        } else if (strncasecmp(pattern, ">:", 2) == 0) {
            pattern += 2;
            if (strcmp(pattern, str) > 0) {
                ret_code = 1;
            }
        } else {
#ifdef WIN32
            char final_file[2048 + 1];

            /* Try to get Windows variable */
            if (*pattern == '%') {
                final_file[0] = '\0';
                final_file[2048] = '\0';

                ExpandEnvironmentStrings(pattern, final_file, 2047);
            } else {
                strncpy(final_file, pattern, 2047);
            }

            /* Compare against the expanded variable */
            if (strcasecmp(final_file, str) == 0) {
                ret_code = 1;
            }
#else
            if (strcasecmp(pattern, str) == 0) {
                ret_code = 1;
            }
#endif
        }
        /* Fix tmp_ret entry */
        if (tmp_ret != NULL) {
            *tmp_ret = ' ';
            tmp_ret = NULL;
        }

        /* If we have "!", return true if we don't match */
        if (neg == 1) {
            if (ret_code) {
                ret_code = 0;
                break;
            }
        } else {
            if (!ret_code) {
                ret_code = 0;
                break;
            }
        }

        ret_code = 1;
        pattern = tmp_pt;
    }

    return (ret_code);
}

static int wm_sca_check_dir(const char *dir, const char *file, char *pattern)
{
    int ret_code = 0;
    char f_name[PATH_MAX + 2];
    struct dirent *entry;
    struct stat statbuf_local;
    DIR *dp = NULL;

    f_name[PATH_MAX + 1] = '\0';

    dp = opendir(dir);
    if (!dp) {
        return (0);
    }

    while ((entry = readdir(dp)) != NULL) {
        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) ||
                (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        /* Create new file + path string */
        snprintf(f_name, PATH_MAX + 1, "%s/%s", dir, entry->d_name);

        /* Check if the read entry matches the provided file name */
        if (strncasecmp(file, "r:", 2) == 0) {
            if (OS_Regex(file + 2, entry->d_name)) {
                if (wm_sca_check_file(f_name, pattern)) {
                    ret_code = 1;
                }
            }
        } else {
            /* ... otherwise try without regex */
            if (OS_Match2(file, entry->d_name)) {
                if (wm_sca_check_file(f_name, pattern)) {
                    ret_code = 1;
                }
            }
        }

        /* Check if file is a directory */
        if (lstat(f_name, &statbuf_local) == 0) {
            if (S_ISDIR(statbuf_local.st_mode)) {
                if (wm_sca_check_dir(f_name, file, pattern)) {
                    ret_code = 1;
                }
            }
        }
    }

    closedir(dp);
    return (ret_code);

}

/* Check if a process is running */
static int wm_sca_is_process(char *value, OSList *p_list)
{
    OSListNode *l_node;
    if (p_list == NULL) {
        return (0);
    }
    if (!value) {
        return (0);
    }

    l_node = OSList_GetFirstNode(p_list);
    while (l_node) {
        W_Proc_Info *pinfo;

        pinfo = (W_Proc_Info *)l_node->data;

        /* Check if value matches */
        if (wm_sca_pt_matches(pinfo->p_path, value)) {
            return (1);
        }

        l_node = OSList_GetNextNode(p_list);
    }

    return (0);
}

// Destroy data
void wm_sca_destroy(wm_sca_t * data) {
    os_free(data);
}

#ifdef WIN32

static int wm_check_registry_entry(char * const value)
{
    /* Look for additional entries in the registry and a pattern to match. */
    char *entry = wm_sca_get_pattern(value);
    char *pattern = entry ? wm_sca_get_pattern(entry) : NULL;

    mdebug1("Checking registry: '%s\\%s'...", value, entry);

    const int ret = wm_sca_is_registry(value, entry, pattern);
    if (ret == 1) {
        mdebug2("registry found.");
        return 1;
    } else if (ret == -1) {
        mdebug2("registry not found.");
    }

    return 0;
}

static int wm_sca_is_registry(char *entry_name, char *reg_option, char *reg_value) {
    char *rk;
    rk = wm_sca_os_winreg_getkey(entry_name);
    if (wm_sca_sub_tree == NULL || rk == NULL) {
        merror(SK_INV_REG, entry_name);
        return (0);
    }

    int test_results_32 = 0;
    int test_results_64 = 0;

    // most likely to find it in the 64bit registry nowadays. Comes first to leverage short-circuit evaluation.
    
    const int found = wm_sca_test_key(rk, entry_name, KEY_WOW64_64KEY, reg_option, reg_value, &test_results_64)
                   || wm_sca_test_key(rk, entry_name, KEY_WOW64_32KEY, reg_option, reg_value, &test_results_32);
    const int test_results = test_results_32 || test_results_64;
    mdebug2("Reading registry 32/64b key %s\\%s -> %s) -> found?: %d, test results: %d", entry_name, reg_option, reg_value, found, test_results);

    // unable to open the entry (not found) -> ret -1
    return found ? test_results : -1;
}

static char *wm_sca_os_winreg_getkey(char *reg_entry)
{
    char *ret = NULL;
    char *tmp_str;

    /* Get only the sub tree first */
    tmp_str = strchr(reg_entry, '\\');
    if (tmp_str) {
        *tmp_str = '\0';
        ret = tmp_str + 1;
    }

    /* Set sub tree */
    if ((strcmp(reg_entry, "HKEY_LOCAL_MACHINE") == 0) ||
            (strcmp(reg_entry, "HKLM") == 0)) {
        wm_sca_sub_tree = HKEY_LOCAL_MACHINE;
    } else if (strcmp(reg_entry, "HKEY_CLASSES_ROOT") == 0) {
        wm_sca_sub_tree = HKEY_CLASSES_ROOT;
    } else if (strcmp(reg_entry, "HKEY_CURRENT_CONFIG") == 0) {
        wm_sca_sub_tree = HKEY_CURRENT_CONFIG;
    } else if (strcmp(reg_entry, "HKEY_USERS") == 0) {
        wm_sca_sub_tree = HKEY_USERS;
    } else if ((strcmp(reg_entry, "HKCU") == 0) ||
               (strcmp(reg_entry, "HKEY_CURRENT_USER") == 0)) {
        wm_sca_sub_tree = HKEY_CURRENT_USER;
    } else {
        /* Set sub tree to null */
        wm_sca_sub_tree = NULL;

        /* Return tmp_str to the previous value */
        if (tmp_str && (*tmp_str == '\0')) {
            *tmp_str = '\\';
        }
        return (NULL);
    }

    /* Check if ret has nothing else */
    if (ret && (*ret == '\0')) {
        ret = NULL;
    }

    /* Fixing tmp_str and the real name of the registry */
    if (tmp_str && (*tmp_str == '\0')) {
        *tmp_str = '\\';
    }

    return (ret);
}

static int wm_sca_test_key(char *subkey, char *full_key_name, unsigned long arch,
                         char *reg_option, char *reg_value, int * test_result)
{
    HKEY oshkey;
    LSTATUS err = RegOpenKeyEx(wm_sca_sub_tree, subkey, 0, KEY_READ | arch, &oshkey);
    if (err != ERROR_SUCCESS) {
        char error_msg[OS_SIZE_1024 + 1];
        error_msg[OS_SIZE_1024] = '\0';
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
                    | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                    NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPTSTR) &error_msg, OS_SIZE_1024, NULL);

        mdebug2("Unable to read  %s: %s", full_key_name, error_msg);
        /* If the key does not exists, testings should also fail */
        *test_result = 0;
        return 0;
    }
    
    /* If the key does exists, a test for existance succeeds  */
    *test_result = 1;
    
    /* If option is set, set test_result as the value of query key */
    if (reg_option) {
        *test_result = wm_sca_winreg_querykey(oshkey, subkey, full_key_name, reg_option, reg_value);
    }

    RegCloseKey(oshkey);
    return 1;
}

static int wm_sca_winreg_querykey(HKEY hKey,
        __attribute__((unused))char *p_key,
        __attribute__((unused)) char *full_key_name,
                         char *reg_option, char *reg_value)
{
    int rc;
    DWORD i, j;

    /* QueryInfo and EnumKey variables */
    TCHAR class_name_b[MAX_PATH + 1];
    DWORD class_name_s = MAX_PATH;

    /* Number of sub keys */
    DWORD subkey_count = 0;

    /* Number of values */
    DWORD value_count;

    /* Variables for RegEnumValue */
    TCHAR value_buffer[MAX_VALUE_NAME + 1];
    TCHAR data_buffer[MAX_VALUE_NAME + 1];
    DWORD value_size;
    DWORD data_size;

    /* Data type for RegEnumValue */
    DWORD data_type = 0;

    /* Storage var */
    char var_storage[MAX_VALUE_NAME + 1];

    /* Initialize the memory for some variables */
    class_name_b[0] = '\0';
    class_name_b[MAX_PATH] = '\0';

    /* We use the class_name, subkey_count and the value count */
    rc = RegQueryInfoKey(hKey, class_name_b, &class_name_s, NULL,
                         &subkey_count, NULL, NULL, &value_count,
                         NULL, NULL, NULL, NULL);
    if (rc != ERROR_SUCCESS) {
        return (0);
    }

    /* Get values (if available) */
    if (value_count) {
        char *mt_data;

        /* Clear the values for value_size and data_size */
        value_buffer[MAX_VALUE_NAME] = '\0';
        data_buffer[MAX_VALUE_NAME] = '\0';
        var_storage[MAX_VALUE_NAME] = '\0';

        /* Get each value */
        for (i = 0; i < value_count; i++) {
            value_size = MAX_VALUE_NAME;
            data_size = MAX_VALUE_NAME;

            value_buffer[0] = '\0';
            data_buffer[0] = '\0';
            var_storage[0] = '\0';

            rc = RegEnumValue(hKey, i, value_buffer, &value_size,
                              NULL, &data_type, (LPBYTE)data_buffer, &data_size);

            /* No more values available */
            if (rc != ERROR_SUCCESS) {
                break;
            }

            /* Check if no value name is specified */
            if (value_buffer[0] == '\0') {
                value_buffer[0] = '@';
                value_buffer[1] = '\0';
            }

            /* Check if the entry name matches the reg_option */
            if (strcasecmp(value_buffer, reg_option) != 0) {
                continue;
            }

            /* If a value is not present and the option matches,
             * we can return ok
             */
            if (!reg_value) {
                return (1);
            }

            /* Write value into a string */
            switch (data_type) {
                    int size_available;

                case REG_SZ:
                case REG_EXPAND_SZ:
                    snprintf(var_storage, MAX_VALUE_NAME, "%s", data_buffer);
                    break;
                case REG_MULTI_SZ:
                    /* Printing multiple strings */
                    size_available = MAX_VALUE_NAME - 3;
                    mt_data = data_buffer;

                    while (*mt_data) {
                        if (size_available > 2) {
                            strncat(var_storage, mt_data, size_available);
                            strncat(var_storage, " ", 2);
                            size_available = MAX_VALUE_NAME -
                                             (strlen(var_storage) + 2);
                        }
                        mt_data += strlen(mt_data) + 1;
                    }

                    break;
                case REG_DWORD:
                    snprintf(var_storage, MAX_VALUE_NAME,
                             "%x", (unsigned int)*data_buffer);
                    break;
                default:
                    size_available = MAX_VALUE_NAME - 2;
                    for (j = 0; j < data_size; j++) {
                        char tmp_c[12];

                        snprintf(tmp_c, 12, "%02x",
                                 (unsigned int)data_buffer[j]);

                        if (size_available > 2) {
                            strncat(var_storage, tmp_c, size_available);
                            size_available = MAX_VALUE_NAME -
                                             (strlen(var_storage) + 2);
                        }
                    }
                    break;
            }

            /* Check if value matches */
            if (wm_sca_pt_matches(var_storage, reg_value)) {
                return (1);
            }

            return (0);
        }
    }

    return (0);
}

static char *wm_sca_getrootdir(char *root_dir, int dir_size)
{
    char final_file[2048 + 1];
    char *tmp;

    final_file[0] = '\0';
    final_file[2048] = '\0';

    ExpandEnvironmentStrings("%WINDIR%", final_file, 2047);

    tmp = strchr(final_file, '\\');
    if (tmp) {
        *tmp = '\0';
        strncpy(root_dir, final_file, dir_size);
        return (root_dir);
    }

    return (NULL);
}
#endif

static int wm_sca_send_summary(wm_sca_t * data, int scan_id,unsigned int passed, unsigned int failed,cJSON *policy,int start_time,int end_time,char * integrity_hash, int first_scan,int id) {
    cJSON *json_summary = cJSON_CreateObject();

    cJSON_AddStringToObject(json_summary, "type", "summary");
    cJSON_AddNumberToObject(json_summary, "scan_id", scan_id);

    /* Policy fields */
    cJSON *name = cJSON_GetObjectItem(policy,"name");
    cJSON *description = cJSON_GetObjectItem(policy,"description");
    cJSON *references = cJSON_GetObjectItem(policy,"references");
    cJSON *policy_id = cJSON_GetObjectItem(policy,"id");
    cJSON *file= cJSON_GetObjectItem(policy,"file");

    cJSON_AddStringToObject(json_summary, "name", name->valuestring);
    cJSON_AddStringToObject(json_summary, "policy_id", policy_id->valuestring);
    cJSON_AddStringToObject(json_summary, "file", file->valuestring);

    if(description) {
        cJSON_AddStringToObject(json_summary, "description", description->valuestring);
    }

    if(references) {
        cJSON *reference;
        char *ref = NULL;

        cJSON_ArrayForEach(reference,references)
        {
            if(reference->valuestring){
               wm_strcat(&ref,reference->valuestring,',');
            }
        }
        cJSON_AddStringToObject(json_summary, "references", ref ? ref : NULL );
        os_free(ref);
    }

    cJSON_AddNumberToObject(json_summary, "passed", passed);
    cJSON_AddNumberToObject(json_summary, "failed", failed);

    float passedf = passed;
    float failedf = failed;
    float score = ((passedf/(failedf+passedf)))* 100;

    cJSON_AddNumberToObject(json_summary, "score", score);

    cJSON_AddNumberToObject(json_summary, "start_time", start_time);
    cJSON_AddNumberToObject(json_summary, "end_time", end_time);

    if(integrity_hash) {
        cJSON_AddStringToObject(json_summary, "hash", integrity_hash);
    } else {
        cJSON_AddStringToObject(json_summary, "hash", "error_calculating_hash");
    }

    if (first_scan) {
        cJSON_AddNumberToObject(json_summary, "first_scan", first_scan);
    }

    mdebug1("Sending summary event for file: '%s", file->valuestring);

    if (last_summary_json[id]) {
        os_free(last_summary_json[id]);
    }

    last_summary_json[id] = cJSON_Duplicate(json_summary,1);
    wm_sca_send_alert(data,json_summary);
    cJSON_Delete(json_summary);

    return 0;
}

static int wm_sca_send_event_check(wm_sca_t * data,cJSON *event) {

    wm_sca_send_alert(data,event);

    return 0;
}

static cJSON *wm_sca_build_event(cJSON *profile,cJSON *policy,char **p_alert_msg,int id,char *result) {
    cJSON *json_alert = cJSON_CreateObject();
    cJSON_AddStringToObject(json_alert, "type", "check");
    cJSON_AddNumberToObject(json_alert, "id", id);

    cJSON *name = cJSON_GetObjectItem(policy,"name");
    cJSON *policy_id = cJSON_GetObjectItem(policy,"id");
    cJSON_AddStringToObject(json_alert, "policy", name->valuestring);

    cJSON *check = cJSON_CreateObject();
    cJSON *pm_id = cJSON_GetObjectItem(profile, "id");
    cJSON *title = cJSON_GetObjectItem(profile, "title");
    cJSON *description = cJSON_GetObjectItem(profile, "description");
    cJSON *rationale = cJSON_GetObjectItem(profile, "rationale");
    cJSON *remediation = cJSON_GetObjectItem(profile, "remediation");
    cJSON *rules = cJSON_GetObjectItem(profile, "rules");

    if(!pm_id) {
        mdebug1("No 'id' field found on check.");
        goto error;
    }

    if(!pm_id->valueint) {
        mdebug1("Field 'id' must be a number.");
        goto error;
    }

    cJSON_AddNumberToObject(check, "id", pm_id->valueint);

    if(title){
        if(!title->valuestring) {
            mdebug1("Field 'title' must be a string.");
            goto error;
        }
        cJSON_AddStringToObject(check, "title", title->valuestring);
    } else {
        mdebug1("No 'title' field found on check '%d'.",pm_id->valueint);
        goto error;
    }

    if(!policy_id){
        mdebug1("No 'id' field found on policy.");
        goto error;
    }

    if(description){
        if(!description->valuestring) {
            mdebug1("Field 'description' must be a string.");
            goto error;
        }
        cJSON_AddStringToObject(check, "description", description->valuestring);
    }

    if(rationale){
        if(!rationale->valuestring) {
            mdebug1("Field 'rationale' must be a string.");
            goto error;
        }
        cJSON_AddStringToObject(check, "rationale", rationale->valuestring);
    }

    if(remediation){
        if(!remediation->valuestring) {
            mdebug1("Field 'remediation' must be a string.");
            goto error;
        }
        cJSON_AddStringToObject(check, "remediation", remediation->valuestring);
    }

    cJSON *compliances = cJSON_GetObjectItem(profile, "compliance");

    if(compliances) {
        cJSON *add_compliances = cJSON_CreateObject();
        cJSON *compliance;

        cJSON_ArrayForEach(compliance,compliances)
        {
            if(compliance->child->valuestring){
                cJSON_AddStringToObject(add_compliances,compliance->child->string,compliance->child->valuestring);
            } else if(compliance->child->valuedouble) {
                char double_value[128] = {0};
                snprintf(double_value,128,"%g",compliance->child->valuedouble);

                cJSON_AddStringToObject(add_compliances,compliance->child->string,double_value);
            } else if(compliance->child->valueint) {
                cJSON_AddNumberToObject(add_compliances,compliance->child->string,compliance->child->valueint);
            }
        }

        cJSON_AddItemToObject(check,"compliance",add_compliances);
    }

    cJSON_AddItemToObject(check,"rules", cJSON_Duplicate(rules,1));

    cJSON *references = cJSON_GetObjectItem(profile, "references");

    if(references) {
        cJSON *reference;
        char *ref = NULL;

        cJSON_ArrayForEach(reference,references)
        {
            if(reference->valuestring){
               wm_strcat(&ref,reference->valuestring,',');
            }
        }
        cJSON_AddStringToObject(check, "references", ref ? ref : NULL );
        os_free(ref);
    }

    // Get File or Process from alert
    int i = 0;
    char * final_str_file = NULL;
    char * final_str_directory = NULL;
    char * final_str_process = NULL;
    char * final_str_registry = NULL;
    char * final_str_command = NULL;
    while(i < 255) {

        if(p_alert_msg[i]) {
            char *alert_file = strstr(p_alert_msg[i],"File:");
            char *alert_directory = strstr(p_alert_msg[i],"Directory:");

            if(alert_file){
                alert_file+= 5;
                *alert_file = '\0';
                alert_file++;
                wm_strcat(&final_str_file,alert_file,',');
            } else if (alert_directory){
                alert_directory+= 10;
                *alert_directory = '\0';
                alert_directory++;
                wm_strcat(&final_str_directory,alert_directory,',');
            } else {
                char *alert_process = strstr(p_alert_msg[i],"Process:");
                if(alert_process){
                    alert_process+= 8;
                    *alert_process = '\0';
                    alert_process++;
                    wm_strcat(&final_str_process,alert_process,',');
                } else {
                    char *alert_registry = strstr(p_alert_msg[i],"Registry:");
                    if(alert_registry){
                        alert_registry+= 9;
                        *alert_registry = '\0';
                        alert_registry++;
                        wm_strcat(&final_str_registry,alert_registry,',');
                    } else {
                        char *alert_command = strstr(p_alert_msg[i],"Command:");
                        if(alert_command) {
                            alert_command+= 8;
                            *alert_command = '\0';
                            alert_command++;
                            wm_strcat(&final_str_command,alert_command,',');
                        }
                    }
                }
            }
        } else {
            break;
        }
        i++;
    }

    if(final_str_file) {
        cJSON_AddStringToObject(check, "file", final_str_file);
        os_free(final_str_file);
    }

    if(final_str_directory) {
        cJSON_AddStringToObject(check, "directory", final_str_directory);
        os_free(final_str_directory);
    }

    if(final_str_process) {
       cJSON_AddStringToObject(check, "process", final_str_process);
       os_free(final_str_process);
    }

    if(final_str_registry) {
       cJSON_AddStringToObject(check, "registry", final_str_registry);
       os_free(final_str_registry);
    }

    if(final_str_command) {
       cJSON_AddStringToObject(check, "command", final_str_command);
       os_free(final_str_command);
    }

    cJSON_AddStringToObject(check, "result", result);

    if(!policy_id->valuestring) {
        mdebug1("Field 'id' must be a string");
        goto error;
    }

    cJSON_AddStringToObject(json_alert, "policy_id", policy_id->valuestring);
    cJSON_AddItemToObject(json_alert,"check",check);

    return json_alert;

error:

    if(json_alert){
        cJSON_Delete(json_alert);
    }

    return NULL;
}

static int wm_sca_check_hash(OSHash *cis_db_hash,char *result,cJSON *profile,cJSON *event, int check_index,int policy_index) {
    cis_db_info_t *hashed_result = NULL;
    char id_hashed[OS_SIZE_128];
    int ret_add = 0;
    cJSON *pm_id = cJSON_GetObjectItem(profile, "id");

    if(!pm_id) {
        return 0;
    }

    if(!pm_id->valueint) {
        return 0;
    }

    sprintf(id_hashed, "%d", pm_id->valueint);

    hashed_result = OSHash_Get(cis_db_hash,id_hashed);

    if(hashed_result){
        if(strcmp(result,hashed_result->result) == 0) {
            return 0;
        } else {
            cis_db_info_t *elem;

            os_calloc(1,sizeof(cis_db_info_t),elem);
            os_strdup(result,elem->result);

            cJSON *obj = cJSON_Duplicate(event,1);
            elem->event = NULL;

            if(obj) {
                elem->event = obj;
                if (ret_add = OSHash_Update(cis_db_hash,id_hashed,elem), ret_add != 1) {
                    merror("Unable to update hash table for check: %d", pm_id->valueint);
                    os_free(elem->result);
                    cJSON_Delete(elem->event);
                    os_free(elem);
                    return 0;
                }

                cis_db_for_hash[policy_index].elem[check_index] = elem;
                return 1;
            }

            os_free(elem->result);
            os_free(elem);
            return 0;
        }
    } else {
        cis_db_info_t *elem;

        os_calloc(1,sizeof(cis_db_info_t),elem);
        os_strdup(result,elem->result);

        cJSON *obj = cJSON_Duplicate(event,1);
        elem->event = NULL;

        if(obj) {
            elem->event = obj;
            if (ret_add = OSHash_Add(cis_db_hash,id_hashed,elem), ret_add != 2) {
                merror("Unable to update hash table for check: %d", pm_id->valueint);
                os_free(elem->result);
                cJSON_Delete(elem->event);
                os_free(elem);
                return 0;
            }
            cis_db_for_hash[policy_index].elem[check_index] = elem;
            return 1;
        }
        os_free(elem->result);
        os_free(elem);
        return 0;
    }
}

static void wm_sca_free_hash_data(cis_db_info_t *event) {

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

static char *wm_sca_hash_integrity(int policy_index) {
    char *str = NULL;

    int i;
    for(i = 0; cis_db_for_hash[policy_index].elem[i]; i++) {
        cis_db_info_t *event;
        event = cis_db_for_hash[policy_index].elem[i];

        if(event->result){
            wm_strcat(&str,event->result,':');
        }
    }

    if(str) {
        os_sha256 hash;
        OS_SHA256_String(str, hash);
        os_free(str);
        return strdup(hash);
    }

    return NULL;
}

static void *wm_sca_dump_db_thread(wm_sca_t * data) {
    int i;

    while(1) {
        request_dump_t *request;

        if (request = queue_pop_ex(request_queue), request) {

#ifndef WIN32
            int random = os_random();
            if (random < 0)
                random = -random;
#else
            unsigned int random1 = os_random();
            unsigned int random2 = os_random();

            char random_id[OS_MAXSTR];
            snprintf(random_id, OS_MAXSTR - 1, "%u%u", random1, random2);

            int random = atoi(random_id);
            if (random < 0)
                random = -random;
#endif
            random = random % data->request_db_interval;

            if(random == 0) {
                random += 5;
            }

            unsigned int time = random;

            if (request->first_scan) {
                wm_delay(2000);
                mdebug1("Sending first scan results for policy '%s'.", data->profile[request->policy_index]->profile);
            } else {
                minfo("Integration checksum failed for policy '%s'. Resending scan results in %d seconds.", data->profile[request->policy_index]->profile,random);
                wm_delay(1000 * time);
                mdebug1("Dumping results to SCA DB for policy index '%u'",request->policy_index);
            }
          
            int scan_id = -1;

            for(i = 0; cis_db_for_hash[request->policy_index].elem[i]; i++) {
                cis_db_info_t *event;
                event = cis_db_for_hash[request->policy_index].elem[i];

                if (event) {
                    if(event->event){
                        cJSON *db_obj;
                        db_obj = event->event;

                        if(scan_id == -1) {
                            cJSON * scan_id_obj = cJSON_GetObjectItem(db_obj, "id");

                            if(scan_id_obj) {
                                scan_id =  scan_id_obj->valueint;
                            }
                        }
                        wm_sca_send_event_check(data,db_obj);
                    }
                }
            }

            sleep(5);
           
            int elements_sent = i - 1;
            mdebug1("Sending end of dump control event");

            wm_sca_send_dump_end(data,elements_sent,data->profile[request->policy_index]->policy_id,scan_id);

            wm_delay(2000);

            /* Send summary only for first scan */
            if (request->first_scan) {
                /* Send summary */
                cJSON_DeleteItemFromObject(last_summary_json[request->policy_index],"first_scan");
                /* Force alert */
                cJSON_AddStringToObject(last_summary_json[request->policy_index], "force_alert", "1");

                wm_sca_send_alert(data,last_summary_json[request->policy_index]);
            }

            mdebug1("Finished dumping scan results to SCA DB for policy index '%u'",request->policy_index);
            os_free(request);
        }
    }

    return NULL;
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

#ifdef WIN32
void wm_sca_push_request_win(char * msg){
    char *db = strchr(msg,':');

    if(!strncmp(msg,WM_CONFIGURATION_ASSESSMENT_DB_DUMP,strlen(WM_CONFIGURATION_ASSESSMENT_DB_DUMP)) && db) {

        *db++ = '\0';

        /* Check for first scan */
        char *first_scan = strchr(db,':');

        if (!first_scan) {
            mdebug1("First scan flag missing");
            return;
        }

        *first_scan++ = '\0';

        /* Search DB */
        int i;

        if(data_win) {
            for(i = 0; data_win->profile[i]; i++) {
                if(!data_win->profile[i]->enabled){
                    continue;
                }

                if(data_win->profile[i]->policy_id) {
                    char *endl;

                    endl = strchr(db,'\n');

                    if(endl){
                        *endl = '\0';
                    }

                    if(strcmp(data_win->profile[i]->policy_id,db) == 0){
                        request_dump_t *request;
                        os_calloc(1, sizeof(request_dump_t),request);
                         
                        request->policy_index = i;
                        request->first_scan = atoi(first_scan);

                        if(queue_push_ex(request_queue,request) < 0) {
                            os_free(request);
                            mdebug1("Could not push policy index to queue");
                        }
                        break;
                    }
                }
            }
        }
    }
}

#endif

#ifndef WIN32
static void * wm_sca_request_thread(wm_sca_t * data) {

    /* Create request socket */
    int cfga_queue;
    if ((cfga_queue = StartMQ(CFGASSESSMENTQUEUEPATH, READ)) < 0) {
        merror_exit(QUEUE_ERROR, CFGASSESSMENTQUEUEPATH, strerror(errno));
    }

    int recv = 0;
    char *buffer = NULL;
    os_calloc(OS_MAXSTR + 1,sizeof(char),buffer);

    while (1) {
        if (recv = OS_RecvUnix(cfga_queue, OS_MAXSTR, buffer),recv) {
            buffer[recv] = '\0';

            char *db = strchr(buffer,':');

            if(!strncmp(buffer,WM_CONFIGURATION_ASSESSMENT_DB_DUMP,strlen(WM_CONFIGURATION_ASSESSMENT_DB_DUMP)) && db) {

                *db++ = '\0';

                /* Check for first scan */
                char *first_scan = strchr(db,':');

                if (!first_scan) {
                    mdebug1("First scan flag missing");
                    continue;
                }

                *first_scan++ = '\0';

                /* Search DB */
                int i;
                for(i = 0; data->profile[i]; i++) {
                    if(!data->profile[i]->enabled){
                        continue;
                    }

                    if(data->profile[i]->policy_id) {
                        char *endl;

                        endl = strchr(db,'\n');

                        if(endl){
                            *endl = '\0';
                        }

                        if(strcmp(data->profile[i]->policy_id,db) == 0){
                            request_dump_t *request;
                            os_calloc(1, sizeof(request_dump_t),request);
                         
                            request->policy_index = i;
                            request->first_scan = atoi(first_scan);

                            if(queue_push_ex(request_queue,request) < 0) {
                                os_free(request);
                                mdebug1("Could not push policy index to queue");
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    return NULL;
}
#endif
static void wm_sca_summary_increment_passed() {
    summary_passed++;
}

static void wm_sca_summary_increment_failed() {
    summary_failed++;
}

static void wm_sca_reset_summary() {
    summary_failed = 0;
    summary_passed = 0;
}

cJSON *wm_sca_dump(const wm_sca_t *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "scan_on_start", data->scan_on_start ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "skip_nfs", data->skip_nfs ? "yes" : "no");
    if (data->interval) cJSON_AddNumberToObject(wm_wd, "interval", data->interval);
    if (data->scan_day) cJSON_AddNumberToObject(wm_wd, "day", data->scan_day);

    switch (data->scan_wday) {
        case 0:
            cJSON_AddStringToObject(wm_wd, "wday", "sunday");
            break;
        case 1:
            cJSON_AddStringToObject(wm_wd, "wday", "monday");
            break;
        case 2:
            cJSON_AddStringToObject(wm_wd, "wday", "tuesday");
            break;
        case 3:
            cJSON_AddStringToObject(wm_wd, "wday", "wednesday");
            break;
        case 4:
            cJSON_AddStringToObject(wm_wd, "wday", "thursday");
            break;
        case 5:
            cJSON_AddStringToObject(wm_wd, "wday", "friday");
            break;
        case 6:
            cJSON_AddStringToObject(wm_wd, "wday", "saturday");
            break;
        default:
            break;
    }
    if (data->scan_time) cJSON_AddStringToObject(wm_wd, "time", data->scan_time);

    if (data->profile && *data->profile) {
        cJSON *profiles = cJSON_CreateArray();
        int i;
        for (i=0;data->profile[i];i++) {
            if(data->profile[i]->enabled == 1){
                cJSON_AddStringToObject(profiles,"policy",data->profile[i]->profile);
            }
        }
        cJSON_AddItemToObject(wm_wd,"policies",profiles);
    }

    cJSON_AddItemToObject(root,"sca",wm_wd);


    return root;
}

static int append_msg_to_vm_scat (wm_sca_t * const data, const char * const msg)
{
    /* Already present */
    if (w_is_str_in_array(data->alert_msg, msg)) {
        return 1;
    }

    int i = 0;
    while (data->alert_msg[i] && (i < 255)) {
        i++;
    }

    if (!data->alert_msg[i]) {
        os_strdup(msg, data->alert_msg[i]);
    }
    return 0;
}
