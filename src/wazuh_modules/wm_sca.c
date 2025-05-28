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

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static
#endif

typedef struct request_dump_t {
    int policy_index;
    int first_scan;
} request_dump_t;

#ifdef WIN32
static HKEY wm_sca_sub_tree;
#endif

static const int RETURN_NOT_FOUND = 0;
static const int RETURN_FOUND = 1;
static const int RETURN_INVALID = 2;

#ifdef WIN32
static DWORD WINAPI wm_sca_main(void *arg);         // Module main function. It won't return
#else
static void * wm_sca_main(wm_sca_t * data);   // Module main function. It won't return
#endif
static void wm_sca_destroy(wm_sca_t * data);  // Destroy data
static int wm_sca_start(wm_sca_t * data);  // Start
static cJSON *wm_sca_build_event(const cJSON * const check, const cJSON * const policy, char **p_alert_msg, int id, const char * const result, const char * const reason);
static int wm_sca_send_event_check(wm_sca_t * data,cJSON *event);  // Send check event
static void wm_sca_read_files(wm_sca_t * data);  // Read policy monitoring files
static int wm_sca_do_scan(cJSON *checks, OSStore *vars, wm_sca_t * data, int id, cJSON *policy, int requirements_scan, int cis_db_index, unsigned int remote_policy, int first_scan, int *checks_number, char ** sorted_variables, char * policy_engine);
static int wm_sca_send_summary(wm_sca_t * data, int scan_id,unsigned int passed, unsigned int failed,unsigned int invalid,cJSON *policy,int start_time,int end_time, char * integrity_hash, char * integrity_hash_file, int first_scan, int id, int checks_number);
static int wm_sca_check_policy(const cJSON * const policy, const cJSON * const checks, OSHash *global_check_list);
static int wm_sca_check_requirements(const cJSON * const requirements);
static void wm_sca_summary_increment_passed();
static void wm_sca_summary_increment_failed();
static void wm_sca_summary_increment_invalid();
static void wm_sca_reset_summary();
static int wm_sca_send_alert(wm_sca_t * data,cJSON *json_alert); // Send alert
static int wm_sca_check_hash(OSHash *cis_db_hash, const char * const result, const cJSON * const check, const cJSON * const event, int check_index, int policy_index);
static char *wm_sca_hash_integrity(int policy_index);
static void wm_sca_free_hash_data(cis_db_info_t *event);
#ifdef WIN32
static DWORD WINAPI wm_sca_dump_db_thread(wm_sca_t * data);
#else
static void * wm_sca_dump_db_thread(wm_sca_t * data);
#endif
static void wm_sca_send_policies_scanned(wm_sca_t * data);
static int wm_sca_send_dump_end(wm_sca_t * data, unsigned int elements_sent,char * policy_id,int scan_id);  // Send dump end event
static int append_msg_to_vm_scat (wm_sca_t * const data, const char * const msg);
static int compare_cis_db_info_t_entry(const void * const a, const void * const  b);

#ifndef WIN32
static void * wm_sca_request_thread(wm_sca_t * data);
#endif

/* Extra functions */
static int wm_sca_get_vars(const cJSON * const variables, OSStore * const vars);
static void wm_sca_set_condition(const char * const c_cond, int *condition);
static char * wm_sca_get_value(char *buf, int *type);
static char * wm_sca_get_pattern(char *value);
static int wm_sca_check_file_contents(const char * const file, const char * const pattern, char ** reason, w_expression_t * regex_engine);
static int wm_sca_check_file_list_for_contents(const char * const file_list, char * const pattern, char ** reason, w_expression_t * regex_engine);
static int wm_sca_check_file_existence(const char * const file, char ** reason);
static int wm_sca_check_file_list_for_existence(const char * const file_list, char ** reason);
static int wm_sca_check_file_list(const char * const file_list, char * const pattern, char ** reason, w_expression_t * regex_engine);
static int wm_sca_read_command(char *command, char * pattern, wm_sca_t * data, char ** reason, w_expression_t * regex_engine);
static int wm_sca_test_positive_minterm(char * const minterm, const char * const str, char ** reason, w_expression_t * regex_engine);
static int wm_sca_pattern_matches(const char * const str, const char * const pattern, char ** reason, w_expression_t * regex_engine); // Check pattern match
static int wm_sca_check_dir(const char * const dir, const char * const file, char * const pattern, char ** reason, w_expression_t * regex_engine);
static int wm_sca_check_dir_existence(const char * const dir, char ** reason);
static int wm_sca_check_dir_list(wm_sca_t * const data, char * const dir_list, char * const file, char * const pattern, char ** reason, w_expression_t * regex_engine);
static int wm_sca_check_process_is_running(OSList *p_list, char * value, char ** reason, w_expression_t * regex_engine);
#ifndef WIN32
static int wm_sca_resolve_symlink(const char * const file, char * realpath_buffer, char **reason);
#endif
static int wm_sca_apply_numeric_partial_comparison(const char * const partial_comparison, const long int number, char **reason, w_expression_t * regex_engine);
static int wm_sca_regex_numeric_comparison (const char * const pattern, const char *const str, char ** reason, w_expression_t * regex_engine);

#ifdef WIN32
static int wm_sca_is_registry(char * entry_name, char * reg_option, char * reg_value, char ** reason, w_expression_t * regex_engine);
static char *wm_sca_os_winreg_getkey(char * reg_entry);
static int wm_sca_test_key(char * subkey, char * full_key_name, unsigned long arch, char * reg_option, char * reg_value, char ** reason, w_expression_t * regex_engine);
static int wm_sca_winreg_querykey(HKEY hKey, const char * full_key_name, char * reg_option, char * reg_value, char ** reason, w_expression_t * regex_engine);
#endif

cJSON *wm_sca_dump(const wm_sca_t * data);     // Read config

const wm_context WM_SCA_CONTEXT = {
    .name = SCA_WM_NAME,
    .start = (wm_routine)wm_sca_main,
    .destroy = (void(*)(void *))wm_sca_destroy,
    .dump = (cJSON * (*)(const void *))wm_sca_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

static unsigned int summary_passed = 0;
static unsigned int summary_failed = 0;
static unsigned int summary_invalid = 0;

static OSHash **cis_db;
static char **last_sha256;
static cis_db_hash_info_t *cis_db_for_hash;

static w_queue_t * request_queue;
static wm_sca_t * data_win;

cJSON **last_summary_json = NULL;

/* Multiple readers / one write mutex */
static pthread_rwlock_t dump_rwlock;

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

    if (!data->policies || data->policies[0] == NULL) {
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

    data->request_db_interval = getDefine_Int("sca","request_db_interval", 1, 60) * 60;
    data->commands_timeout = getDefine_Int("sca", "commands_timeout", 1, 300);
#ifdef CLIENT
    data->remote_commands = getDefine_Int("sca", "remote_commands", 0, 1);
#else
    data->remote_commands = 1;  // Only for agents
#endif

    /* Maximum request interval is the scan interval */
    if(data->request_db_interval > data->scan_config.interval) {
       data->request_db_interval = data->scan_config.interval;
       minfo("The request_db_interval option cannot be higher than the scan interval. It will be redefined to that value.");
    }

    int i;
    for(i = 0; data->policies[i]; i++) {
        if(data->policies[i]->enabled){
            minfo("Loaded policy '%s'", data->policies[i]->policy_path);
        } else {
            minfo("Policy '%s' disabled by configuration.", data->policies[i]->policy_path);
        }
    }

    /* Create Hash for each policy file */
    for(i = 0; data->policies[i]; i++) {
        os_realloc(cis_db, (i + 2) * sizeof(OSHash *), cis_db);
        cis_db[i] = OSHash_Create();
        if (!cis_db[i]) {
            merror(LIST_ERROR);
            pthread_exit(NULL);
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

    /* Create summary hash for each policy file */
    for(i = 0; data->policies[i]; i++) {
        os_realloc(last_sha256, (i + 2) * sizeof(char *), last_sha256);
        os_calloc(1,sizeof(os_sha256),last_sha256[i]);
    }


#ifndef WIN32

    data->queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (data->queue < 0) {
        merror("Can't connect to queue.");
    }

#endif

    request_queue = queue_init(1024);

    w_rwlock_init(&dump_rwlock, NULL);

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

        if ((data->queue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0) {
            mwarn("Can't connect to queue.");
        } else {
            if(wm_sendmsg(data->msg_delay, data->queue, msg,WM_SCA_STAMP, SCA_MQ) < 0) {
                merror(QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
            }
        }
    }

    os_free(msg);

    return (0);
}

#ifdef WAZUH_UNIT_TESTING
__attribute__((weak))
#endif
static void wm_sca_send_policies_scanned(wm_sca_t * data) {
    cJSON *policies_obj = cJSON_CreateObject();
    cJSON *policies = cJSON_CreateArray();

    int i;
    if(data->policies) {
        for(i = 0; data->policies[i]; i++) {
            if(data->policies[i]->enabled) {
                cJSON_AddStringToObject(policies,"policy",data->policies[i]->policy_id);
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

static void wm_sca_read_files(wm_sca_t * data) {
    int checks_number = 0;
    static int first_scan = 1;

    /* Read every policy monitoring file */
    if(data->policies) {
        OSHash *check_list = OSHash_Create();
        int i;
        for(i = 0; data->policies[i]; i++) {
            if(!data->policies[i]->enabled){
                continue;
            }

            OSStore *vars = NULL;
            cJSON * object = NULL;
            cJSON *requirements_array = NULL;
            int cis_db_index = i;
            char **sorted_variables = NULL;

            FILE *fp = wfopen(data->policies[i]->policy_path, "r");

            if(!fp) {
                mwarn("Policy file not found: '%s'. Skipping it.", data->policies[i]->policy_path);
                goto next;
            }
            w_file_cloexec(fp);

            /* Yaml parsing */
            yaml_document_t document;

            if (yaml_parse_file(data->policies[i]->policy_path, &document)) {
                mwarn("Error found while parsing file: '%s'. Skipping it.", data->policies[i]->policy_path);
                goto next;
            }

            if (object = yaml2json(&document,1), !object) {
                mwarn("Error found while transforming yaml to json: '%s'. Skipping it.", data->policies[i]->policy_path);
                yaml_document_delete(&document);
                goto next;
            }

            yaml_document_delete(&document);

            cJSON *policy = cJSON_GetObjectItem(object, "policy");
            cJSON *variables_policy = cJSON_GetObjectItem(object, "variables");
            cJSON *checks = cJSON_GetObjectItem(object, "checks");
            requirements_array = cJSON_CreateArray();
            cJSON *requirements = cJSON_GetObjectItem(object, "requirements");
            cJSON_AddItemReferenceToArray(requirements_array, requirements);

            if (wm_sca_check_policy(policy, checks, check_list)) {
                mwarn("Error found while validating policy file: '%s'. Skipping it.", data->policies[i]->policy_path);
                goto next;
            }

            cJSON * policy_regex_type = cJSON_GetObjectItem(policy, "regex_type");

            if (!policy_regex_type) {
                data->policies[i]->policy_regex_type = OSREGEX_STR;
            } else {
                data->policies[i]->policy_regex_type = cJSON_GetStringValue(policy_regex_type);
            }

            if (requirements && wm_sca_check_requirements(requirements)) {
                mwarn("Error found while reading 'requirements' section of file: '%s'. Skipping it.", data->policies[i]->policy_path);
                goto next;
            }

            if (!data->policies[i]->policy_id) {
                cJSON *id = cJSON_GetObjectItem(policy, "id");
                os_strdup(id->valuestring,data->policies[i]->policy_id);
            }

            if (!checks) {
                mwarn("Error found while reading 'checks' section of file: '%s'. Skipping it.", data->policies[i]->policy_path);
                goto next;
            }

            vars = OSStore_Create();
            sorted_variables = wm_sort_variables(variables_policy);
            if (wm_sca_get_vars(variables_policy,vars) != 0) {
                mwarn("Error found while reading the 'variables' section of file: '%s'. Skipping it.", data->policies[i]->policy_path);
                goto next;
            }

            // Set unique ID for each scan
#ifndef WIN32
            int id = os_random();
            if (id < 0) {
                id = -id;
            }
#else
            char random_id[RANDOM_LENGTH];
            snprintf(random_id, RANDOM_LENGTH - 1, "%u%u", os_random(), os_random());
            int id = atoi(random_id);

            if (id < 0) {
                id = -id;
            }
#endif
            int requirements_satisfied = 0;

            if(!requirements) {
                requirements_satisfied = 1;
            }

            mdebug1("Calculating hash for policy file '%s'", data->policies[i]->policy_path);
            char * integrity_hash_file = wm_sca_hash_integrity_file(data->policies[i]->policy_path);

            /* Check if the file integrity has changed */
            if(last_sha256[cis_db_index]) {
                w_rwlock_rdlock(&dump_rwlock);
                if (strcmp(last_sha256[cis_db_index],"")) {

                    /* File hash changed, delete table */
                    if(integrity_hash_file && strcmp(integrity_hash_file,last_sha256[cis_db_index])) {
                        OSHash_Free(cis_db[cis_db_index]);
                        cis_db[cis_db_index] = OSHash_Create();

                        if (!cis_db[cis_db_index]) {
                            merror(LIST_ERROR);
                            w_rwlock_unlock(&dump_rwlock);
                            pthread_exit(NULL);
                        }

                        OSHash_SetFreeDataPointer(cis_db[cis_db_index], (void (*)(void *))wm_sca_free_hash_data);

                        os_free(cis_db_for_hash[cis_db_index].elem);
                        os_realloc(cis_db_for_hash[cis_db_index].elem, sizeof(cis_db_info_t *) * (2), cis_db_for_hash[cis_db_index].elem);
                        cis_db_for_hash[cis_db_index].elem[0] = NULL;
                        cis_db_for_hash[cis_db_index].elem[1] = NULL;
                    }
                }
                w_rwlock_unlock(&dump_rwlock);
            }

            if(requirements) {
                w_rwlock_rdlock(&dump_rwlock);
                if (wm_sca_do_scan(requirements_array, vars, data, id, policy, 1, cis_db_index, data->policies[i]->remote,first_scan, &checks_number, sorted_variables, data->policies[i]->policy_regex_type) == 0) {
                    requirements_satisfied = 1;
                }
                w_rwlock_unlock(&dump_rwlock);
            }

            if(requirements_satisfied) {
                w_rwlock_rdlock(&dump_rwlock);

                time_t time_start = 0;
                time_t time_end = 0;
                time_start = time(NULL);

                minfo("Starting evaluation of policy: '%s'", data->policies[i]->policy_path);

                if (wm_sca_do_scan(checks, vars, data, id, policy, 0, cis_db_index, data->policies[i]->remote, first_scan, &checks_number, sorted_variables, data->policies[i]->policy_regex_type) != 0) {
                    merror("Error while evaluating the policy '%s'", data->policies[i]->policy_path);
                }
                mdebug1("Calculating hash for scanned results.");
                char * integrity_hash = wm_sca_hash_integrity(cis_db_index);

                time_end = time(NULL);

                /* Send summary */
                if(integrity_hash && integrity_hash_file) {
                    w_time_delay(1000 * data->summary_delay);
                    wm_sca_send_summary(data,id,summary_passed,summary_failed,summary_invalid,policy,time_start,time_end,integrity_hash,integrity_hash_file,first_scan,cis_db_index,checks_number);
                    snprintf(last_sha256[cis_db_index] ,sizeof(os_sha256),"%s",integrity_hash_file);
                }

                os_free(integrity_hash);

                minfo("Evaluation finished for policy '%s'", data->policies[i]->policy_path);
                wm_sca_reset_summary();

                w_rwlock_unlock(&dump_rwlock);
            } else {
                cJSON *title = cJSON_GetObjectItem(requirements,"title");
                minfo("Skipping policy '%s': '%s'", data->policies[i]->policy_path, title->valuestring);
            }

            os_free(integrity_hash_file);

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

            free_strarray(sorted_variables);
        }
        first_scan = 0;
        OSHash_Clean(check_list, free);
    }
}

static int wm_sca_check_policy(const cJSON * const policy, const cJSON * const checks, OSHash *global_check_list)
{
    if(!policy) {
        return 1;
    }

    const cJSON * const id = cJSON_GetObjectItem(policy, "id");
    if(!id) {
        mwarn("Field 'id' not found in policy header.");
        return 1;
    }

    if(!id->valuestring){
        mwarn("Invalid format for field 'id'");
        return 1;
    }

    char *coincident_policy_file;
    if((coincident_policy_file = OSHash_Get(global_check_list,id->valuestring)), coincident_policy_file) {
        mwarn("Found duplicated policy ID: %s. File '%s' contains the same ID.", id->valuestring, coincident_policy_file);
        return 1;
    }

    const cJSON * const name = cJSON_GetObjectItem(policy, "name");
    if(!name) {
        mwarn("Field 'name' not found in policy header.");
        return 1;
    }

    if(!name->valuestring){
        mwarn("Invalid format for field 'name'");
        return 1;
    }

    const cJSON * const file = cJSON_GetObjectItem(policy, "file");
    if(!file) {
        mwarn("Field 'file' not found in policy header.");
        return 1;
    }

    if(!file->valuestring){
        mwarn("Invalid format for field 'file'");
        return 1;
    }

    const cJSON * const description = cJSON_GetObjectItem(policy, "description");
    if(!description) {
        mwarn("Field 'description' not found in policy header.");
        return 1;
    }

    const cJSON * const regex_type = cJSON_GetObjectItem(policy, "regex_type");
    if(!regex_type) {
        mdebug1("Field 'regex_type' not found in policy header. The OS_REGEX engine shall be used.");
    }

    if(!description->valuestring) {
        mwarn("Invalid format for field 'description'");
        return 1;
    }

    // Check for policy rules with duplicated IDs */
    if (!checks) {
        mwarn("Section 'checks' not found.");
        return 1;
    }

    int *read_id;
    os_calloc(1, sizeof(int), read_id);
    read_id[0] = 0;

    const cJSON *check;
    cJSON_ArrayForEach(check, checks) {
        const cJSON * const check_id = cJSON_GetObjectItem(check, "id");
        if (check_id == NULL) {
            mwarn("Check ID not found.");
            free(read_id);
            return 1;
        }

        if (check_id->valueint <= 0) {
            // Invalid ID
            mwarn("Invalid check ID: %d", check_id->valueint);
            free(read_id);
            return 1;
        }

        char *coincident_policy;
        char *key_id;
        size_t key_length = snprintf(NULL, 0, "%d", check_id->valueint);
        os_malloc(key_length + 1, key_id);
        snprintf(key_id, key_length + 1, "%d", check_id->valueint);

        if((coincident_policy = (char *)OSHash_Get(global_check_list, key_id)), coincident_policy){
            // Invalid ID
            mwarn("Found duplicated check ID: %d. First appearance at policy '%s'", check_id->valueint, coincident_policy);
            os_free(key_id);
            os_free(read_id);
            return 1;
        }
        os_free(key_id);

        int i;
        for (i = 0; read_id[i] != 0; i++) {
            if (check_id->valueint == read_id[i]) {
                // Duplicated ID
                mwarn("Found duplicated check ID: %d", check_id->valueint);
                free(read_id);
                return 1;
            }
        }

        os_realloc(read_id, sizeof(int) * (i + 2), read_id);
        read_id[i] = check_id->valueint;
        read_id[i + 1] = 0;

        const cJSON * const rules = cJSON_GetObjectItem(check, "rules");

        if (rules == NULL) {
            mwarn("Invalid check %d: no rules found.", check_id->valueint);
            free(read_id);
            return 1;
        }

        int rules_n = 0;
        const cJSON *rule;
        cJSON_ArrayForEach(rule, rules) {
            if (!rule->valuestring) {
                mwarn("Invalid check %d: Empty rule.", check_id->valueint);
                free(read_id);
                return 1;
            }

            char *valuestring_ref = rule->valuestring;
            valuestring_ref += 4 * (!strncmp(valuestring_ref, "NOT ", 4) || !strncmp(valuestring_ref, "not ", 4));

            switch (*valuestring_ref) {
#ifdef WIN32
                case 'r':
#endif
                case 'f':
                case 'd':
                case 'p':
                case 'c':
                    break;
                case '\0':
                    mwarn("Invalid check %d: Empty rule.", check_id->valueint);
                    free(read_id);
                    return 1;
                default:
                    mwarn("Invalid check %d: Invalid rule format.", check_id->valueint);
                    free(read_id);
                    return 1;
            }

            rules_n++;
            if (rules_n > 255) {
                free(read_id);
                mwarn("Invalid check %d: Maximum number of rules is 255.", check_id->valueint);
                return 1;
            }
        }

        if (rules_n == 0) {
            mwarn("Invalid check %d: no rules found.", check_id->valueint);
            free(read_id);
            return 1;
        }

    }

    char *policy_file = NULL;
    os_strdup(file->valuestring, policy_file);
    const int id_add_retval = OSHash_Add(global_check_list, id->valuestring, policy_file);
    if (id_add_retval == 0){
        os_free(policy_file);
        os_free(read_id);
        merror_exit("(1102): Could not acquire memory");
    }

    if (id_add_retval == 1){
        merror("Error validating duplicated ID. Policy %s in file %s is duplicated", id->valuestring, policy_file);
        os_free(policy_file);
        os_free(read_id);
        return 1;
    }

    int i;
    for (i = 0; read_id[i] != 0; ++i) {
        char *policy_id = NULL;
        os_strdup(id->valuestring, policy_id);
        const int check_add_retval = OSHash_Numeric_Add_ex(global_check_list, read_id[i], policy_id);
        if (check_add_retval == 0){
            os_free(policy_id);
            os_free(read_id);
            merror_exit("(1102): Could not acquire memory");
        }

        if (check_add_retval == 1){
            merror("Error validating duplicated ID. Check %s in policy %s is duplicated", id->valuestring, policy_id);
            os_free(policy_id);
            os_free(read_id);
            return 1;
        }
    }

    os_free(read_id);
    return 0;
}

static int wm_sca_check_requirements(const cJSON * const requirements)
{
    if(!requirements) {
        return 1;
    }

    const cJSON * const title = cJSON_GetObjectItem(requirements, "title");
    if(!title) {
        merror("Field 'title' not found on requirements.");
        return 1;
    }

    if(!title->valuestring){
        merror("Field 'title' must be a string.");
        return 1;
    }

    const cJSON * const description = cJSON_GetObjectItem(requirements, "description");
    if(!description) {
        merror("Field 'description' not found on policy.");
        return 1;
    }

    if(!description->valuestring){
        merror("Field 'description' must be a string.");
        return 1;
    }

    const cJSON * const condition = cJSON_GetObjectItem(requirements, "condition");
    if(!condition) {
        merror("Field 'condition' not found on policy.");
        return 1;
    }

    if(!condition->valuestring){
        merror("Field 'condition' must be a string.");
        return 1;
    }

    const cJSON * const rules = cJSON_GetObjectItem(requirements, "rules");
    if (!rules) {
        merror("Field 'rules' must be present.");
        return 1;
    }

    if (!cJSON_IsArray(rules)) {
        merror("Field 'rules' must be an array.");
        return 1;
    }

    return 0;
}

#ifndef WIN32
static int wm_sca_resolve_symlink(const char * const file, char * realpath_buffer, char **reason)
{
    mdebug2("Resolving real path of '%s'", file);
    const char * const realpath_buffer_ref = realpath(file, realpath_buffer);

    if (realpath_buffer_ref == NULL) {
        const int realpath_errno = errno;

        if (realpath_errno == ENOENT) {
            mdebug2("Path '%s' does not exists, or points to an unexistent path -> RETURN_NOT_FOUND: %s", file, strerror(realpath_errno));
            return RETURN_NOT_FOUND;
        }

        mdebug2("Could not resolve the real path of '%s': %s", file, strerror(realpath_errno));
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Could not resolve the real path of '%s': %s", file, strerror(realpath_errno)) + 1, *reason);
            sprintf(*reason, "Could not resolve the real path of '%s': %s", file, strerror(realpath_errno));
        }

        return RETURN_INVALID;
    }

    mdebug2("Real path of '%s' is '%s'", file, realpath_buffer);
    return RETURN_FOUND;
}
#endif

static int wm_sca_check_dir_list(wm_sca_t * const data,
                                 char * const dir_list,
                                 char * const file,
                                 char * const pattern,
                                 char ** reason,
                                 w_expression_t * regex_engine)
{
    char *f_value_copy;
    os_strdup(dir_list, f_value_copy);
    char *f_value_copy_ref = f_value_copy;
    int found = RETURN_NOT_FOUND;
    char *dir = NULL;
    mdebug2("Exploring directories [%s]", f_value_copy);
    while ((dir = w_strtok_r_str_delim(",", &f_value_copy_ref))) {
        short is_nfs = IsNFS(dir);
        mdebug2("Checking directory '%s' => is_nfs=%d, skip_nfs=%d", dir, is_nfs, data->skip_nfs);
        if(data->skip_nfs && is_nfs == 1) {
            mdebug2("Directory '%s' flagged as NFS and skip_nfs is enabled.", dir);
            if (*reason == NULL) {
                os_malloc(snprintf(NULL, 0, "Directory '%s' flagged as NFS and skip_nfs is enabled", dir) + 1, *reason);
                sprintf(*reason, "Directory '%s' flagged as NFS and skip_nfs is enabled", dir);
            }
            found = RETURN_INVALID;
        } else {
            int check_result;
            if (file == NULL) {
                check_result = wm_sca_check_dir_existence(dir, reason);
            } else {
                check_result = wm_sca_check_dir(dir, file, pattern, reason, regex_engine);
            }

            if (check_result == RETURN_FOUND) {
                found = RETURN_FOUND;
                mdebug2("Found match in directory '%s'", dir);
            } else if (check_result == RETURN_INVALID) {
                found = RETURN_INVALID;
                mdebug2("Check returned not applicable for directory '%s'", dir);
            }
        }

        char _b_msg[OS_SIZE_1024 + 1];
        _b_msg[OS_SIZE_1024] = '\0';
        snprintf(_b_msg, OS_SIZE_1024, " Directory: %s", dir);
        append_msg_to_vm_scat(data, _b_msg);

        if (found == RETURN_FOUND) {
            break;
        }
    }

    os_free(f_value_copy);
    return found;
}

/*
Rules that match always return 1, and the other way arround.

Rule aggregators logic:

##########################################################

ALL:
    r_1 -f -> r:123
    ...
    r_n -f -> r:234

For an ALL to succeed, every rule shall return 1, in other words,

               |  = n -> ALL = RETURN_FOUND
SUM(r_i, 0, n) |
               | != n -> ALL = RETURN_NOT_FOUND

##########################################################

ANY:
    r_1 -f -> r:123
    ...
    r_n -f -> r:234

For an ANY to succeed, a rule shall return 1, in other words,

               | > 0 -> ANY = RETURN_FOUND
SUM(r_i, 0, n) |
               | = 0 -> ANY = RETURN_NOT_FOUND

##########################################################

NONE:
    r_1 -f -> r:123
    ...
    r_n -f -> r:234

For a NONE to succeed, all rules shall return RETURN_NOT_FOUND, in other words,

               |  > 0 -> NONE = RETURN_NOT_FOUND
SUM(r_i, 0, n) |
               |  = 0 -> NONE = RETURN_FOUND

##########################################################

ANY and NONE aggregators are complementary.

*/

static int wm_sca_do_scan(cJSON * checks,
                          OSStore * vars,
                          wm_sca_t * data,
                          int id,
                          cJSON * policy,
                          int requirements_scan,
                          int cis_db_index,
                          unsigned int remote_policy,
                          int first_scan,
                          int * checks_number,
                          char ** sorted_variables,
                          char * policy_engine)
{
    int type = 0;
    char buf[OS_SIZE_1024 + 2];
    char final_file[2048 + 1];
    char *reason = NULL;

    int ret_val = 0;
    OSList *p_list = NULL;

    /* Initialize variables */
    memset(buf, '\0', sizeof(buf));
    memset(final_file, '\0', sizeof(final_file));

    int check_count = 0;
    cJSON *check = NULL;
    cJSON_ArrayForEach(check, checks) {
        char _check_id_str[50];
        if (requirements_scan) {
            snprintf(_check_id_str, sizeof(_check_id_str), "Requirements check");
        } else {
            const cJSON * const c_id = cJSON_GetObjectItem(check, "id");
            if (!c_id || !c_id->valueint) {
                merror("Skipping check. Check ID is invalid. Offending check number: %d", check_count);
                ret_val = 1;
                continue;
            }
            snprintf(_check_id_str, sizeof(_check_id_str), "id: %d", c_id->valueint);
        }

        const cJSON * const c_title = cJSON_GetObjectItem(check, "title");
        if (!c_title || !c_title->valuestring) {
            merror("Skipping check with %s: Check name is invalid.", _check_id_str);
            if (requirements_scan) {
                ret_val = 1;
                goto clean_return;
            }
            continue;
        }

        const cJSON * const c_condition = cJSON_GetObjectItem(check, "condition");
        if (!c_condition || !c_condition->valuestring) {
            merror("Skipping check '%s: %s': Check condition not found.", _check_id_str, c_title->valuestring);
            if (requirements_scan) {
                ret_val = 1;
                goto clean_return;
            }
            continue;
        }

        int condition = 0;
        wm_sca_set_condition(c_condition->valuestring, &condition);

        if (condition == WM_SCA_COND_INV) {
            merror("Skipping check '%s: %s': Check condition (%s) is invalid.",_check_id_str, c_title->valuestring, c_condition->valuestring);
            if (requirements_scan) {
                ret_val = 1;
                goto clean_return;
            }
            continue;
        }

        int g_found = RETURN_NOT_FOUND;
        if ((condition & WM_SCA_COND_ANY) || (condition & WM_SCA_COND_NON)) {
            /* aggregators ANY and NONE break by matching, so they shall return NOT_FOUND if they never break */
            g_found = RETURN_NOT_FOUND;
        } else if (condition & WM_SCA_COND_ALL) {
            /* aggregator ALL breaks the moment a rule does not match. If it doesn't break, all rules have matched */
            g_found = RETURN_FOUND;
        }

        mdebug1("Beginning evaluation of check %s '%s'", _check_id_str, c_title->valuestring);
        mdebug1("Rule aggregation strategy for this check is '%s'", c_condition->valuestring);
        mdebug2("Initial rule-aggregator value por this type of rule is '%d'",  g_found);
        mdebug1("Beginning rules evaluation.");

        const cJSON *const rules = cJSON_GetObjectItem(check, "rules");
        if (!rules) {
            merror("Skipping check %s '%s': No rules found.", _check_id_str, c_title->valuestring);
            if (requirements_scan) {
                ret_val = 1;
                goto clean_return;
            }
            continue;
        }

        w_expression_t * regex_engine = NULL;
        cJSON * engine = cJSON_GetObjectItem(check, "regex_type");
        if (engine) {
            if (strcmp(PCRE2_STR, cJSON_GetStringValue(engine)) == 0) {
                w_calloc_expression_t(&regex_engine, EXP_TYPE_PCRE2);
            } else {
                w_calloc_expression_t(&regex_engine, EXP_TYPE_OSREGEX);
            }
        } else {
            if(strcmp(PCRE2_STR, policy_engine) == 0) {
                w_calloc_expression_t(&regex_engine, EXP_TYPE_PCRE2);
            } else {
                w_calloc_expression_t(&regex_engine, EXP_TYPE_OSREGEX);
            }
        }
        mdebug1("SCA will use '%s' engine to check the rules.", w_expression_get_regex_type(regex_engine));

        char *rule_cp = NULL;
        const cJSON *rule_ref;
        cJSON_ArrayForEach(rule_ref, rules) {
            /* this free is responsible of freeing the copy of the previous rule if
            the loop 'continues', i.e, does not reach the end of its block. */
            os_free(rule_cp);

            if(!rule_ref->valuestring) {
                mdebug1("Field 'rule' must be a string.");
                ret_val = 1;
                os_free(regex_engine);
                goto clean_return;
            }

            mdebug1("Considering rule: '%s'", rule_ref->valuestring);

            os_strdup(rule_ref->valuestring, rule_cp);
            char *rule_cp_ref = NULL;

        #ifdef WIN32
            char expanded_rule[2048] = {0};
            ExpandEnvironmentStrings(rule_cp, expanded_rule, 2048);
            rule_cp_ref = expanded_rule;
            mdebug2("Rule after variable expansion: '%s'", rule_cp_ref);
        #else
            rule_cp_ref = rule_cp;
        #endif

            int rule_is_negated = 0;
            if (rule_cp_ref &&
                    (strncmp(rule_cp_ref, "NOT ", 4) == 0 ||
                     strncmp(rule_cp_ref, "not ", 4) == 0))
            {
                mdebug2("Rule is negated.");
                rule_is_negated = 1;
                rule_cp_ref += 4;
            }

            /* Get value to look for. char *value is a reference
            to rule_cp memory. Do not release value!  */
            char *value = wm_sca_get_value(rule_cp_ref, &type);

            if (value == NULL) {
                merror("Invalid rule: '%s'. Skipping policy.", rule_ref->valuestring);
                os_free(rule_cp);
                ret_val = 1;
                os_free(regex_engine);
                goto clean_return;
            }

            int found = RETURN_NOT_FOUND;
            if (type == WM_SCA_TYPE_FILE) {
                /* Check files */
                char *pattern = wm_sca_get_pattern(value);
                char *rule_location = NULL;
                char *aux = NULL;

                os_strdup(value, rule_location);

                /* If any, replace the variables by their respective values */
                if (sorted_variables) {
                    for (int i = 0; sorted_variables[i]; i++) {
                        if (strstr(rule_location, sorted_variables[i])) {
                            mdebug2("Variable '%s' found at rule '%s'. Replacing it.", sorted_variables[i], rule_location);
                            aux = wstr_replace(rule_location, sorted_variables[i], OSStore_Get(vars, sorted_variables[i]));
                            os_free(rule_location);
                            rule_location = aux;
                            if (!rule_location) {
                                merror("Invalid variable replacement: '%s'. Skipping check.", sorted_variables[i]);
                                break;
                            }
                            mdebug2("Variable replaced: '%s'", rule_location);
                        }
                    }
                }

                if (!rule_location) {
                    continue;
                }
                const int result = wm_sca_check_file_list(rule_location, pattern, &reason, regex_engine);
                if (result == RETURN_FOUND || result == RETURN_INVALID) {
                    found = result;
                }

                char _b_msg[OS_SIZE_1024 + 1];
                _b_msg[OS_SIZE_1024] = '\0';
                snprintf(_b_msg, OS_SIZE_1024, " File: %s", rule_location);
                append_msg_to_vm_scat(data, _b_msg);
                os_free(rule_location);

            } else if (type == WM_SCA_TYPE_COMMAND) {
                /* Check command output */
                char *pattern = wm_sca_get_pattern(value);
                char *rule_location = NULL;
                char *aux = NULL;

                os_strdup(value, rule_location);

                if (!data->remote_commands && remote_policy) {
                    mwarn("Ignoring check for policy '%s'. The internal option 'sca.remote_commands' is disabled.", cJSON_GetObjectItem(policy, "name")->valuestring);
                    if (reason == NULL) {
                        os_malloc(snprintf(NULL, 0, "Ignoring check for running command '%s'. The internal option 'sca.remote_commands' is disabled", rule_location) + 1, reason);
                        sprintf(reason, "Ignoring check for running command '%s'. The internal option 'sca.remote_commands' is disabled", rule_location);
                    }
                    found = RETURN_INVALID;

                } else {
                    /* If any, replace the variables by their respective values */
                    if (sorted_variables) {
                        for (int i = 0; sorted_variables[i]; i++) {
                            if (strstr(rule_location, sorted_variables[i])) {
                                mdebug2("Variable '%s' found at rule '%s'. Replacing it.", sorted_variables[i], rule_location);
                                aux = wstr_replace(rule_location, sorted_variables[i], OSStore_Get(vars, sorted_variables[i]));
                                os_free(rule_location);
                                rule_location = aux;
                                if (!rule_location) {
                                    merror("Invalid variable: '%s'. Skipping check.", sorted_variables[i]);
                                    break;
                                }
                                mdebug2("Variable replaced: '%s'", rule_location);
                            }
                        }
                    }

                    if (!rule_location) {
                        continue;
                    }

                    mdebug2("Running command: '%s'", rule_location);
                    const int val = wm_sca_read_command(rule_location, pattern, data, &reason, regex_engine);
                    if (val == RETURN_FOUND) {
                        mdebug2("Command output matched.");
                        found = RETURN_FOUND;
                    } else if (val == RETURN_INVALID){
                        mdebug2("Command output did not match.");
                        found = RETURN_INVALID;
                    }
                }

                char _b_msg[OS_SIZE_1024 + 1];
                _b_msg[OS_SIZE_1024] = '\0';
                snprintf(_b_msg, OS_SIZE_1024, " Command: %s", rule_location);
                append_msg_to_vm_scat(data, _b_msg);
                os_free(rule_location);

            } else if (type == WM_SCA_TYPE_DIR) {
                /* Check directory */
                mdebug2("Processing directory rule '%s'", value);
                char * const file = wm_sca_get_pattern(value);
                char *rule_location = NULL;
                char *aux = NULL;

                os_strdup(value, rule_location);

                /* If any, replace the variables by their respective values */
                if (sorted_variables) {
                    for (int i = 0; sorted_variables[i]; i++) {
                        if (strstr(rule_location, sorted_variables[i])) {
                            mdebug2("Variable '%s' found at rule '%s'. Replacing it.", sorted_variables[i], rule_location);
                            aux = wstr_replace(rule_location, sorted_variables[i], OSStore_Get(vars, sorted_variables[i]));
                            os_free(rule_location);
                            rule_location = aux;
                            if (!rule_location) {
                                merror("Invalid variable: '%s'. Skipping check.", sorted_variables[i]);
                                break;
                            }
                            mdebug2("Variable replaced: '%s'", rule_location);
                        }
                    }
                }

                if (!rule_location) {
                    continue;
                }

                char * const pattern = wm_sca_get_pattern(file);
                found = wm_sca_check_dir_list(data, rule_location, file, pattern, &reason, regex_engine);
                mdebug2("Check directory rule result: %d", found);
                os_free(rule_location);

            } else if (type == WM_SCA_TYPE_PROCESS) {
                /* Check process existence */
                if (!p_list) {
                    /* Lazy evaluation */
                    p_list = w_os_get_process_list();
                }

                mdebug2("Checking process: '%s'", value);
                if (wm_sca_check_process_is_running(p_list, value, &reason, regex_engine)) {
                    mdebug2("Process found.");
                    found = RETURN_FOUND;
                } else {
                    mdebug2("Process not found.");
                }

                char _b_msg[OS_SIZE_1024 + 1];
                _b_msg[OS_SIZE_1024] = '\0';
                snprintf(_b_msg, OS_SIZE_1024, " Process: %s", value);
                append_msg_to_vm_scat(data, _b_msg);
            }
        #ifdef WIN32
            else if (type == WM_SCA_TYPE_REGISTRY) {
                /* Check windows registry */
                char * const entry = wm_sca_get_pattern(value);
                char * const pattern = wm_sca_get_pattern(entry);
                found = wm_sca_is_registry(value, entry, pattern, &reason, regex_engine);

                char _b_msg[OS_SIZE_1024 + 1];
                _b_msg[OS_SIZE_1024] = '\0';
                snprintf(_b_msg, OS_SIZE_1024, " Registry: %s", value);
                append_msg_to_vm_scat(data, _b_msg);
            }
        #endif

            /* Rule result processing */

            if (found != RETURN_INVALID) {
                found = rule_is_negated ^ found;
            }

            mdebug1("Result for rule '%s': %d", rule_ref->valuestring, found);

            if (((condition & WM_SCA_COND_ALL) && found == RETURN_NOT_FOUND) ||
                ((condition & WM_SCA_COND_ANY) && found == RETURN_FOUND) ||
                ((condition & WM_SCA_COND_NON) && found == RETURN_FOUND))
            {
                g_found = found;
                mdebug1("Breaking from rule aggregator '%s' with found = %d", c_condition->valuestring, g_found);
                break;
            }

            if (found == RETURN_INVALID) {
                /* Rules that agreggate by ANY are the only that can success after an INVALID
                On the other hand ALL and NONE agregators can fail after an INVALID. */
                g_found = found;
                mdebug1("Rule evaluation returned INVALID. Continuing.");
            }
        }

        if ((condition & WM_SCA_COND_NON) && g_found != RETURN_INVALID) {
            g_found = !g_found;
        }

        mdebug1("Result for check %s '%s' -> %d", _check_id_str, c_title->valuestring, g_found);

        if (g_found != RETURN_INVALID) {
            os_free(reason);
        }

        /* if the loop breaks, rule_cp shall be released.
            Also frees the the memory reserved on the last iteration */
        os_free(rule_cp);

        /* Determine if requirements are satisfied */
        if (requirements_scan) {
            /*  return value for requirement scans is the inverse of the result,
                unless the result is INVALID */
            ret_val = g_found == RETURN_INVALID ? 1 : !g_found;
            int i;
            for (i=0; data->alert_msg[i]; i++){
                free(data->alert_msg[i]);
                data->alert_msg[i] = NULL;
            }
            w_free_expression_t(&regex_engine);
            goto clean_return;
        }

        /* Event construction */
        const char failed[] = "failed";
        const char passed[] = "passed";
        const char invalid[] = ""; //NOT AN ERROR!
        const char *message_ref = NULL;

        if (g_found == RETURN_NOT_FOUND) {
            wm_sca_summary_increment_failed();
            message_ref = failed;
        } else if (g_found == RETURN_FOUND) {
            wm_sca_summary_increment_passed();
            message_ref = passed;
        } else {
            wm_sca_summary_increment_invalid();
            message_ref = invalid;

            if (reason == NULL) {
                os_malloc(snprintf(NULL, 0, "Unknown reason") + 1, reason);
                sprintf(reason, "Unknown reason");
                mdebug1("A check returned INVALID for an unknown reason.");
            }
        }

        cJSON *event = wm_sca_build_event(check, policy, data->alert_msg, id, message_ref, reason);
        if (event) {
            /* Alert if necessary */
            if(!cis_db_for_hash[cis_db_index].elem[check_count]) {
                os_realloc(cis_db_for_hash[cis_db_index].elem, sizeof(cis_db_info_t *) * (check_count + 2), cis_db_for_hash[cis_db_index].elem);
                cis_db_for_hash[cis_db_index].elem[check_count] = NULL;
                cis_db_for_hash[cis_db_index].elem[check_count + 1] = NULL;
            }

            if (wm_sca_check_hash(cis_db[cis_db_index], message_ref, check, event, check_count, cis_db_index) && !first_scan) {
                wm_sca_send_event_check(data,event);
            }

            check_count++;

            cJSON_Delete(event);
        } else {
            merror("Error constructing event for check: %s. Set debug mode for more information.", c_title->valuestring);
            ret_val = 1;
        }

        int i;
        for (i=0; data->alert_msg[i]; i++){
            free(data->alert_msg[i]);
            data->alert_msg[i] = NULL;
        }

        os_free(reason);
        w_free_expression_t(&regex_engine);
    }

    *checks_number = check_count;

/* Clean up memory */
clean_return:
    os_free(reason);
    w_del_plist(p_list);

    return ret_val;
}

static void wm_sca_set_condition(const char * const c_cond, int *condition)
{
    if (strcmp(c_cond, "all") == 0) {
        *condition |= WM_SCA_COND_ALL;
    } else if (strcmp(c_cond, "any") == 0) {
        *condition |= WM_SCA_COND_ANY;
    } else if (strcmp(c_cond, "none") == 0) {
        *condition |= WM_SCA_COND_NON;
    } else if (strcmp(c_cond, "any required") == 0) {
        *condition |= WM_SCA_COND_ANY;
        minfo("Modifier 'required' is deprecated. Defaults to 'any'");
    } else if (strcmp(c_cond, "all required") == 0) {
        *condition |= WM_SCA_COND_ALL;
        minfo("Modifier 'required' is deprecated. Defaults to 'all'");
    } else {
        *condition = WM_SCA_COND_INV;
    }
}

static int wm_sca_get_vars(const cJSON * const variables, OSStore * const vars)
{
    const cJSON *variable;
    cJSON_ArrayForEach (variable, variables) {
        if (*variable->string != '$') {
            merror("Invalid variable: '%s'", variable->string);
            return -1;
        }

        char *var_value;
        os_strdup(variable->valuestring, var_value);
        OSStore_Put(vars, variable->string, var_value);

    }

    return 0;
}

static char *wm_sca_get_value(char *buf, int *type)
{
    /* Zero type before using it to make sure return is valid
     * in case of error.
     */
    *type = 0;

    char *value = strchr(buf, ':');
    if (value == NULL) {
        return NULL;
    }

    *value = '\0';
    value++;

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
        return NULL;
    }

    return value;
}

static char *wm_sca_get_pattern(char *value)
{
    if (value == NULL) {
        return NULL;
    }

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

static int wm_sca_check_file_existence(const char * const file, char **reason)
{
    #ifdef WIN32
    const char *realpath_buffer = file;
    #else
    char realpath_buffer[OS_MAXSTR];
    const int wm_sca_resolve_symlink_result = wm_sca_resolve_symlink(file, realpath_buffer, reason);
    if (wm_sca_resolve_symlink_result != RETURN_FOUND) {
        return wm_sca_resolve_symlink_result;
    }
    #endif

    struct stat statbuf;
    const int lstat_ret = lstat(realpath_buffer, &statbuf);
    const int lstat_errno = errno;

    if (lstat_ret == -1) {
        if (lstat_errno == ENOENT) {
            mdebug2("FILE_EXISTS(%s) -> RETURN_NOT_FOUND: %s", file, strerror(lstat_errno));
            return RETURN_NOT_FOUND;
        }
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Could not open '%s': %s", file, strerror(lstat_errno)) + 1, *reason);
            sprintf(*reason, "Could not open '%s': %s", file, strerror(lstat_errno));
        }
        mdebug2("FILE_EXISTS(%s) -> RETURN_INVALID: %s", file, strerror(lstat_errno));
        return RETURN_INVALID;
    }

    if (S_ISREG(statbuf.st_mode)) {
        mdebug2("FILE_EXISTS(%s) -> RETURN_FOUND", file);
        return RETURN_FOUND;
    }

    if (*reason == NULL) {
        os_malloc(snprintf(NULL, 0, "FILE_EXISTS(%s) -> RETURN_INVALID: Not a regular file.", file) + 1, *reason);
        sprintf(*reason, "FILE_EXISTS(%s) -> RETURN_INVALID: Not a regular file.", file);
    }

    mdebug2("FILE_EXISTS(%s) -> RETURN_INVALID: Not a regular file.", file);
    return RETURN_INVALID;
}

static int wm_sca_check_file_contents(const char * const file,
                                      const char * const pattern,
                                      char ** reason,
                                      w_expression_t * regex_engine)
{
    mdebug2("Checking contents of file '%s' against pattern '%s'", file, pattern);

    #ifdef WIN32
    const char *realpath_buffer = file;
    #else
    char realpath_buffer[OS_MAXSTR];
    const int wm_sca_resolve_symlink_result = wm_sca_resolve_symlink(file, realpath_buffer, reason);
    if (wm_sca_resolve_symlink_result != RETURN_FOUND) {
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Could not open file '%s'", file) + 1, *reason);
            sprintf(*reason, "Could not open file '%s'", file);
        }

        mdebug2("Could not open file '%s'", file);

        return RETURN_INVALID;
    }
    #endif

    FILE *fp = wfopen(realpath_buffer, "r");
    const int fopen_errno = errno;
    if (!fp) {
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Could not open file '%s': %s", file, strerror(fopen_errno)) + 1, *reason);
            sprintf(*reason, "Could not open file '%s': %s", file, strerror(fopen_errno));
        }
        mdebug2("Could not open file '%s': %s", file, strerror(fopen_errno));
        return RETURN_INVALID;
    }

    int result = RETURN_NOT_FOUND;
    char buf[OS_SIZE_2048 + 1];
    while (fgets(buf, OS_SIZE_2048, fp) != NULL) {
        os_trimcrlf(buf);
        result = wm_sca_pattern_matches(buf, pattern, reason, regex_engine);
        mdebug2("(%s)(%s) -> %d", pattern, *buf != '\0' ? buf : "EMPTY_LINE" , result);

        if (result) {
            mdebug2("Match found. Skipping the rest.");
            break;
        }
    }

    fclose(fp);
    mdebug2("Result for (%s)(%s) -> %d", pattern, file, result);
    return result;
}

static int wm_sca_check_file_list(const char * const file_list,
                                  char * const pattern,
                                  char ** reason,
                                  w_expression_t * regex_engine)
{
    if (pattern) {
        return wm_sca_check_file_list_for_contents(file_list, pattern, reason, regex_engine);
    }

    return wm_sca_check_file_list_for_existence(file_list, reason);
}

static int wm_sca_check_file_list_for_existence(const char * const file_list, char **reason)
{
    mdebug1("Checking file list '%s' for existence.", file_list);

    if (!file_list) {
        return RETURN_NOT_FOUND;
    }

    int result_accumulator = RETURN_NOT_FOUND;
    char *file_list_copy = NULL;
    os_strdup(file_list, file_list_copy);
    char *file_list_ref = file_list_copy;
    char *file = NULL;
    char *save_ptr = NULL;
    for (file = strtok_r(file_list_ref, ",", &save_ptr); file != NULL;
            file = strtok_r(NULL, ",", &save_ptr))
    {
        const int file_check_result = wm_sca_check_file_existence(file, reason);
        if (file_check_result == RETURN_FOUND) {
            result_accumulator = RETURN_FOUND;
            mdebug2("File '%s' found. Skipping the rest.", file);
            break;
        }

        if (file_check_result == RETURN_INVALID) {
            result_accumulator = RETURN_INVALID;
            mdebug2("Could not open file '%s'. Continuing.", file);
        } else {
            mdebug2("File '%s' does not exists. Continuing.", file);
        }
    }

    mdebug1("Result for FILES_EXIST(%s) -> %d", file_list, result_accumulator);

    os_free(file_list_copy);
    return result_accumulator;
}

static int wm_sca_check_file_list_for_contents(const char * const file_list,
                                               char * pattern,
                                               char ** reason,
                                               w_expression_t * regex_engine)
{
    mdebug1("Checking file list '%s' with '%s'", file_list, pattern);

    if (!file_list) {
        return RETURN_NOT_FOUND;
    }

    int result_accumulator = RETURN_NOT_FOUND;
    char *file_list_copy = NULL;
    os_strdup(file_list, file_list_copy);
    char *file_list_ref = file_list_copy;
    char *file = NULL;
    char *save_ptr = NULL;
    for (file = strtok_r(file_list_ref, ",", &save_ptr); file != NULL;
            file = strtok_r(NULL, ",", &save_ptr))
    {
        const int existence_check_result = wm_sca_check_file_existence(file, reason);
        if (existence_check_result != RETURN_FOUND) {
            /* a file that does not exist produces an INVALID check */
            result_accumulator = RETURN_INVALID;
            if (*reason == NULL) {
                os_malloc(snprintf(NULL, 0, "Could not open file '%s'",  file) + 1, *reason);
                sprintf(*reason, "Could not open file '%s'",  file);
            }
            mdebug2("Could not open file '%s'. Skipping.", file);
            continue;
        }

        const int contents_check_result = wm_sca_check_file_contents(file, pattern, reason, regex_engine);
        if (contents_check_result == RETURN_FOUND) {
            result_accumulator = RETURN_FOUND;
            mdebug2("Match found in '%s'. Skipping the rest.", file);
            break;
        }

        if (contents_check_result == RETURN_INVALID) {
            mdebug2("Check was invalid in file '%s'. Continuing.", file);
            result_accumulator = RETURN_INVALID;
        } else {
            mdebug2("Match not found in file '%s'. Continuing.", file);
        }
    }

    mdebug1("Result for (%s)(%s) -> %d", pattern, file_list, result_accumulator);

    os_free(file_list_copy);
    return result_accumulator;
}

static int wm_sca_read_command(char * command,
                               char * pattern,
                               wm_sca_t * data,
                               char ** reason,
                               w_expression_t * regex_engine)
{
    if (command == NULL) {
        mdebug1("No Command specified Returning.");
        return RETURN_NOT_FOUND;
    }

    if (!pattern) {
        mdebug1("No pattern given. Returning FOUND.");
        return RETURN_FOUND;
    }

    mdebug1("Executing command '%s', and testing output with pattern '%s'", command, pattern);
    char *cmd_output = NULL;
    int result_code;

    switch (wm_exec(command, &cmd_output, &result_code, data->commands_timeout, NULL)) {
    case 0:
        mdebug1("Command '%s' returned code %d", command, result_code);
        break;
    case WM_ERROR_TIMEOUT:
        os_free(cmd_output);
        mdebug1("Timeout overtaken running command '%s'", command);
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Timeout overtaken running command '%s'", command) + 1, *reason);
            sprintf(*reason, "Timeout overtaken running command '%s'", command);
        }
        os_free(cmd_output);
        return RETURN_INVALID;
    default:
        if (result_code == EXECVE_ERROR) {
            mdebug1("Invalid path or wrong permissions to run command '%s'", command);
            if (*reason == NULL) {
                os_malloc(snprintf(NULL, 0, "Invalid path or wrong permissions to run command '%s'", command) + 1, *reason);
                sprintf(*reason, "Invalid path or wrong permissions to run command '%s'", command);
            }
        } else {
            mdebug1("Failed to run command '%s'. Returned code %d", command, result_code);
            if (*reason == NULL) {
                os_malloc(snprintf(NULL, 0, "Failed to run command '%s'. Returned code %d", command, result_code) + 1, *reason);
                sprintf(*reason, "Failed to run command '%s'. Returned code %d", command, result_code);
            }
        }
        return RETURN_INVALID;
    }

    if(!cmd_output) {
        mdebug2("Command yielded no output. Returning.");
        return RETURN_NOT_FOUND;
    }

    char **output_line;
    output_line = OS_StrBreak('\n', cmd_output, 256);

    if(!output_line) {
        mdebug1("Command output could not be processed. Output dump:\n%s", cmd_output);
        os_free(cmd_output);
        return RETURN_NOT_FOUND;
    }

    os_free(cmd_output);

    int i;
    int result = RETURN_NOT_FOUND;
    for (i=0; output_line[i] != NULL; i++) {
        char *buf = output_line[i];
        os_trimcrlf(buf);
        result = wm_sca_pattern_matches(buf, pattern, reason, regex_engine);
        if (result == RETURN_FOUND){
            break;
        }
    }

    free_strarray(output_line);
    mdebug2("Result for (%s)(%s) -> %d", pattern, command, result);
    return result;
}

static int wm_sca_apply_numeric_partial_comparison(const char * const partial_comparison,
                                                   const long int number,
                                                   char ** reason,
                                                   w_expression_t * regex_engine)
{
    if (!partial_comparison) {
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "No comparison provided.") + 1, *reason);
            sprintf(*reason, "No comparison provided.");
        }
        mwarn("No comparison provided.");
        return RETURN_INVALID;
    }

    mdebug2("Partial comparison '%s'", partial_comparison);

    w_expression_t * regex = NULL;
    if (strcmp(w_expression_get_regex_type(regex_engine), OSREGEX_STR) == 0) {
            w_calloc_expression_t(&regex, EXP_TYPE_OSREGEX);
    }
    else if (strcmp(w_expression_get_regex_type(regex_engine), PCRE2_STR) == 0) {
            w_calloc_expression_t(&regex, EXP_TYPE_PCRE2);
    }
    else{
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Invalid regex type.") + 1, *reason);
            sprintf(*reason, "Invalid regex type.");
        }
        return RETURN_INVALID;
    }

    if (!w_expression_compile(regex, "(\\d+)", OS_RETURN_SUBSTRING)) {
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Cannot compile regex.") + 1, *reason);
            sprintf(*reason, "Cannot compile regex.");
        }
        mwarn("Cannot compile regex");
        w_free_expression_t(&regex);
        return RETURN_INVALID;
    }
    regex_matching * regex_match = NULL;
    os_calloc(1, sizeof(regex_matching), regex_match);

    if (!w_expression_match(regex, partial_comparison, NULL, regex_match)) {
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "No integer was found within the comparison '%s' ", partial_comparison) + 1, *reason);
            sprintf(*reason, "No integer was found within the comparison '%s' ", partial_comparison);
        }
        mwarn("No integer was found within the comparison '%s' ", partial_comparison);
        w_free_expression_match(regex, &regex_match);
        w_free_expression_t(&regex);
        return RETURN_INVALID;
    }

    if (!regex_match->sub_strings || !regex_match->sub_strings[0]) {
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "No number was captured.") + 1, *reason);
            sprintf(*reason, "No number was captured.");
        }
        mwarn("No number was captured.");
        w_free_expression_match(regex, &regex_match);
        w_free_expression_t(&regex);
        return RETURN_INVALID;
    }

    mdebug2("Value given for comparison: '%s'", regex_match->sub_strings[0]);

    errno = 0;
    char *strtol_end_ptr = NULL;
    const long int value_given = strtol(regex_match->sub_strings[0], &strtol_end_ptr, 10);

    if (errno != 0 || strtol_end_ptr == regex_match->sub_strings[0]) {
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Conversion error. Cannot convert '%s' to integer.", regex_match->sub_strings[0]) + 1, *reason);
            sprintf(*reason, "Conversion error. Cannot convert '%s' to integer.", regex_match->sub_strings[0]);
        }
        mwarn("Conversion error. Cannot convert '%s' to integer.", regex_match->sub_strings[0]);
        w_free_expression_match(regex, &regex_match);
        w_free_expression_t(&regex);
        return RETURN_INVALID;
    }

    if (regex_match) {
        if (regex_match->sub_strings) {
            for (unsigned int a = 0; regex_match->sub_strings[a] != NULL; a++) {
                os_free(regex_match->sub_strings[a]);
            }
            os_free(regex_match->sub_strings);
        }
    }

    w_free_expression_match(regex, &regex_match);
    w_free_expression_t(&regex);


    mdebug2("Value converted: '%ld'", value_given);

    if ('=' == *partial_comparison) {
        mdebug2("Operation is '%ld == %ld'", number, value_given);
        return number == value_given ? RETURN_FOUND : RETURN_NOT_FOUND;
    } else if (strstr(partial_comparison, "!=")) {
        mdebug2("Operation is '%ld != %ld'", number, value_given);
        return number != value_given ? RETURN_FOUND : RETURN_NOT_FOUND;
    } else if (strstr(partial_comparison, "<=")) {
        mdebug2("Operation is '%ld <= %ld'", number, value_given);
        return number <= value_given ? RETURN_FOUND : RETURN_NOT_FOUND;
    } else if (strstr(partial_comparison, ">=")) {
        mdebug2("Operation is '%ld >= %ld'", number, value_given);
        return number >= value_given ? RETURN_FOUND : RETURN_NOT_FOUND;
    } else if (strstr(partial_comparison, "<")) {
        mdebug2("Operation is '%ld < %ld'", number, value_given);
        return number < value_given ? RETURN_FOUND : RETURN_NOT_FOUND;
    } else if (strstr(partial_comparison, ">")) {
        mdebug2("Operation is '%ld > %ld'", number, value_given);
        return number > value_given ? RETURN_FOUND : RETURN_NOT_FOUND;
    }
    if (*reason == NULL) {
        os_malloc(snprintf(NULL, 0, "Unrecognized operation: '%s'", partial_comparison) + 1, *reason);
        sprintf(*reason, "Unrecognized operation: '%s'", partial_comparison);
    }
    mdebug2("Unrecognized operation: '%s'", partial_comparison);
    return RETURN_INVALID;
}

static int wm_sca_regex_numeric_comparison (const char * const pattern,
                                            const char * const str,
                                            char ** reason,
                                            w_expression_t * regex_engine)
{
    char *pattern_copy;
    os_strdup(pattern, pattern_copy);
    char *pattern_copy_ref = pattern_copy;
    char *partial_comparison_ref = strstr(pattern_copy_ref, " compare ");

    if (!partial_comparison_ref) {
        mdebug2("Keyword 'compare' not found. Did you forget adding 'compare COMPARATOR VALUE' to your rule?' %s'", pattern_copy_ref);
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Keyword 'compare' not found. Did you forget adding 'compare COMPARATOR VALUE' to your rule?' %s'", pattern_copy_ref) + 1, *reason);
            sprintf(*reason, "Keyword 'compare' not found. Did you forget adding 'compare COMPARATOR VALUE' to your rule?' %s'", pattern_copy_ref);
        }
        os_free(pattern_copy);
        return RETURN_INVALID;
    }

    *partial_comparison_ref = '\0';
    partial_comparison_ref += 9;
    mdebug2("REGEX: '%s'. Partial comparison: '%s'", pattern_copy_ref, partial_comparison_ref);

    if (!w_expression_compile(regex_engine, pattern_copy_ref, OS_RETURN_SUBSTRING)) {
        mdebug2("Cannot compile regex '%s'", pattern_copy_ref);
        if (!*reason) {
            os_malloc(snprintf(NULL, 0, "Cannot compile regex '%s'", pattern_copy_ref) + 1, *reason);
            sprintf(*reason, "Cannot compile regex '%s'", pattern_copy_ref);
        }
        os_free(pattern_copy);
        return RETURN_INVALID;
    }
    regex_matching * regex_match = NULL;
    os_calloc(1, sizeof(regex_matching), regex_match);

    if (!w_expression_match(regex_engine, str, NULL, regex_match)) {
        mdebug2("No match found for regex '%s'", pattern_copy_ref);
        os_free(pattern_copy);
        w_free_expression_match(regex_engine, &regex_match);
        return RETURN_NOT_FOUND;
    }

    if (!regex_match->sub_strings || !regex_match->sub_strings[0]) {
        mdebug2("Regex '%s' matched, but no string was captured by it. Did you forget specifying a capture group?", pattern_copy_ref);
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Regex '%s' matched, but no string was captured by it. Did you forget specifying a capture group?", pattern_copy_ref) + 1, *reason);
            sprintf(*reason, "Regex '%s' matched, but no string was captured by it. Did you forget specifying a capture group?", pattern_copy_ref);
        }
        os_free(pattern_copy);
        w_free_expression_match(regex_engine, &regex_match);
        return RETURN_INVALID;
    }

    mdebug2("Captured value: '%s'", regex_match->sub_strings[0]);

    errno = 0;
    char *strtol_end_ptr = NULL;
    const long int value_captured = strtol(regex_match->sub_strings[0], &strtol_end_ptr, 10);

    if (errno != 0 || strtol_end_ptr == regex_match->sub_strings[0]) {
        mdebug2("Conversion error. Cannot convert '%s' to integer.", regex_match->sub_strings[0]);
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Conversion error. Cannot convert '%s' to integer.", regex_match->sub_strings[0]) + 1, *reason);
            sprintf(*reason, "Conversion error. Cannot convert '%s' to integer.", regex_match->sub_strings[0]);
        }
        os_free(pattern_copy);
        w_free_expression_match(regex_engine, &regex_match);
        return RETURN_INVALID;
    }

    mdebug2("Converted value: '%ld'", value_captured);

    const int result = wm_sca_apply_numeric_partial_comparison(partial_comparison_ref, value_captured, reason, regex_engine);
    mdebug2("Comparison result '%ld %s' -> %d", value_captured, partial_comparison_ref, result);

    os_free(pattern_copy);
    if (regex_match) {
        if (regex_match->sub_strings) {
            for (unsigned int a = 0; regex_match->sub_strings[a] != NULL; a++) {
                os_free(regex_match->sub_strings[a]);
            }
            os_free(regex_match->sub_strings);
        }
        w_free_expression_match(regex_engine, &regex_match);
    }

    return result;
}

int wm_sca_test_positive_minterm(char * const minterm,
                                 const char * const str,
                                 char **reason,
                                 w_expression_t * regex_engine)
{
    char * pattern_ref = minterm;
    if (strncasecmp(pattern_ref, "r:", 2) == 0) {
        pattern_ref += 2;
        if (!w_expression_compile(regex_engine, pattern_ref, OS_RETURN_SUBSTRING)) {
            mdebug2("Failed to compile regex '%s'", pattern_ref);
            return RETURN_NOT_FOUND;
        }
        if (w_expression_match(regex_engine, str, NULL, NULL)) {
            return RETURN_FOUND;
        }
    } else if (strncasecmp(pattern_ref, "n:", 2) == 0) {
        pattern_ref += 2;
        return wm_sca_regex_numeric_comparison(pattern_ref, str, reason, regex_engine);
    } else if (strcasecmp(pattern_ref, str) == 0) {
        return RETURN_FOUND;
    }

    return RETURN_NOT_FOUND;
}

int wm_sca_pattern_matches(const char * const str,
                           const char * const pattern,
                           char ** reason,
                           w_expression_t * regex_engine)
{
    if (!str) {
        return 0;
    }

    char *pattern_copy = NULL;
    os_strdup(pattern, pattern_copy);
    char *pattern_copy_ref = pattern_copy;
    char *minterm = NULL;
    int test_result = RETURN_FOUND;

    while ((minterm = w_strtok_r_str_delim(" && ", &pattern_copy_ref))) {
        int negated = 0;
        if ((*minterm) == '!'){
            minterm++;
            negated = 1;
        }

        w_expression_t * regex = NULL;
        if (strcmp(w_expression_get_regex_type(regex_engine), OSREGEX_STR) == 0) {
            w_calloc_expression_t(&regex, EXP_TYPE_OSREGEX);
        }
        else if (strcmp(w_expression_get_regex_type(regex_engine), PCRE2_STR) == 0) {
            w_calloc_expression_t(&regex, EXP_TYPE_PCRE2);
        }
        if(regex == NULL)
            break;

        const int minterm_result = negated ^ wm_sca_test_positive_minterm (minterm, str, reason, regex);
        w_free_expression_t(&regex);

        test_result *= minterm_result;
        mdebug2("Testing minterm (%s%s)(%s) -> %d", negated ? "!" : "", minterm, *str != '\0' ? str : "EMPTY_LINE", minterm_result);
    }

    mdebug2("Pattern test result: (%s)(%s) -> %d", pattern, *str != '\0' ? str : "EMPTY_LINE", test_result);
    os_free(pattern_copy);

    return test_result;
}

static int wm_sca_check_dir_existence(const char * const dir, char **reason)
{
    #ifdef WIN32
    const char *realpath_buffer = dir;
    #else
    char realpath_buffer[OS_MAXSTR];
    const int wm_sca_resolve_symlink_result = wm_sca_resolve_symlink(dir, realpath_buffer, reason);
    if (wm_sca_resolve_symlink_result != RETURN_FOUND) {
        return wm_sca_resolve_symlink_result;
    }
    #endif

    DIR *dp = wopendir(realpath_buffer);
    const int open_dir_errno = errno;
    if (dp) {
        mdebug2("DIR_EXISTS(%s) -> RETURN_FOUND", dir);
        closedir(dp);
        return RETURN_FOUND;
    }

    if (open_dir_errno == ENOENT) {
        mdebug2("DIR_EXISTS(%s) -> RETURN_NOT_FOUND. Reason: %s", dir, strerror(open_dir_errno));
        return RETURN_NOT_FOUND;
    }

    if (*reason == NULL) {
        os_malloc(snprintf(NULL, 0, "Could not check directory existence for '%s': %s", dir, strerror(open_dir_errno)) + 1, *reason);
        sprintf(*reason, "Could not check directory existence for '%s': %s", dir, strerror(open_dir_errno));
    }

    mdebug2("Could not check directory existence for '%s': %s", dir, strerror(open_dir_errno));
    return RETURN_INVALID;
}

static int wm_sca_check_dir(const char * const dir,
                            const char * const file,
                            char * const pattern,
                            char **reason,
                            w_expression_t * regex_engine)
{
    mdebug2("Checking directory '%s'%s%s%s%s", dir,
            file ? " -> "  : "", file ? file : "",
            pattern ? " -> " : "", pattern ? pattern: "");

    #ifdef WIN32
    const char *realpath_buffer = dir;
    #else
    char realpath_buffer[OS_MAXSTR];
    const int wm_sca_resolve_symlink_result = wm_sca_resolve_symlink(dir, realpath_buffer, reason);
    if (wm_sca_resolve_symlink_result != RETURN_FOUND) {
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Could not open dir '%s'", dir) + 1, *reason);
            sprintf(*reason, "Could not open dir '%s'", dir);
        }

        mdebug2("Could not open dir '%s'", dir);

        return RETURN_INVALID;
    }
    #endif

    DIR *dp = wopendir(realpath_buffer);
    if (!dp) {
        const int open_dir_errno = errno;
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Could not open '%s': %s", dir, strerror(open_dir_errno)) + 1, *reason);
            sprintf(*reason, "Could not open '%s': %s", dir, strerror(open_dir_errno));
        }
        mdebug2("Could not open '%s': %s", dir, strerror(open_dir_errno));
        return RETURN_INVALID;
    }

    int result_accumulator = RETURN_NOT_FOUND;
    struct dirent *entry = NULL;

    while ((entry = readdir(dp)) != NULL) {
        /* Ignore . and ..  */
        if ((strcmp(entry->d_name, ".") == 0) || (strcmp(entry->d_name, "..") == 0)) {
            continue;
        }

        /* Create new file + path string */
        char f_name[PATH_MAX + 2];
        f_name[PATH_MAX + 1] = '\0';
        snprintf(f_name, PATH_MAX + 1, "%s/%s", dir, entry->d_name);

        mdebug2("Considering directory entry '%s'", f_name);

        int result;
        struct stat statbuf_local;
        if (lstat(f_name, &statbuf_local) != 0) {
            mdebug2("Cannot check directory entry '%s'", f_name);
            if (*reason == NULL){
                os_malloc(snprintf(NULL, 0, "Cannot check directory entry '%s", f_name) + 1, *reason);
                sprintf(*reason, "Cannot check directory entry '%s", f_name);
            }
            result_accumulator = RETURN_INVALID;
            continue;
        }

        if (S_ISDIR(statbuf_local.st_mode)) {
            result = wm_sca_check_dir(f_name, file, pattern, reason, regex_engine);
        } else if (((file && strncasecmp(file, "r:", 2) == 0) && OS_Regex(file + 2, entry->d_name))
                || OS_Match2(file, entry->d_name))
        {
            result = wm_sca_check_file_list(f_name, pattern, reason, regex_engine);
        } else {
            mdebug2("Skipping directory entry '%s'", f_name);
            continue;
        }

        mdebug2("Result for entry '%s': %d", f_name, result);

        if (result == RETURN_FOUND) {
            mdebug2("Match found in '%s', skipping the rest.", f_name);
            result_accumulator = RETURN_FOUND;
            break;
        } else if (result == RETURN_INVALID) {
            result_accumulator = RETURN_INVALID;
        }
    }

    closedir(dp);
    mdebug2("Check result for dir '%s': %d", dir, result_accumulator);
    return result_accumulator;
}

static int wm_sca_check_process_is_running(OSList * p_list,
                                           char * value,
                                           char ** reason,
                                           w_expression_t * regex_engine)
{
    if (p_list == NULL) {
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Process list is empty.") + 1, *reason);
            sprintf(*reason, "Process list is empty.");
        }
        return RETURN_INVALID;
    }

    if (!value) {
        return RETURN_NOT_FOUND;
    }

    OSListNode *l_node = OSList_GetFirstNode(p_list);
    while (l_node) {
        W_Proc_Info *pinfo = (W_Proc_Info *)l_node->data;
        /* Check if value matches */
        if (wm_sca_pattern_matches(pinfo->p_path, value, reason, regex_engine)) {
            return RETURN_FOUND;
        }

        l_node = OSList_GetNextNode(p_list);
    }

    return RETURN_NOT_FOUND;
}

// Destroy data
void wm_sca_destroy(wm_sca_t * data) {
    os_free(data);
}

#ifdef WIN32

static int wm_sca_is_registry(char * entry_name,
                              char * reg_option,
                              char * reg_value,
                              char ** reason,
                              w_expression_t * regex_engine)
{
    char *rk = wm_sca_os_winreg_getkey(entry_name);

    if (wm_sca_sub_tree == NULL || rk == NULL) {
         if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Invalid registry entry: '%s'", entry_name) + 1, *reason);
            sprintf(*reason, "Invalid registry entry: '%s'", entry_name);
        }

        merror("Invalid registry entry: '%s'", entry_name);
        return RETURN_INVALID;
    }

    int returned_value_64 = wm_sca_test_key(rk, entry_name, KEY_WOW64_64KEY, reg_option, reg_value, reason, regex_engine);

    int returned_value_32 = RETURN_NOT_FOUND;
    if (returned_value_64 != RETURN_FOUND) {
        returned_value_32 = wm_sca_test_key(rk, entry_name, KEY_WOW64_32KEY, reg_option, reg_value, reason, regex_engine);
    }

    int ret_value = RETURN_NOT_FOUND;
    if (returned_value_32 == RETURN_INVALID && returned_value_64 == RETURN_INVALID) {
        ret_value = RETURN_INVALID;
    } else if (returned_value_32 == RETURN_FOUND || returned_value_64 == RETURN_FOUND) {
        ret_value = RETURN_FOUND;
    }

    return ret_value;
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

static int wm_sca_test_key(char * subkey,
                           char * full_key_name,
                           unsigned long arch,
                           char * reg_option,
                           char * reg_value,
                           char ** reason,
                           w_expression_t * regex_engine)
{
    mdebug2("Checking '%s' in the %dBIT subsystem.", full_key_name, arch == KEY_WOW64_64KEY ? 64 : 32);

    HKEY oshkey;
    LSTATUS err = RegOpenKeyEx(wm_sca_sub_tree, subkey, 0, KEY_READ | arch, &oshkey);
    if (err == ERROR_ACCESS_DENIED) {
        if (*reason == NULL) {
            os_malloc(snprintf(NULL, 0, "Access denied for registry '%s'", full_key_name) + 1, *reason);
            sprintf(*reason, "Access denied for registry '%s'", full_key_name);
        }
        merror("Access denied for registry '%s'", full_key_name);
        return RETURN_INVALID;
    } else if (err != ERROR_SUCCESS) {
        char error_msg[OS_SIZE_1024 + 1];
        error_msg[OS_SIZE_1024] = '\0';
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
                    | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                    NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPTSTR) &error_msg, OS_SIZE_1024, NULL);

        mdebug2("Unable to read registry '%s': %s", full_key_name, error_msg);

        /* If registry not found and no key is requested -> return RETURN_NOT_FOUND */
        if (!reg_option) {
            mdebug2("Registry '%s' not found.", full_key_name);
            return RETURN_NOT_FOUND;
        }

        if (*reason == NULL){
            os_malloc(snprintf(NULL, 0, "Unable to read registry '%s' (%s)", full_key_name, error_msg) + 1, *reason);
            sprintf(*reason, "Unable to read registry '%s' (%s)", full_key_name, error_msg);
        }
        return RETURN_INVALID;
    }

    /* If the key does exists, a test for existence succeeds  */
    int ret_val = RETURN_FOUND;

    /* If option is set, set test_result as the value of query key */
    if (reg_option) {
        ret_val = wm_sca_winreg_querykey(oshkey, full_key_name, reg_option, reg_value, reason, regex_engine);
    }

    RegCloseKey(oshkey);

    return ret_val;
}

static int wm_sca_winreg_querykey(HKEY hKey,
                                  const char * full_key_name,
                                  char * reg_option,
                                  char * reg_value,
                                  char ** reason,
                                  w_expression_t * regex_engine)
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
        char error_msg[OS_SIZE_1024 + 1];
        error_msg[OS_SIZE_1024] = '\0';
        FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
                    | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                    NULL, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPTSTR) &error_msg, OS_SIZE_1024, NULL);

        if (*reason == NULL){
            os_malloc(snprintf(NULL, 0, "Unable to read registry '%s' (%s)", full_key_name, error_msg) + 1, *reason);
            sprintf(*reason, "Unable to read registry '%s' (%s)", full_key_name, error_msg);
        }

        mdebug2("Unable to read registry '%s': %s", full_key_name, error_msg);
        return RETURN_INVALID;
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
            if (rc != ERROR_SUCCESS && rc != ERROR_NO_MORE_ITEMS) {
                char error_msg[OS_SIZE_1024 + 1];
                error_msg[OS_SIZE_1024] = '\0';
                FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
                            | FORMAT_MESSAGE_MAX_WIDTH_MASK,
                            NULL, rc, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                            (LPTSTR) &error_msg, OS_SIZE_1024, NULL);

                if (*reason == NULL){
                    os_malloc(snprintf(NULL, 0, "Unable to enumerate values of registry '%s' (%s)", full_key_name, error_msg) + 1, *reason);
                    sprintf(*reason, "Unable to enumerate values of registry '%s' (%s)", full_key_name, error_msg);
                }

                mdebug2("Unable to enumerate values of registry '%s' -> RETURN_INVALID", full_key_name);
                return RETURN_INVALID;
            }

            /* Check if no value name is specified */
            if (value_buffer[0] == '\0') {
                value_buffer[0] = '@';
                value_buffer[1] = '\0';
            }

            /* Check if the entry name matches the reg_option */
            if (strcasecmp(value_buffer, reg_option) != 0) {
                mdebug2("Considering value '%s' -> '%s' != '%s': Skipping value.", full_key_name, value_buffer, reg_option);
                continue;
            }

            mdebug2("Considering value '%s' -> '%s' == '%s': Value found.", full_key_name, value_buffer, reg_option);

            /* If a value is not present and the option matches return found */
            if (!reg_value) {
                mdebug2("No value data especified. Existence check for '%s': 1", full_key_name);
                return RETURN_FOUND;
            }

            /* Write value into a string */
            switch (data_type) {
                int size_available;
                size_t size_data;

                case REG_SZ:
                case REG_EXPAND_SZ:
                    snprintf(var_storage, MAX_VALUE_NAME, "%s", data_buffer);
                    break;
                case REG_MULTI_SZ:
                    /* Printing multiple strings */
                    size_available = MAX_VALUE_NAME;
                    mt_data = data_buffer;

                    while (*mt_data) {
                        size_data = strlen(mt_data) + strlen(" ");

                        if ((size_t)size_available >= size_data) {
                            strncat(var_storage, mt_data, size_available);
                            size_available -= strlen(mt_data);
                            strncat(var_storage, " ", size_available);
                            size_available -= strlen(" ");
                        }
                        mt_data += strlen(mt_data) + 1;
                    }
                    break;
                case REG_DWORD:
                    snprintf(var_storage, MAX_VALUE_NAME, "%u", *((uint32_t*)data_buffer));
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

            mdebug2("Checking value data '%s' with rule '%s'", var_storage, reg_value);

            int result = wm_sca_pattern_matches(var_storage, reg_value, reason, regex_engine);
            return result;
        }
    }

    if (*reason == NULL && reg_value){
        os_malloc(snprintf(NULL, 0, "Key '%s' not found for registry '%s'", reg_option, full_key_name) + 1, *reason);
        sprintf(*reason, "Key '%s' not found for registry '%s'", reg_option, full_key_name);
    }

    return reg_value ? RETURN_INVALID : RETURN_NOT_FOUND;
}
#endif

static int wm_sca_send_summary(wm_sca_t * data, int scan_id,unsigned int passed, unsigned int failed,unsigned int invalid,cJSON *policy,int start_time,int end_time,char * integrity_hash,char *integrity_hash_file, int first_scan,int id,int checks_number) {

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

        if (ref) {
            cJSON_AddStringToObject(json_summary, "references", ref);
        }

        os_free(ref);
    }

    cJSON_AddNumberToObject(json_summary, "passed", passed);
    cJSON_AddNumberToObject(json_summary, "failed", failed);
    cJSON_AddNumberToObject(json_summary, "invalid", invalid);

    float passedf = passed;
    float failedf = failed;
    float score = ((passedf/(failedf+passedf))) * 100;

    if (passed == 0 && failed == 0) {
        score = 0;
    }

    cJSON_AddNumberToObject(json_summary, "total_checks", checks_number);
    cJSON_AddNumberToObject(json_summary, "score", score);

    cJSON_AddNumberToObject(json_summary, "start_time", start_time);
    cJSON_AddNumberToObject(json_summary, "end_time", end_time);

    cJSON_AddStringToObject(json_summary, "hash", integrity_hash);
    cJSON_AddStringToObject(json_summary, "hash_file", integrity_hash_file);

    if (first_scan) {
        cJSON_AddNumberToObject(json_summary, "first_scan", first_scan);
    }

    mdebug1("Sending summary event for file: '%s'", file->valuestring);

    if (last_summary_json[id]) {
        cJSON_Delete(last_summary_json[id]);
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

static cJSON *wm_sca_build_event(const cJSON * const check, const cJSON * const policy, char **p_alert_msg, int id, const char * const result, const char * const reason) {
    cJSON *json_alert = cJSON_CreateObject();
    cJSON_AddStringToObject(json_alert, "type", "check");
    cJSON_AddNumberToObject(json_alert, "id", id);

    cJSON *name = cJSON_GetObjectItem(policy,"name");
    cJSON *policy_id = cJSON_GetObjectItem(policy,"id");
    cJSON_AddStringToObject(json_alert, "policy", name->valuestring);

    cJSON *check_information = cJSON_CreateObject();
    cJSON *pm_id = cJSON_GetObjectItem(check, "id");
    cJSON *title = cJSON_GetObjectItem(check, "title");
    cJSON *description = cJSON_GetObjectItem(check, "description");
    cJSON *rationale = cJSON_GetObjectItem(check, "rationale");
    cJSON *remediation = cJSON_GetObjectItem(check, "remediation");
    cJSON *condition = cJSON_GetObjectItem(check, "condition");
    cJSON *rules = cJSON_GetObjectItem(check, "rules");

    if(!pm_id) {
        mdebug1("No 'id' field found on check.");
        goto error;
    }

    if(!pm_id->valueint) {
        mdebug1("Field 'id' must be a number.");
        goto error;
    }

    cJSON_AddNumberToObject(check_information, "id", pm_id->valueint);

    if(title){
        if(!title->valuestring) {
            mdebug1("Field 'title' must be a string.");
            goto error;
        }
        cJSON_AddStringToObject(check_information, "title", title->valuestring);
    } else {
        mdebug1("No 'title' field found on check '%d'", pm_id->valueint);
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
        cJSON_AddStringToObject(check_information, "description", description->valuestring);
    }

    if(rationale){
        if(!rationale->valuestring) {
            mdebug1("Field 'rationale' must be a string.");
            goto error;
        }
        cJSON_AddStringToObject(check_information, "rationale", rationale->valuestring);
    }

    if(remediation){
        if(!remediation->valuestring) {
            mdebug1("Field 'remediation' must be a string.");
            goto error;
        }
        cJSON_AddStringToObject(check_information, "remediation", remediation->valuestring);
    }

    cJSON *compliances = cJSON_GetObjectItem(check, "compliance");

    if(compliances) {
        cJSON *add_compliances = cJSON_CreateObject();
        cJSON *compliance;

        cJSON_ArrayForEach(compliance, compliances) {

            if (!compliance->child) {
                continue;
            }

            cJSON *policy = cJSON_GetObjectItem(compliance, compliance->child->string);
            cJSON *version;
            char *compliance_value = NULL;
            cJSON_ArrayForEach(version, policy){
                if(!version->valuestring){
                    mwarn("Invalid compliance format in policy: %s (check %d)", policy_id->valuestring, pm_id->valueint);
                    continue;
                }
                wm_strcat(&compliance_value, version->valuestring, ',');
            }

            cJSON_AddStringToObject(add_compliances, compliance->child->string, compliance_value);
            os_free(compliance_value);
        }

        cJSON_AddItemToObject(check_information, "compliance", add_compliances);
    }

    cJSON_AddItemToObject(check_information, "rules", cJSON_Duplicate(rules, 1));

    if(!condition) {
        mdebug1("No 'condition' field found on check.");
        goto error;
    }

    if(!condition->valuestring) {
        mdebug1("Field 'condition' must be a string.");
        goto error;
    }

    cJSON_AddStringToObject(check_information, "condition", condition->valuestring);

    cJSON *references = cJSON_GetObjectItem(check, "references");

    if(references) {
        cJSON *reference;
        char *reference_list = NULL;

        cJSON_ArrayForEach(reference,references)
        {
            if(reference->valuestring){
               wm_strcat(&reference_list, reference->valuestring, ',');
            }
        }

        if (reference_list) {
            cJSON_AddStringToObject(check_information, "references", reference_list);
        }

        os_free(reference_list);
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
        cJSON_AddStringToObject(check_information, "file", final_str_file);
        os_free(final_str_file);
    }

    if(final_str_directory) {
        cJSON_AddStringToObject(check_information, "directory", final_str_directory);
        os_free(final_str_directory);
    }

    if(final_str_process) {
       cJSON_AddStringToObject(check_information, "process", final_str_process);
       os_free(final_str_process);
    }

    if(final_str_registry) {
       cJSON_AddStringToObject(check_information, "registry", final_str_registry);
       os_free(final_str_registry);
    }

    if(final_str_command) {
       cJSON_AddStringToObject(check_information, "command", final_str_command);
       os_free(final_str_command);
    }

    if (!strcmp(result, "")) {
        cJSON_AddStringToObject(check_information, "status", "Not applicable");
        if (reason) {
            cJSON_AddStringToObject(check_information, "reason", reason);
        }
    } else {
        cJSON_AddStringToObject(check_information, "result", result);
    }

    if(!policy_id->valuestring) {
        mdebug1("Field 'id' must be a string.");
        goto error;
    }

    cJSON_AddStringToObject(json_alert, "policy_id", policy_id->valuestring);
    cJSON_AddItemToObject(json_alert, "check", check_information);

    return json_alert;

error:

    if(json_alert){
        cJSON_Delete(json_alert);
    }

    return NULL;
}

static int wm_sca_check_hash(OSHash * const cis_db_hash, const char * const result,
    const cJSON * const check, const cJSON * const event, int check_index,int policy_index)
{
    cis_db_info_t *hashed_result = NULL;
    char id_hashed[OS_SIZE_128];
    int ret_add = 0;
    cJSON *pm_id = cJSON_GetObjectItem(check, "id");
    int alert = 1;

    if(!pm_id) {
        return 0;
    }

    if(!pm_id->valueint) {
        return 0;
    }

    sprintf(id_hashed, "%d", pm_id->valueint);

    hashed_result = OSHash_Get(cis_db_hash, id_hashed);

    cis_db_info_t *elem;
    os_calloc(1, sizeof(cis_db_info_t), elem);

    elem->id = pm_id->valueint;

    if (!result) {
	    os_strdup("",elem->result);
	} else {
	    os_strdup(result,elem->result);
	}

    cJSON *obj = cJSON_Duplicate(event,1);
    elem->event = NULL;

    if(obj) {
        elem->event = obj;

        if (!hashed_result) {
            if (ret_add = OSHash_Add(cis_db_hash,id_hashed,elem), ret_add != 2) {
                merror("Unable to update hash table for check: %d", pm_id->valueint);
                os_free(elem->result);
                cJSON_Delete(elem->event);
                os_free(elem);
                return 0;
            }
        } else {
            if(strcmp(elem->result,hashed_result->result) == 0) {
                alert = 0;
            }

            if (ret_add = OSHash_Update(cis_db_hash,id_hashed,elem), ret_add != 1) {
                merror("Unable to update hash table for check: %d", pm_id->valueint);
                os_free(elem->result);
                cJSON_Delete(elem->event);
                os_free(elem);
                return 0;
            }
        }

        cis_db_for_hash[policy_index].elem[check_index] = elem;
        return alert;

    }

    os_free(elem->result);
    os_free(elem);
    return 0;

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

static int compare_cis_db_info_t_entry(const void * const a, const void * const  b)
{
    const cis_db_info_t * const cis_db_info_t_a = *((const cis_db_info_t ** const) a);
    const cis_db_info_t * const cis_db_info_t_b = *((const cis_db_info_t ** const) b);
    return cis_db_info_t_a->id - cis_db_info_t_b->id;
}

static char *wm_sca_hash_integrity(int policy_index) {
    char *str = NULL;


    int check_count = 0;
    int i;
    for(i = 0; cis_db_for_hash[policy_index].elem[i]; ++i) {
        ++check_count;
    }

    if (check_count) {
        qsort(cis_db_for_hash[policy_index].elem, check_count, sizeof(struct cis_db_info_t *), compare_cis_db_info_t_entry);
    }

    mdebug2("Concatenating check results:");
    for(i = 0; cis_db_for_hash[policy_index].elem[i]; i++) {
        const cis_db_info_t * const event = cis_db_for_hash[policy_index].elem[i];
        mdebug2("ID: %d; Result: '%s'", event->id, event->result);
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

char *wm_sca_hash_integrity_file(const char *file) {

    char *hash_file = NULL;
    os_malloc(65*sizeof(char), hash_file);

    if(OS_SHA256_File(file, hash_file, OS_TEXT) != 0){
        merror("Unable to calculate SHA256 for file '%s'", file);
        os_free(hash_file);
        return NULL;
    }

    return hash_file;
}

#ifdef WIN32
static DWORD WINAPI wm_sca_dump_db_thread(wm_sca_t * data) {
#else
static void *wm_sca_dump_db_thread(wm_sca_t * data) {
#endif
    int i;

    while(1) {
        request_dump_t *request;

        if (request = queue_pop_ex(request_queue), request) {

#ifndef WIN32
            int random = os_random();
            if (random < 0) {
                random = -random;
            }
#else
            unsigned int random1 = os_random();
            unsigned int random2 = os_random();

            char random_id[OS_MAXSTR];
            snprintf(random_id, OS_MAXSTR - 1, "%u%u", random1, random2);

            int random = atoi(random_id);
            if (random < 0) {
                random = -random;
            }
#endif
            random = random % data->request_db_interval;

            if(random == 0) {
                random += 5;
            }

            unsigned int time = random;

            if (request->first_scan) {
                w_time_delay(2000);
                mdebug1("Sending first scan results for policy '%s'", data->policies[request->policy_index]->policy_path);
            } else {
                minfo("Integration checksum failed for policy '%s'. Resending scan results in %d seconds.",
                    data->policies[request->policy_index]->policy_path, random);
                w_time_delay(1000 * time);
            }

            mdebug1("Dumping results to SCA DB for policy '%s' (Policy index: %u)",
                    data->policies[request->policy_index]->policy_path, request->policy_index);

            int scan_id = -1;
            w_rwlock_wrlock(&dump_rwlock);

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

            w_time_delay(5000);

            int elements_sent = i;
            mdebug1("Sending end of dump control event.");

            wm_sca_send_dump_end(data,elements_sent,data->policies[request->policy_index]->policy_id,scan_id);

            w_time_delay(2000);

            /* Send summary only for first scan */
            if (request->first_scan) {
                /* Send summary */
                cJSON_DeleteItemFromObject(last_summary_json[request->policy_index],"first_scan");
                /* Force alert */
                cJSON_AddStringToObject(last_summary_json[request->policy_index], "force_alert", "1");

                wm_sca_send_alert(data,last_summary_json[request->policy_index]);
            }

            mdebug1("Finished dumping scan results to SCA DB for policy '%s' (%u) (%d)",
                data->policies[request->policy_index]->policy_id,
                request->policy_index,
                request->first_scan);

            w_rwlock_unlock(&dump_rwlock);
            os_free(request);
        }
    }

#ifndef WIN32
    return NULL;
#endif
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
            mdebug1("First scan flag missing.");
            return;
        }

        *first_scan++ = '\0';

        /* Search DB */
        int i;

        if(data_win) {
            for(i = 0; data_win->policies[i]; i++) {
                if(!data_win->policies[i]->enabled){
                    continue;
                }

                if(data_win->policies[i]->policy_id) {
                    char *endl;

                    endl = strchr(db,'\n');

                    if(endl){
                        *endl = '\0';
                    }

                    if(strcmp(data_win->policies[i]->policy_id,db) == 0){
                        request_dump_t *request;
                        os_calloc(1, sizeof(request_dump_t),request);

                        request->policy_index = i;
                        request->first_scan = atoi(first_scan);

                        if(queue_push_ex(request_queue,request) < 0) {
                            os_free(request);
                            mdebug1("Could not push policy index to queue.");
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
    if ((cfga_queue = StartMQWithSpecificOwnerAndPerms(CFGAQUEUE, READ, 0, getuid(), wm_getGroupID(), 0660)) < 0) {
        merror(QUEUE_ERROR, CFGAQUEUE, strerror(errno));
        pthread_exit(NULL);
    }

    int recv = 0;
    char *buffer = NULL;

    /* For he who seeks The Leak in here:
        This buffer is going to report a leak whenever the process dies, as this function never returns
        and its buffer is never released. Also, any forks() comming from the process that's started this
        thread will report a leak here, as the leak has been inherited from the parent.

        But rest assured, if the fork dies the memory is recalled by the OS.
    */
    os_calloc(OS_MAXSTR + 1, sizeof(char), buffer);

    while (1) {
        if (recv = OS_RecvUnix(cfga_queue, OS_MAXSTR, buffer),recv) {
            buffer[recv] = '\0';

            char *db = strchr(buffer,':');

            if(!strncmp(buffer,WM_CONFIGURATION_ASSESSMENT_DB_DUMP,strlen(WM_CONFIGURATION_ASSESSMENT_DB_DUMP)) && db) {

                *db++ = '\0';

                /* Check for first scan */
                char *first_scan = strchr(db,':');

                if (!first_scan) {
                    mdebug1("First scan flag missing.");
                    continue;
                }

                *first_scan++ = '\0';

                /* Search DB */
                int i;
                for(i = 0; data->policies[i]; i++) {
                    if(!data->policies[i]->enabled){
                        continue;
                    }

                    if(data->policies[i]->policy_id) {
                        char *endl;

                        endl = strchr(db,'\n');

                        if(endl){
                            *endl = '\0';
                        }

                        if(strcmp(data->policies[i]->policy_id,db) == 0){
                            request_dump_t *request;
                            os_calloc(1, sizeof(request_dump_t),request);

                            request->policy_index = i;
                            request->first_scan = atoi(first_scan);

                            if(queue_push_ex(request_queue,request) < 0) {
                                os_free(request);
                                mdebug1("Could not push policy index to queue.");
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    os_free(buffer);
    return NULL;
}
#endif
static void wm_sca_summary_increment_passed() {
    summary_passed++;
}

static void wm_sca_summary_increment_failed() {
    summary_failed++;
}

static void wm_sca_summary_increment_invalid() {
    summary_invalid++;
}

static void wm_sca_reset_summary() {
    summary_failed = 0;
    summary_passed = 0;
    summary_invalid = 0;
}

cJSON *wm_sca_dump(const wm_sca_t *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    sched_scan_dump(&(data->scan_config), wm_wd);

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "scan_on_start", data->scan_on_start ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "skip_nfs", data->skip_nfs ? "yes" : "no");

    if (data->policies && *data->policies) {
        cJSON *policies = cJSON_CreateArray();
        int i;
        for (i=0;data->policies[i];i++) {
            if(data->policies[i]->enabled == 1){
                cJSON_AddStringToObject(policies, "policy", data->policies[i]->policy_path);
            }
        }
        cJSON_AddItemToObject(wm_wd,"policies", policies);
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

/* Sort the variables from largest to smallest in size */
char **wm_sort_variables(const cJSON * const variables) {
    char **variables_array;
    const cJSON *variable;
    char *aux;
    int i = 0;
    int variables_array_size = cJSON_GetArraySize(variables);

    if (variables == NULL || variables_array_size == 0) {
        return NULL;
    }

    os_calloc(variables_array_size + 1, sizeof(char *), variables_array);

    // Fill array with unsorted variables
    cJSON_ArrayForEach(variable, variables) {
        os_strdup(variable->string, variables_array[i]);
        i++;
    }

    // variables_array_size and i should always be the same
    if (variables_array_size != i) {
        free_strarray(variables_array);
        return NULL;
    }

    // Sorting algorithm
    for(i = 0; i < variables_array_size; i++) {
        for(int j = i + 1; j < variables_array_size; j++) {
            if(strlen(variables_array[j]) > strlen(variables_array[i])) {
                aux = variables_array[i];
                variables_array[i] = variables_array[j];
                variables_array[j] = aux;
            }
        }
    }

    return variables_array;
}
