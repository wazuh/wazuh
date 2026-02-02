/*
 * Wazuh Module for AWS S3 integration
 * Copyright (C) 2015, Wazuh Inc.
 * January 08, 2018.
 *
 * Updated by Jeremy Phillips <jeremy@uranusbytes.com>
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static
#endif

static wm_aws *aws_config;                              // Pointer to aws_configuration
#ifdef WIN32
static DWORD WINAPI wm_aws_main(void *arg);             // Module main function. It won't return
#else
static void* wm_aws_main(wm_aws *aws_config);           // Module main function. It won't return
#endif
static void wm_aws_destroy(wm_aws *aws_config);         // Destroy data
static void wm_aws_setup(wm_aws *_aws_config);          // Setup module
static void wm_aws_check();                             // Check configuration, disable flag
static void wm_aws_run_s3(wm_aws *aws_config, wm_aws_bucket *bucket);       // Run a s3 bucket
static void wm_aws_run_service(wm_aws *aws_config, wm_aws_service *service);// Run a AWS service such as Inspector
static void wm_aws_run_subscriber(wm_aws *aws_config, wm_aws_subscriber *subscriber); //Run an AWS subscriber
cJSON *wm_aws_dump(const wm_aws *aws_config);

// Command module context definition

const wm_context WM_AWS_CONTEXT = {
    .name = "aws-s3",
    .start = (wm_routine)wm_aws_main,
    .destroy = (void(*)(void *))wm_aws_destroy,
    .dump = (cJSON * (*)(const void *))wm_aws_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

// Module module main function. It won't return.
#ifdef WIN32
DWORD WINAPI wm_aws_main(void *arg) {
    wm_aws *aws_config = (wm_aws *)arg;
#else
void* wm_aws_main(wm_aws *aws_config) {
#endif
    wm_aws_bucket *cur_bucket;
    wm_aws_service *cur_service;
    wm_aws_subscriber *cur_subscriber;
    char *log_info;
    char * timestamp = NULL;


    wm_aws_setup(aws_config);
    mtinfo(WM_AWS_LOGTAG, "Module AWS started");

    // Main loop

    do {

        const time_t time_sleep = sched_scan_get_time_until_next_scan(&(aws_config->scan_config), WM_AWS_LOGTAG, aws_config->run_on_start);

        if (aws_config->state.next_time == 0) {
            aws_config->state.next_time = aws_config->scan_config.time_start + time_sleep;
        }

        if (wm_state_io(WM_AWS_CONTEXT.name, WM_IO_WRITE, &aws_config->state, sizeof(aws_config->state)) < 0)
            mterror(WM_AWS_LOGTAG, "Couldn't save running state.");

        if (time_sleep) {
            const int next_scan_time = sched_get_next_scan_time(aws_config->scan_config);
            timestamp = w_get_timestamp(next_scan_time);
            mtdebug2(WM_AWS_LOGTAG, "Sleeping until: %s", timestamp);
            os_free(timestamp);
            w_sleep_until(next_scan_time);
        }
        mtinfo(WM_AWS_LOGTAG, "Starting fetching of logs.");

        for (cur_bucket = aws_config->buckets; cur_bucket; cur_bucket = cur_bucket->next) {

            log_info = NULL;

            wm_strcat(&log_info, "Executing Bucket Analysis: (Bucket:", '\0');
            if (cur_bucket->bucket) {
                wm_strcat(&log_info, cur_bucket->bucket, ' ');
            }
            else {
                wm_strcat(&log_info, "unknown_bucket", ' ');
            }


            if (cur_bucket->trail_prefix) {
                wm_strcat(&log_info, ", Path:", '\0');
                wm_strcat(&log_info, cur_bucket->trail_prefix, ' ');
            }

            if (cur_bucket->trail_suffix) {
                wm_strcat(&log_info, ", Path suffix:", '\0');
                wm_strcat(&log_info, cur_bucket->trail_suffix, ' ');
            }

            if (cur_bucket->type) {
                wm_strcat(&log_info, ", Type:", '\0');
                wm_strcat(&log_info, cur_bucket->type, ' ');
            }

            if (cur_bucket->aws_account_id) {
                wm_strcat(&log_info, ", Account ID:", '\0');
                wm_strcat(&log_info, cur_bucket->aws_account_id, ' ');
            }

            if (cur_bucket->aws_account_alias) {
                wm_strcat(&log_info, ", Account Alias:", '\0');
                wm_strcat(&log_info, cur_bucket->aws_account_alias, ' ');
            }

            if (cur_bucket->aws_organization_id) {
                wm_strcat(&log_info, ", Organization ID:", '\0');
                wm_strcat(&log_info, cur_bucket->aws_organization_id, ' ');
            }

            if (cur_bucket->aws_profile) {
                wm_strcat(&log_info, ", Profile:", '\0');
                wm_strcat(&log_info, cur_bucket->aws_profile, ' ');
            }

            wm_strcat(&log_info, ")", '\0');

            mtinfo(WM_AWS_LOGTAG, "%s", log_info);
            wm_aws_run_s3(aws_config, cur_bucket);
            free(log_info);
        }

        for (cur_service = aws_config->services; cur_service; cur_service = cur_service->next) {

            log_info = NULL;

            wm_strcat(&log_info, "Executing Service Analysis: (Service:", '\0');
            if (cur_service->type) {
                wm_strcat(&log_info, cur_service->type, ' ');
            }
            else {
                wm_strcat(&log_info, "unknown_type", ' ');
            }


            if (cur_service->aws_account_id) {
                wm_strcat(&log_info, ", Account ID:", '\0');
                wm_strcat(&log_info, cur_service->aws_account_id, ' ');
            }

            if (cur_service->aws_account_alias) {
                wm_strcat(&log_info, ", Account Alias:", '\0');
                wm_strcat(&log_info, cur_service->aws_account_alias, ' ');
            }

            if (cur_service->aws_profile) {
                wm_strcat(&log_info, ", Profile:", '\0');
                wm_strcat(&log_info, cur_service->aws_profile, ' ');
            }

            wm_strcat(&log_info, ")", '\0');

            mtinfo(WM_AWS_LOGTAG, "%s", log_info);
            wm_aws_run_service(aws_config, cur_service);
            free(log_info);
        }

        for (cur_subscriber = aws_config->subscribers; cur_subscriber; cur_subscriber = cur_subscriber->next) {
            log_info = NULL;

            wm_strcat(&log_info, "Executing Subscriber fetch: (Type and SQS:", '\0');
            if (cur_subscriber->type) {
                wm_strcat(&log_info, cur_subscriber->type, ' ');
            }
            else {
                wm_strcat(&log_info, "unknown_type", ' ');
            }

            if (cur_subscriber->sqs_name) {
                wm_strcat(&log_info, cur_subscriber->sqs_name, ' ');
            }
            else {
                wm_strcat(&log_info, "unknown_queue", ' ');
            }

            wm_strcat(&log_info, ")", '\0');

            mtinfo(WM_AWS_LOGTAG, "%s", log_info);
            wm_aws_run_subscriber(aws_config, cur_subscriber);
            free(log_info);
        }

        mtinfo(WM_AWS_LOGTAG, "Fetching logs finished.");

    } while (FOREVER());

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}


// Get read data

cJSON *wm_aws_dump(const wm_aws *aws_config) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_aws = cJSON_CreateObject();

    sched_scan_dump(&(aws_config->scan_config), wm_aws);

    if (aws_config->enabled) cJSON_AddStringToObject(wm_aws,"disabled","no"); else cJSON_AddStringToObject(wm_aws,"disabled","yes");
    if (aws_config->run_on_start) cJSON_AddStringToObject(wm_aws,"run_on_start","yes"); else cJSON_AddStringToObject(wm_aws,"run_on_start","no");
    if (aws_config->skip_on_error) cJSON_AddStringToObject(wm_aws,"skip_on_error","yes"); else cJSON_AddStringToObject(wm_aws,"skip_on_error","no");
    if (aws_config->buckets) {
        wm_aws_bucket *iter;
        cJSON *arr_buckets = cJSON_CreateArray();
        for (iter = aws_config->buckets; iter; iter = iter->next) {
            cJSON *buck = cJSON_CreateObject();
            if (iter->bucket) cJSON_AddStringToObject(buck,"name",iter->bucket);
            if (iter->access_key) cJSON_AddStringToObject(buck,"access_key",iter->access_key);
            if (iter->secret_key) cJSON_AddStringToObject(buck,"secret_key",iter->secret_key);
            if (iter->aws_profile) cJSON_AddStringToObject(buck,"aws_profile",iter->aws_profile);
            if (iter->iam_role_arn) cJSON_AddStringToObject(buck,"iam_role_arn",iter->iam_role_arn);
            if (iter->iam_role_duration) cJSON_AddStringToObject(buck, "iam_role_duration",iter->iam_role_duration);
            if (iter->aws_account_id) cJSON_AddStringToObject(buck,"aws_account_id",iter->aws_account_id);
            if (iter->aws_account_alias) cJSON_AddStringToObject(buck,"aws_account_alias",iter->aws_account_alias);
            if (iter->trail_prefix) cJSON_AddStringToObject(buck,"path",iter->trail_prefix);
            if (iter->trail_suffix) cJSON_AddStringToObject(buck,"path_suffix",iter->trail_suffix);
            if (iter->only_logs_after) cJSON_AddStringToObject(buck,"only_logs_after",iter->only_logs_after);
            if (iter->regions) cJSON_AddStringToObject(buck,"regions",iter->regions);
            if (iter->type) cJSON_AddStringToObject(buck,"type",iter->type);
            if (iter->remove_from_bucket) cJSON_AddStringToObject(buck,"remove_from_bucket","yes"); else cJSON_AddStringToObject(buck,"remove_from_bucket","no");
            if (iter->discard_field) cJSON_AddStringToObject(buck,"discard_field",iter->discard_field);
            if (iter->discard_regex) cJSON_AddStringToObject(buck,"discard_regex",iter->discard_regex);
            if (iter->sts_endpoint) cJSON_AddStringToObject(buck,"sts_endpoint",iter->sts_endpoint);
            if (iter->service_endpoint) cJSON_AddStringToObject(buck,"service_endpoint",iter->service_endpoint);
            cJSON_AddItemToArray(arr_buckets,buck);
        }
        if (cJSON_GetArraySize(arr_buckets) > 0) {
            cJSON_AddItemToObject(wm_aws,"buckets",arr_buckets);
        } else {
            cJSON_free(arr_buckets);
        }
    }
    if (aws_config->services) {
        wm_aws_service *iter;
        cJSON *arr_services = cJSON_CreateArray();
        for (iter = aws_config->services; iter; iter = iter->next) {
            cJSON *service = cJSON_CreateObject();
            if (iter->type) cJSON_AddStringToObject(service,"type",iter->type); // type is the name of the service
            if (iter->access_key) cJSON_AddStringToObject(service,"access_key",iter->access_key);
            if (iter->secret_key) cJSON_AddStringToObject(service,"secret_key",iter->secret_key);
            if (iter->aws_profile) cJSON_AddStringToObject(service,"aws_profile",iter->aws_profile);
            if (iter->iam_role_arn) cJSON_AddStringToObject(service,"iam_role_arn",iter->iam_role_arn);
            if (iter->iam_role_duration) cJSON_AddStringToObject(service, "iam_role_duration",iter->iam_role_duration);
            if (iter->aws_account_id) cJSON_AddStringToObject(service,"aws_account_id",iter->aws_account_id);
            if (iter->aws_account_alias) cJSON_AddStringToObject(service,"aws_account_alias",iter->aws_account_alias);
            if (iter->only_logs_after) cJSON_AddStringToObject(service,"only_logs_after",iter->only_logs_after);
            if (iter->regions) cJSON_AddStringToObject(service,"regions",iter->regions);
            if (iter->aws_log_groups) cJSON_AddStringToObject(service,"aws_log_groups",iter->aws_log_groups);
            if (iter->remove_log_streams) cJSON_AddStringToObject(service,"remove_log_streams","yes"); else cJSON_AddStringToObject(service,"remove_log_streams","no");
            if (iter->discard_field) cJSON_AddStringToObject(service,"discard_field",iter->discard_field);
            if (iter->discard_regex) cJSON_AddStringToObject(service,"discard_regex",iter->discard_regex);
            if (iter->sts_endpoint) cJSON_AddStringToObject(service,"sts_endpoint",iter->sts_endpoint);
            if (iter->service_endpoint) cJSON_AddStringToObject(service,"service_endpoint",iter->service_endpoint);
            cJSON_AddItemToArray(arr_services,service);
        }
        if (cJSON_GetArraySize(arr_services) > 0) {
            cJSON_AddItemToObject(wm_aws,"services",arr_services);
        } else {
            cJSON_free(arr_services);
        }
    }
    if (aws_config->subscribers) {
    wm_aws_subscriber *iter;
        cJSON *arr_subscribers = cJSON_CreateArray();
        for (iter = aws_config->subscribers; iter; iter = iter->next) {
            cJSON *subscriber = cJSON_CreateObject();
            if (iter->type) cJSON_AddStringToObject(subscriber,"type",iter->type);
            if (iter->sqs_name) cJSON_AddStringToObject(subscriber,"sqs_name",iter->sqs_name);
            if (iter->external_id) cJSON_AddStringToObject(subscriber,"external_id",iter->external_id);
            if (iter->iam_role_arn) cJSON_AddStringToObject(subscriber,"iam_role_arn",iter->iam_role_arn);
            if (iter->iam_role_duration) cJSON_AddStringToObject(subscriber, "iam_role_duration",iter->iam_role_duration);
            if (iter->aws_profile) cJSON_AddStringToObject(subscriber,"aws_profile",iter->aws_profile);
            if (iter->sts_endpoint) cJSON_AddStringToObject(subscriber,"sts_endpoint",iter->sts_endpoint);
            if (iter->service_endpoint) cJSON_AddStringToObject(subscriber,"service_endpoint",iter->service_endpoint);
            if (iter->discard_field) cJSON_AddStringToObject(subscriber,"discard_field",iter->discard_field);
            if (iter->discard_regex) cJSON_AddStringToObject(subscriber,"discard_regex",iter->discard_regex);
            cJSON_AddItemToArray(arr_subscribers,subscriber);
        }
        if (cJSON_GetArraySize(arr_subscribers) > 0) {
            cJSON_AddItemToObject(wm_aws,"subscribers",arr_subscribers);
        } else {
            cJSON_free(arr_subscribers);
        }
    }
    cJSON_AddItemToObject(root,"aws-s3",wm_aws);

    return root;
}


// Destroy data
void wm_aws_destroy(wm_aws *aws_config) {
    free(aws_config);
}

// Setup module

void wm_aws_setup(wm_aws *_aws_config) {

    aws_config = _aws_config;
    wm_aws_check();

    // Read running state

    if (wm_state_io(WM_AWS_CONTEXT.name, WM_IO_READ, &aws_config->state, sizeof(aws_config->state)) < 0)
        memset(&aws_config->state, 0, sizeof(aws_config->state));

    // Connect to socket

    aws_config->queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (aws_config->queue_fd < 0) {
        mterror(WM_AWS_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }
}


// Check configuration

void wm_aws_check() {
    // Check if disabled

    if (!aws_config->enabled) {
        mtinfo(WM_AWS_LOGTAG, "Module AWS is disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check if there are buckets or services

    if (!aws_config->buckets && !aws_config->services && !aws_config->subscribers) {
        mtwarn(WM_AWS_LOGTAG, "No AWS buckets, services or subscribers defined. Exiting...");
        pthread_exit(NULL);
    }

    // Check if interval defined; otherwise set default

    if (!aws_config->scan_config.interval)
        aws_config->scan_config.interval = WM_AWS_DEFAULT_INTERVAL;

}

// Run a bucket parsing
#ifdef WAZUH_UNIT_TESTING
__attribute__((weak))
#endif
void wm_aws_run_s3(wm_aws *aws_config, wm_aws_bucket *exec_bucket) {
    int status;
    char *output = NULL;
    char *command = NULL;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Create arguments
    mtdebug2(WM_AWS_LOGTAG, "Create argument list");

    // script path
    char * script = NULL;
    os_calloc(PATH_MAX, sizeof(char), script);

    snprintf(script, PATH_MAX, "%s", WM_AWS_SCRIPT_PATH);

    wm_strcat(&command, script, '\0');
    os_free(script);

    // bucket
    wm_strcat(&command, "--bucket", ' ');
    wm_strcat(&command, exec_bucket->bucket, ' ');

    // bucket arguments
    if (exec_bucket->remove_from_bucket) {
        wm_strcat(&command, "--remove", ' ');
    }
    if (exec_bucket->access_key) {
        wm_strcat(&command, "--access_key", ' ');
        wm_strcat(&command, exec_bucket->access_key, ' ');
    }
    if (exec_bucket->secret_key) {
        wm_strcat(&command, "--secret_key", ' ');
        wm_strcat(&command, exec_bucket->secret_key, ' ');
    }
    if (exec_bucket->aws_profile) {
        wm_strcat(&command, "--aws_profile", ' ');
        wm_strcat(&command, exec_bucket->aws_profile, ' ');
    }
    if (exec_bucket->iam_role_arn) {
        wm_strcat(&command, "--iam_role_arn", ' ');
        wm_strcat(&command, exec_bucket->iam_role_arn, ' ');
    }
    if (exec_bucket->iam_role_duration){
        wm_strcat(&command, "--iam_role_duration", ' ');
        wm_strcat(&command, exec_bucket->iam_role_duration, ' ');
    }
    if (exec_bucket->aws_organization_id) {
        wm_strcat(&command, "--aws_organization_id", ' ');
        wm_strcat(&command, exec_bucket->aws_organization_id, ' ');
    }
    if (exec_bucket->aws_account_id) {
        wm_strcat(&command, "--aws_account_id", ' ');
        wm_strcat(&command, exec_bucket->aws_account_id, ' ');
    }
    if (exec_bucket->aws_account_alias) {
        wm_strcat(&command, "--aws_account_alias", ' ');
        wm_strcat(&command, exec_bucket->aws_account_alias, ' ');
    }
    if (exec_bucket->trail_prefix) {
        wm_strcat(&command, "--trail_prefix", ' ');
        wm_strcat(&command, exec_bucket->trail_prefix, ' ');
    }
    if (exec_bucket->trail_suffix) {
        wm_strcat(&command, "--trail_suffix", ' ');
        wm_strcat(&command, exec_bucket->trail_suffix, ' ');
    }
    if (exec_bucket->only_logs_after) {
        wm_strcat(&command, "--only_logs_after", ' ');
        wm_strcat(&command, exec_bucket->only_logs_after, ' ');
    }
    if (exec_bucket->regions) {
        wm_strcat(&command, "--regions", ' ');
        wm_strcat(&command, exec_bucket->regions, ' ');
    }
    if (exec_bucket->discard_field) {
        wm_strcat(&command, "--discard-field", ' ');
        wm_strcat(&command, exec_bucket->discard_field, ' ');
    }
    if (exec_bucket->discard_regex) {
        wm_strcat(&command, "--discard-regex", ' ');
        wm_strcat(&command, exec_bucket->discard_regex, ' ');
    }
    if (exec_bucket->sts_endpoint) {
        wm_strcat(&command, "--sts_endpoint", ' ');
        wm_strcat(&command, exec_bucket->sts_endpoint, ' ');
    }
    if (exec_bucket->service_endpoint) {
        wm_strcat(&command, "--service_endpoint", ' ');
        wm_strcat(&command, exec_bucket->service_endpoint, ' ');
    }
    if (exec_bucket->type) {
        wm_strcat(&command, "--type", ' ');
        wm_strcat(&command, exec_bucket->type, ' ');
    }
    if (isDebug()) {
        wm_strcat(&command, "--debug", ' ');
        if (isDebug() > 2) {
            wm_strcat(&command, "3", ' ');
        } else if (isDebug() > 1) {
            wm_strcat(&command, "2", ' ');
        } else {
            wm_strcat(&command, "1", ' ');
        }
    }
    if (aws_config->skip_on_error) {
        wm_strcat(&command, "--skip_on_error", ' ');
    }
    if (wm_state_io(WM_AWS_CONTEXT.name, WM_IO_READ, &aws_config->state, sizeof(aws_config->state)) < 0) {
        memset(&aws_config->state, 0, sizeof(aws_config->state));
    }

    // Execute
    char *trail_title = NULL;
    wm_strcat(&trail_title, "Bucket:", ' ');
    wm_strcat(&trail_title, exec_bucket->aws_account_id, ' ');
    if(exec_bucket->aws_account_alias){
        wm_strcat(&trail_title, "(", '\0');
        wm_strcat(&trail_title, exec_bucket->aws_account_alias, '\0');
        wm_strcat(&trail_title, ")", '\0');
    }
    wm_strcat(&trail_title, " - ", ' ');

    mtdebug1(WM_AWS_LOGTAG, "Launching S3 Command: %s", command);

    const int wm_exec_ret_code = wm_exec(command, &output, &status, 0, NULL);

    os_free(command);

    if (wm_exec_ret_code != 0){
        mterror(WM_AWS_LOGTAG, "Internal error. Exiting...");
        os_free(trail_title);
        if (wm_exec_ret_code > 0) {
            os_free(output);
        }
        pthread_exit(NULL);
    } else if (status > 0) {
        mtwarn(WM_AWS_LOGTAG, "%s Returned exit code %d", trail_title, status);
        if(status == 1) {
            char * unknown_error_msg = strstr(output,"Unknown error");
            if (unknown_error_msg == NULL)
                mtwarn(WM_AWS_LOGTAG, "%s Unknown error.", trail_title);
            else
                mtwarn(WM_AWS_LOGTAG, "%s %s", trail_title, unknown_error_msg);
        } else if(status == 2) {
            char * ptr;
            if (ptr = strstr(output, "aws.py: error:"), ptr) {
                ptr += 14;
                mtwarn(WM_AWS_LOGTAG, "%s Error parsing arguments: %s", trail_title, ptr);
            } else {
                mtwarn(WM_AWS_LOGTAG, "%s Error parsing arguments.", trail_title);
            }
        } else {
            char * ptr;
            if (ptr = strstr(output, "ERROR: "), ptr) {
                ptr += 7;
                mtwarn(WM_AWS_LOGTAG, "%s %s", trail_title, ptr);
            } else {
                mtwarn(WM_AWS_LOGTAG, "%s %s", trail_title, output);
            }
        }
        mtdebug1(WM_AWS_LOGTAG, "%s OUTPUT: %s", trail_title, output);
    } else {
        mtdebug2(WM_AWS_LOGTAG, "%s OUTPUT: %s", trail_title, output);
    }

    char *line;
    char *save_ptr = NULL;
    for (line = strtok_r(output, "\n", &save_ptr); line; line = strtok_r(NULL, "\n", &save_ptr)) {
        wm_sendmsg(usec, aws_config->queue_fd, line, WM_AWS_CONTEXT.name, LOCALFILE_MQ);
    }

    os_free(trail_title);
    os_free(output);
}

// Run a service parsing

void wm_aws_run_service(wm_aws *aws_config, wm_aws_service *exec_service) {
    int status;
    char *output = NULL;
    char *command = NULL;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Create arguments
    mtdebug2(WM_AWS_LOGTAG, "Create argument list");

    // script path
    char * script = NULL;
    os_calloc(PATH_MAX, sizeof(char), script);

    snprintf(script, PATH_MAX, "%s", WM_AWS_SCRIPT_PATH);

    wm_strcat(&command, script, '\0');
    os_free(script);

    // service
    wm_strcat(&command, "--service", ' ');
    wm_strcat(&command, exec_service->type, ' ');

    // service arguments
    if (exec_service->access_key) {
        wm_strcat(&command, "--access_key", ' ');
        wm_strcat(&command, exec_service->access_key, ' ');
    }
    if (exec_service->secret_key) {
        wm_strcat(&command, "--secret_key", ' ');
        wm_strcat(&command, exec_service->secret_key, ' ');
    }
    if (exec_service->aws_profile) {
        wm_strcat(&command, "--aws_profile", ' ');
        wm_strcat(&command, exec_service->aws_profile, ' ');
    }
    if (exec_service->iam_role_arn) {
        wm_strcat(&command, "--iam_role_arn", ' ');
        wm_strcat(&command, exec_service->iam_role_arn, ' ');
    }
    if (exec_service->iam_role_duration){
        wm_strcat(&command, "--iam_role_duration", ' ');
        wm_strcat(&command, exec_service->iam_role_duration, ' ');
    }
    if (exec_service->aws_account_id) {
        wm_strcat(&command, "--aws_account_id", ' ');
        wm_strcat(&command, exec_service->aws_account_id, ' ');
    }
    if (exec_service->aws_account_alias) {
        wm_strcat(&command, "--aws_account_alias", ' ');
        wm_strcat(&command, exec_service->aws_account_alias, ' ');
    }
    if (exec_service->only_logs_after) {
        wm_strcat(&command, "--only_logs_after", ' ');
        wm_strcat(&command, exec_service->only_logs_after, ' ');
    }
    if (exec_service->regions) {
        wm_strcat(&command, "--regions", ' ');
        wm_strcat(&command, exec_service->regions, ' ');
    }
    if (exec_service->aws_log_groups) {
        wm_strcat(&command, "--aws_log_groups", ' ');
        wm_strcat(&command, exec_service->aws_log_groups, ' ');
    }
    if (exec_service->remove_log_streams) {
        wm_strcat(&command, "--remove-log-streams", ' ');
    }
    if (exec_service->discard_field) {
        wm_strcat(&command, "--discard-field", ' ');
        wm_strcat(&command, exec_service->discard_field, ' ');
    }
    if (exec_service->discard_regex) {
        wm_strcat(&command, "--discard-regex", ' ');
        wm_strcat(&command, exec_service->discard_regex, ' ');
    }
    if (exec_service->sts_endpoint) {
        wm_strcat(&command, "--sts_endpoint", ' ');
        wm_strcat(&command, exec_service->sts_endpoint, ' ');
    }
    if (exec_service->service_endpoint) {
        wm_strcat(&command, "--service_endpoint", ' ');
        wm_strcat(&command, exec_service->service_endpoint, ' ');
    }
    if (isDebug()) {
        wm_strcat(&command, "--debug", ' ');
        if (isDebug() > 2) {
            wm_strcat(&command, "3", ' ');
        } else if (isDebug() > 1) {
            wm_strcat(&command, "2", ' ');
        } else {
            wm_strcat(&command, "1", ' ');
        }
    }
    if (aws_config->skip_on_error) {
        wm_strcat(&command, "--skip_on_error", ' ');
    }
    if (wm_state_io(WM_AWS_CONTEXT.name, WM_IO_READ, &aws_config->state, sizeof(aws_config->state)) < 0) {
        memset(&aws_config->state, 0, sizeof(aws_config->state));
    }

    // Execute
    char *service_title = NULL;
    wm_strcat(&service_title, "Service:", ' ');
    wm_strcat(&service_title, exec_service->type, ' ');
    wm_strcat(&service_title, exec_service->aws_account_id, ' ');
    if(exec_service->aws_account_alias){
        wm_strcat(&service_title, "(", '\0');
        wm_strcat(&service_title, exec_service->aws_account_alias, '\0');
        wm_strcat(&service_title, ")", '\0');
    }
    wm_strcat(&service_title, " - ", ' ');

    mtdebug1(WM_AWS_LOGTAG, "Launching S3 Command: %s", command);

    const int wm_exec_ret_code = wm_exec(command, &output, &status, 0, NULL);

    os_free(command);

    if (wm_exec_ret_code) {
        mterror(WM_AWS_LOGTAG, "Internal error. Exiting...");
        os_free(service_title);

        if (wm_exec_ret_code > 0) {
            os_free(output);
        }
        pthread_exit(NULL);
    } else if (status > 0) {
        mtwarn(WM_AWS_LOGTAG, "%s Returned exit code %d", service_title, status);
        if(status == 1) {
            char * unknown_error_msg = strstr(output,"Unknown error");
            if (unknown_error_msg == NULL)
                mtwarn(WM_AWS_LOGTAG, "%s Unknown error.", service_title);
            else
                mtwarn(WM_AWS_LOGTAG, "%s %s", service_title, unknown_error_msg);
        } else if(status == 2) {
            char * ptr;
            if (ptr = strstr(output, "aws.py: error:"), ptr) {
                ptr += 14;
                mtwarn(WM_AWS_LOGTAG, "%s Error parsing arguments: %s", service_title, ptr);
            } else {
                mtwarn(WM_AWS_LOGTAG, "%s Error parsing arguments.", service_title);
            }
        } else {
            char * ptr;
            if (ptr = strstr(output, "ERROR: "), ptr) {
                ptr += 7;
                mtwarn(WM_AWS_LOGTAG, "%s %s", service_title, ptr);
            } else {
                mtwarn(WM_AWS_LOGTAG, "%s %s", service_title, output);
            }
        }
        mtdebug1(WM_AWS_LOGTAG, "%s OUTPUT: %s", service_title, output);
    } else {
        mtdebug2(WM_AWS_LOGTAG, "%s OUTPUT: %s", service_title, output);
    }

    os_free(service_title);

    char *line;
    char *save_ptr = NULL;
    for (line = strtok_r(output, "\n", &save_ptr); line; line = strtok_r(NULL, "\n", &save_ptr)) {
        wm_sendmsg(usec, aws_config->queue_fd, line, WM_AWS_CONTEXT.name, LOCALFILE_MQ);
    }

    os_free(output);
}

// Run a subscriber parsing
void wm_aws_run_subscriber(wm_aws *aws_config, wm_aws_subscriber *exec_subscriber) {
    int status;
    char *output = NULL;
    char *command = NULL;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Create arguments
    mtdebug2(WM_AWS_LOGTAG, "Create argument list");

    // script path
    char * script = NULL;
    os_calloc(PATH_MAX, sizeof(char), script);

    snprintf(script, PATH_MAX, "%s", WM_AWS_SCRIPT_PATH);

    wm_strcat(&command, script, '\0');
    os_free(script);

    // subscriber
    wm_strcat(&command, "--subscriber", ' ');
    wm_strcat(&command, exec_subscriber->type, ' ');

    wm_strcat(&command, "--queue", ' ');
    wm_strcat(&command, exec_subscriber->sqs_name, ' ');

    // subscriber arguments
    if (exec_subscriber->external_id) {
        wm_strcat(&command, "--external_id", ' ');
        wm_strcat(&command, exec_subscriber->external_id, ' ');
    }
    if (exec_subscriber->iam_role_arn) {
        wm_strcat(&command, "--iam_role_arn", ' ');
        wm_strcat(&command, exec_subscriber->iam_role_arn, ' ');
    }
    if (exec_subscriber->iam_role_duration){
        wm_strcat(&command, "--iam_role_duration", ' ');
        wm_strcat(&command, exec_subscriber->iam_role_duration, ' ');
    }
    if (exec_subscriber->aws_profile) {
        wm_strcat(&command, "--aws_profile", ' ');
        wm_strcat(&command, exec_subscriber->aws_profile, ' ');
    }
    if (exec_subscriber->sts_endpoint){
        wm_strcat(&command, "--sts_endpoint", ' ');
        wm_strcat(&command, exec_subscriber->sts_endpoint, ' ');
    }
    if (exec_subscriber->service_endpoint){
        wm_strcat(&command, "--service_endpoint", ' ');
        wm_strcat(&command, exec_subscriber->service_endpoint, ' ');
    }

    if (exec_subscriber->discard_field) {
        wm_strcat(&command, "--discard-field", ' ');
        wm_strcat(&command, exec_subscriber->discard_field, ' ');
    }
    if (exec_subscriber->discard_regex) {
        wm_strcat(&command, "--discard-regex", ' ');
        wm_strcat(&command, exec_subscriber->discard_regex, ' ');
    }

    if (isDebug()) {
        wm_strcat(&command, "--debug", ' ');
        if (isDebug() > 2) {
            wm_strcat(&command, "3", ' ');
        } else if (isDebug() > 1) {
            wm_strcat(&command, "2", ' ');
        } else {
            wm_strcat(&command, "1", ' ');
        }
    }

    if (aws_config->skip_on_error) {
        wm_strcat(&command, "--skip_on_error", ' ');
    }
    if (wm_state_io(WM_AWS_CONTEXT.name, WM_IO_READ, &aws_config->state, sizeof(aws_config->state)) < 0) {
        memset(&aws_config->state, 0, sizeof(aws_config->state));
    }

    // Execute
    char *subscriber_title = NULL;
    wm_strcat(&subscriber_title, "Subscriber:", ' ');
    wm_strcat(&subscriber_title, exec_subscriber->type, ' ');
    wm_strcat(&subscriber_title, exec_subscriber->sqs_name, ' ');

    wm_strcat(&subscriber_title, " - ", ' ');

    mtdebug1(WM_AWS_LOGTAG, "Launching S3 Subscriber Command: %s", command);

    const int wm_exec_ret_code = wm_exec(command, &output, &status, 0, NULL);

    os_free(command);

    if (wm_exec_ret_code) {
        mterror(WM_AWS_LOGTAG, "Internal error. Exiting...");
        os_free(subscriber_title);

        if (wm_exec_ret_code > 0) {
            os_free(output);
        }
        pthread_exit(NULL);
    } else if (status > 0) {
        mtwarn(WM_AWS_LOGTAG, "%s Returned exit code %d", subscriber_title, status);
        if(status == 1) {
            char * unknown_error_msg = strstr(output,"Unknown error");
            if (unknown_error_msg == NULL)
                mtwarn(WM_AWS_LOGTAG, "%s Unknown error.", subscriber_title);
            else
                mtwarn(WM_AWS_LOGTAG, "%s %s", subscriber_title, unknown_error_msg);
        } else if(status == 2) {
            char * ptr;
            if (ptr = strstr(output, "aws.py: error:"), ptr) {
                ptr += 14;
                mtwarn(WM_AWS_LOGTAG, "%s Error parsing arguments: %s", subscriber_title, ptr);
            } else {
                mtwarn(WM_AWS_LOGTAG, "%s Error parsing arguments.", subscriber_title);
            }
        } else {
            char * ptr;
            if (ptr = strstr(output, "ERROR: "), ptr) {
                ptr += 7;
                mtwarn(WM_AWS_LOGTAG, "%s %s", subscriber_title, ptr);
            } else {
                mtwarn(WM_AWS_LOGTAG, "%s %s", subscriber_title, output);
            }
        }
        mtdebug1(WM_AWS_LOGTAG, "%s OUTPUT: %s", subscriber_title, output);
    } else {
        mtdebug2(WM_AWS_LOGTAG, "%s OUTPUT: %s", subscriber_title, output);
    }

    os_free(subscriber_title);

    char *line;
    char *save_ptr = NULL;
    for (line = strtok_r(output, "\n", &save_ptr); line; line = strtok_r(NULL, "\n", &save_ptr)) {
        wm_sendmsg(usec, aws_config->queue_fd, line, WM_AWS_CONTEXT.name, LOCALFILE_MQ);
    }

    os_free(output);
}
