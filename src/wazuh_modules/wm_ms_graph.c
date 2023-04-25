/*
 * Wazuh Module for Azure integration
 * Copyright (C) 2015, Wazuh Inc.
 * March, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined(WIN32) || defined(__linux__) || defined(__MACH__)

#include "wmodules.h"
#include "wm_ms_graph.h"

#ifdef WIN32
#ifdef WAZUH_UNIT_TESTING
#define gmtime_r(x, y)
#else
#define gmtime_r(x, y) gmtime_s(y, x)
#endif
#endif

static void* wm_ms_graph_main(wm_ms_graph* ms_graph);
static bool wm_ms_graph_setup(wm_ms_graph* ms_graph);
static bool wm_ms_graph_check();
static void wm_ms_graph_get_access_token(wm_ms_graph_auth* auth_config, const ssize_t curl_max_size);
static void wm_ms_graph_scan_relationships(wm_ms_graph* ms_graph);
static void wm_ms_graph_destroy(wm_ms_graph* ms_graph);
static void wm_ms_graph_cleanup();
cJSON* wm_ms_graph_dump(const wm_ms_graph* ms_graph);

static int queue_fd; // Socket ID
time_t last_scan;

const wm_context WM_MS_GRAPH_CONTEXT = {
    .name = MS_GRAPH_WM_NAME,
    .start = (wm_routine)wm_ms_graph_main,
    .destroy = (void (*)(void*))wm_ms_graph_destroy,
    .dump = (cJSON* (*)(const void*))wm_ms_graph_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};


void* wm_ms_graph_main(wm_ms_graph* ms_graph) {
    char* timestamp = NULL;

    if (!wm_ms_graph_setup(ms_graph)){
        return NULL;
    }
    else{
        last_scan = time(NULL);
        mtinfo(WM_MS_GRAPH_LOGTAG, "Started module.");

        while(FOREVER()){
            const time_t time_sleep = sched_scan_get_time_until_next_scan(&ms_graph->scan_config, WM_MS_GRAPH_LOGTAG, ms_graph->run_on_start);

            if(ms_graph->state.next_time == 0){
                ms_graph->state.next_time = ms_graph->scan_config.time_start + time_sleep;
            }

            if (time_sleep) {
                const int next_scan_time = sched_get_next_scan_time(ms_graph->scan_config);
                timestamp = w_get_timestamp(next_scan_time);
                mtdebug1(WM_MS_GRAPH_LOGTAG, "Waiting until: %s", timestamp);
                os_free(timestamp);
                w_sleep_until(next_scan_time);
            }

            if(!ms_graph->auth_config.access_token || time(NULL) >= ms_graph->auth_config.token_expiration_time){
                mtinfo(WM_MS_GRAPH_LOGTAG, "Obtaining access token.");
                wm_ms_graph_get_access_token(&ms_graph->auth_config, ms_graph->curl_max_size);
            }
            mtinfo(WM_MS_GRAPH_LOGTAG, "Scanning tenant '%s'", ms_graph->auth_config.tenant_id);
            wm_ms_graph_scan_relationships(ms_graph);

        }
    }    
    return NULL;
}

bool wm_ms_graph_setup(wm_ms_graph* ms_graph) {

    if (!wm_ms_graph_check(ms_graph)){
        return false;
    }

    if(wm_state_io(WM_MS_GRAPH_CONTEXT.name, WM_IO_READ, &ms_graph->state, sizeof(ms_graph->state)) < 0){
        memset(&ms_graph->state, 0, sizeof(ms_graph->state));
    }

    queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (queue_fd < 0) {
        mterror(WM_MS_GRAPH_LOGTAG, "Unable to connect to Message Queue. Exiting...");
        #ifdef WAZUH_UNIT_TESTING
        return false;
        #else
        pthread_exit(NULL);
        #endif
    }

    atexit(wm_ms_graph_cleanup);
    return true;

}

bool wm_ms_graph_check(wm_ms_graph* ms_graph) {

    if(!ms_graph->enabled){
        mtinfo(WM_MS_GRAPH_LOGTAG, "Module disabled. Exiting...");
        #ifdef WAZUH_UNIT_TESTING
        return false;
        #else
        pthread_exit(NULL);
        #endif
        
    }
    else if (!ms_graph || !ms_graph->resources || ms_graph->num_resources == 0){
        mterror(WM_MS_GRAPH_LOGTAG, "Invalid module configuration (Missing API info, resources, relationships). Exiting...");
        #ifdef WAZUH_UNIT_TESTING
        return false;
        #else
        pthread_exit(NULL);
        #endif
    }
    else {
        for(unsigned int resource = 0; resource < ms_graph->num_resources; resource++){
            if(ms_graph->resources[resource].num_relationships == 0){
                mterror(WM_MS_GRAPH_LOGTAG, "Invalid module configuration (Missing API info, resources, relationships). Exiting...");
                #ifdef WAZUH_UNIT_TESTING
                return false;
                #else
                pthread_exit(NULL);
                #endif
            }
        }
    }
    return true;
}

void wm_ms_graph_get_access_token(wm_ms_graph_auth* auth_config, const ssize_t curl_max_size) {
    char *url= calloc(1, sizeof(char) * OS_SIZE_8192);
    char *payload = calloc(1, sizeof(char) * OS_SIZE_8192);
    char** headers = NULL;
    curl_response* response;

    //memset(url, '\0', OS_SIZE_8192);
    snprintf(url, OS_SIZE_8192 - 1, WM_MS_GRAPH_ACCESS_TOKEN_URL, auth_config->tenant_id);
    mtdebug1(WM_MS_GRAPH_LOGTAG, "Microsoft Graph API Access Token URL: '%s'", url);
    //memset(payload, '\0', OS_SIZE_8192);
    snprintf(payload, OS_SIZE_8192 - 1, WM_MS_GRAPH_ACCESS_TOKEN_PAYLOAD, auth_config->client_id, auth_config->secret_value);
    os_malloc(sizeof(char*) * 2, headers);
    os_strdup("Content-Type: application/x-www-form-urlencoded", headers[0]);
    headers[1] = NULL;

    response = wurl_http_request(WURL_POST_METHOD, headers, url, payload, curl_max_size, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    if(response){
        if(response->status_code != 200){
            char status_code[4];
            snprintf(status_code, 4, "%ld", response->status_code);
            mtwarn(WM_MS_GRAPH_LOGTAG, "Recieved unsuccessful status code when attempting to obtain access token: Status code was '%s' & response was '%s'", status_code, response->body);
        }
        else if (response->max_size_reached){
            mtwarn(WM_MS_GRAPH_LOGTAG, "Reached maximum CURL size when attempting to obtain access token. Consider increasing the value of 'curl_max_size'.");
        }
        else{
            cJSON* response_body = NULL;
            if(response_body = cJSON_Parse(response->body), response_body){
                os_strdup(cJSON_GetObjectItem(response_body, "access_token")->valuestring, auth_config->access_token);
                auth_config->token_expiration_time = time(NULL) + cJSON_GetObjectItem(response_body, "expires_in")->valueint;
                cJSON_Delete(response_body);
            }
            else{
                mtwarn(WM_MS_GRAPH_LOGTAG, "Failed to parse access token JSON body.");
            }
        }
        wurl_free_response(response);
    }
    else{
        mtwarn(WM_MS_GRAPH_LOGTAG, "No response recieved when attempting to obtain access token.");
    }
    
    os_free(headers);
}

void wm_ms_graph_scan_relationships(wm_ms_graph* ms_graph) {
    char url[OS_SIZE_8192];
    char auth_header[OS_SIZE_2048];
    char** headers = NULL;
    char last_scan_timestamp[OS_SIZE_32];
    struct tm time_struct = { .tm_sec = 0 };
    curl_response* response;
    char* payload;

    for(unsigned int resource_num = 0; resource_num < ms_graph->num_resources; resource_num++){
        
        for(unsigned int relationship_num = 0; relationship_num < ms_graph->resources[resource_num].num_relationships; relationship_num++){

            memset(last_scan_timestamp, '\0', OS_SIZE_32);
            gmtime_r(&last_scan, &time_struct);
            strftime(last_scan_timestamp, sizeof(last_scan_timestamp), "%Y-%m-%dT%H:%M:%SZ", &time_struct);

            memset(auth_header, '\0', OS_SIZE_2048);
            snprintf(auth_header, OS_SIZE_2048 - 1, "Authorization: Bearer %s", ms_graph->auth_config.access_token);
            os_malloc(sizeof(char*) * 2, headers);
            os_strdup(auth_header, headers[0]);
            headers[1] = NULL;

            memset(url, '\0', OS_SIZE_8192);
            snprintf(url, OS_SIZE_8192 - 1, WM_MS_GRAPH_API_URL,
            ms_graph->version,
            ms_graph->resources[resource_num].name,
            ms_graph->resources[resource_num].relationships[relationship_num],
            ms_graph->only_future_events ? last_scan_timestamp : "1970-01-01T00:00:00Z");
            mtdebug1(WM_MS_GRAPH_LOGTAG, "Microsoft Graph API Log URL: '%s'", url);

            response = wurl_http_request(WURL_GET_METHOD, headers, url, "", ms_graph->curl_max_size, WM_MS_GRAPH_DEFAULT_TIMEOUT);
            if(response){
                if(response->status_code != 200){
                    char status_code[4];
                    snprintf(status_code, 4, "%ld", response->status_code);
                    mtwarn(WM_MS_GRAPH_LOGTAG, "Recieved unsuccessful status code when attempting to get relationship '%s' logs: Status code was '%s' & response was '%s'",
                    ms_graph->resources[resource_num].relationships[relationship_num],
                    status_code,
                    response->body);
                    wurl_free_response(response);
                    goto failed;
                }
                else if (response->max_size_reached){
                    mtwarn(WM_MS_GRAPH_LOGTAG, "Reached maximum CURL size when attempting to get relationship '%s' logs. Consider increasing the value of 'curl_max_size'.",
                    ms_graph->resources[resource_num].relationships[relationship_num]);
                }
                else{
                    cJSON* logs = NULL;
                    if(logs = cJSON_Parse(response->body), logs){
                        logs = cJSON_GetObjectItem(logs, "value");
                        int num_logs = cJSON_GetArraySize(logs);
                        if(num_logs > 0){
                            for(int log_index = 0; log_index < num_logs; log_index++){
                                cJSON* log = NULL;
                                if(log = cJSON_GetArrayItem(logs, log_index), log){
                                    cJSON* full_log = cJSON_CreateObject();

                                    cJSON_AddStringToObject(log, "resource", ms_graph->resources[resource_num].name);
                                    cJSON_AddStringToObject(log, "relationship", ms_graph->resources[resource_num].relationships[relationship_num]);
                                    cJSON_AddStringToObject(full_log, "integration", WM_MS_GRAPH_CONTEXT.name);
                                    cJSON_AddItemToObject(full_log, WM_MS_GRAPH_CONTEXT.name, cJSON_Duplicate(log, true));

                                    os_strdup(cJSON_PrintUnformatted(full_log), payload);
                                    mtdebug2(WM_MS_GRAPH_LOGTAG, "Sending log: '%s'", payload);
                                    if (wm_sendmsg(1000000 / wm_max_eps, queue_fd, payload, WM_MS_GRAPH_CONTEXT.name, LOCALFILE_MQ) < 0) {
                                        mterror(WM_MS_GRAPH_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                                    }

                                    os_free(payload);
                                    cJSON_Delete(full_log);
                                }
                                else{
                                mtwarn(WM_MS_GRAPH_LOGTAG, "Failed to parse log array into singular log.");
                                }
                            }
                        }
                        else{
                            mtdebug2(WM_MS_GRAPH_LOGTAG, "No new logs recieved.");
                        }
                        cJSON_Delete(logs);
                    }
                    else{
                        mtwarn(WM_MS_GRAPH_LOGTAG, "Failed to parse relationship '%s' JSON body.", ms_graph->resources[resource_num].relationships[relationship_num]);
                    }
                }
                wurl_free_response(response);
            }
            else{
                mtwarn(WM_MS_GRAPH_LOGTAG, "No response recieved when attempting to get relationship '%s' from resource '%s' on API version '%s'.",
                ms_graph->resources[resource_num].relationships[relationship_num],
                ms_graph->resources[resource_num].name,
                ms_graph->version);
            }
        }
    }
    last_scan = time(NULL);
    failed:
    if(headers){
        os_free(headers);
    }
}

void wm_ms_graph_destroy(wm_ms_graph* ms_graph) {

    for(unsigned int resource = 0; resource < ms_graph->num_resources; resource++){
        for(unsigned int relationship = 0; relationship < ms_graph->resources[resource].num_relationships; relationship++){
            os_free(ms_graph->resources[resource].relationships[relationship]);
        }
        os_free(ms_graph->resources[resource].name);
        os_free(ms_graph->resources[resource].relationships);
    }
    os_free(ms_graph->resources);

    os_free(ms_graph->auth_config.tenant_id);
    os_free(ms_graph->auth_config.client_id);
    os_free(ms_graph->auth_config.secret_value);
    os_free(ms_graph->auth_config.access_token);

    os_free(ms_graph->version);

    os_free(ms_graph);
}

void wm_ms_graph_cleanup() {
    close(queue_fd);
    mtinfo(WM_MS_GRAPH_LOGTAG, "Module shutdown.");
}

cJSON* wm_ms_graph_dump(const wm_ms_graph* ms_graph) {
    cJSON* root = cJSON_CreateObject();
    cJSON* ms_graph_info = cJSON_CreateObject();
    cJSON* ms_graph_auth = cJSON_CreateObject();

    if(ms_graph->enabled){
        cJSON_AddStringToObject(ms_graph_info, "enabled", "yes");
    }
    else{
        cJSON_AddStringToObject(ms_graph_info, "enabled", "no");
    }
    if(ms_graph->only_future_events){
        cJSON_AddStringToObject(ms_graph_info, "only_future_events", "yes");
    }
    else{
        cJSON_AddStringToObject(ms_graph_info, "only_future_events", "no");
    }
    if(ms_graph->curl_max_size){
        cJSON_AddNumberToObject(ms_graph_info, "curl_max_size", ms_graph->curl_max_size);
    }
    if(ms_graph->run_on_start){
        cJSON_AddStringToObject(ms_graph_info, "run_on_start", "yes");
    }
    else{
        cJSON_AddStringToObject(ms_graph_info, "run_on_start", "no");
    }
    if(ms_graph->version){
        cJSON_AddStringToObject(ms_graph_info, "version", ms_graph->version);
    }
    sched_scan_dump(&ms_graph->scan_config, ms_graph_info);

    if(ms_graph->auth_config.client_id){
        cJSON_AddStringToObject(ms_graph_auth, "client_id", ms_graph->auth_config.client_id);
    }
    if(ms_graph->auth_config.tenant_id){
        cJSON_AddStringToObject(ms_graph_auth, "tenant_id", ms_graph->auth_config.tenant_id);
    }
    if(ms_graph->auth_config.secret_value){
        cJSON_AddStringToObject(ms_graph_auth, "secret_value", ms_graph->auth_config.secret_value);
    }
    cJSON_AddItemToObject(ms_graph_info, "api_auth", ms_graph_auth);

    if(ms_graph->resources){
        cJSON* resource_array = cJSON_CreateArray();
        for(unsigned int resource_num = 0; resource_num < ms_graph->num_resources; resource_num++){
            cJSON* resource = cJSON_CreateObject();
            if(ms_graph->resources[resource_num].name){
                cJSON_AddStringToObject(ms_graph_auth, "name", ms_graph->resources[resource_num].name);
            }
            else{
                cJSON_free(resource);
                continue;
            }
            if(ms_graph->resources[resource_num].relationships){
                for(unsigned int relationship_num = 0; relationship_num < ms_graph->resources[resource_num].num_relationships; relationship_num++){
                    if(ms_graph->resources[resource_num].relationships[relationship_num]){
                        cJSON_AddStringToObject(resource, "relationship", ms_graph->resources[resource_num].relationships[relationship_num]);
                    }
                }
            }
            cJSON_AddItemToArray(resource_array, resource);
        }
        if(cJSON_GetArraySize(resource_array) > 0){
            cJSON_AddItemToObject(ms_graph_info, "resources", resource_array);
        }
        else{
            cJSON_free(resource_array);
        }
    }
    cJSON_AddItemToObject(root, "ms_graph", ms_graph_info);

    return root;
}

#endif // WIN32 || defined __linux__ || defined __MACH__
