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

static wm_ms_graph* ms_graph;
void* wm_ms_graph_main(wm_ms_graph* ms_graph);
void wm_ms_graph_setup(wm_ms_graph* ms_graph);
void wm_ms_graph_get_access_token(wm_ms_graph_auth auth_config);
void wm_ms_graph_scan_relationships(wm_ms_graph* ms_graph);
void wm_ms_graph_check();
void wm_ms_graph_destroy(wm_ms_graph* ms_graph);
void wm_ms_graph_cleanup();
cJSON wm_ms_graph_dump(wm_ms_graph* ms_graph);

int queue_fd; // Socket ID
time_t startup_time;
time_t last_scan;

const wm_context WM_MS_GRAPH_CONTEXT = {
    .name = MS_GRAPH_WM_NAME,
    .start = (wm_routine)wm_ms_graph_main,
    .destroy = (void (*)(void*))wm_ms_graph_destroy,
    .dump = (cJSON* (*)(const void*))wm_ms_graph_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL
};


void* wm_ms_graph_main(wm_ms_graph* ms_graph) {
    char* timestamp = NULL;

    wm_ms_graph_setup(ms_graph);
    startup_time = time(NULL);
    mtinfo(WM_MS_GRAPH_LOGTAG, "Started module.");

    while(FOREVER()){
        const time_t time_sleep = sched_scan_get_time_until_next_scan(&(ms_graph->scan_config), WM_MS_GRAPH_LOGTAG, ms_graph->run_on_start);

        if(ms_graph->state.next_time == 0){
            ms_graph->state.next_time = ms_graph->scan_config.time_start + time_sleep;
        }

        if (time_sleep) {
            const int next_scan_time = sched_get_next_scan_time(ms_graph->scan_config);
            timestamp = w_get_timestamp(next_scan_time);
            mtdebug2(WM_MS_GRAPH_LOGTAG, "Waiting until: %s", timestamp);
            os_free(timestamp);
            w_sleep_until(next_scan_time);
        }

        if(!ms_graph->auth_config.access_token || time(NULL) >= ms_graph->auth_config.token_expiration_time){
            mtinfo(WM_MS_GRAPH_LOGTAG, "Obtaining access token.");
            wm_ms_graph_get_access_token(ms_graph->auth_config);
        }
        mtinfo(WM_MS_GRAPH_LOGTAG, "Starting scan of tenant '%s'", ms_graph->auth_config.tenant_id);
        wm_ms_graph_scan_relationships(ms_graph);
        last_scan = time(NULL);

    }
    return NULL;
}

void wm_ms_graph_setup(wm_ms_graph* _ms_graph) {

    ms_graph = _ms_graph;
    wm_ms_graph_check();

    if(wm_state_io(WM_MS_GRAPH_CONTEXT.name, WM_IO_READ, &ms_graph->state, sizeof(ms_graph->state)) < 0){
        memset(&ms_graph->state, 0, sizeof(ms_graph->state));
    }

    queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (queue_fd < 0) {
        mterror(WM_AZURE_LOGTAG, "Unable to connect to Message Queue. Exiting...");
        pthread_exit(NULL);
    }

    atexit(wm_ms_graph_cleanup);

}

void wm_ms_graph_get_access_token(wm_ms_graph_auth auth_config) {
    char url[OS_SIZE_8192];
    char payload[OS_SIZE_8192];
    curl_response* response;

    memset(url, '\0', OS_SIZE_8192);
    snprintf(url, OS_SIZE_8192 - 1, WM_MS_GRAPH_ACCESS_TOKEN_URL, auth_config.tenant_id);
    mtdebug1("Microsoft Graph API Access Token URL: '%s'", url);
    memset(payload, '\0', OS_SIZE_8192);
    snprintf(payload, OS_SIZE_8192 - 1, WM_MS_GRAPH_ACCESS_TOKEN_PAYLOAD, auth_config.client_id, auth_config.secret_value);
    response = wurl_http_request(WURL_POST_METHOD, "Content-Type: application/x-www-form-urlencoded", url, payload, ms_graph->curl_max_size, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    if(response){
        if(response->status_code != 200){
            mterror(WM_MS_GRAPH_LOGTAG, "Recieved unsuccessful status code when attempting to obtain access token: '%s'", response->status_code);
        }
        else if (response->max_size_reached){
            mterror(WM_MS_GRAPH_LOGTAG, "Reached maximum CURL size when attempting to obtain access token. Consider increasing the value of 'curl_max_size'");
        }
        else{
            cJSON* response_body = NULL;
            if(response_body = cJSON_Parse(response->body), !response_body){
                mterror(WM_MS_GRAPH_LOGTAG, "Failed to parse access token JSON body.");
            }
            else{
                os_strdup(cJSON_GetObjectItem(response_body, "access_token")->valuestring, auth_config.access_token);
                auth_config.token_expiration_time = time(NULL) + cJSON_GetObjectItem(response_body, "expires_in")->valueint;
                cJSON_Delete(response_body);
                wurl_free_response(response);
            }
        }
    }
    else{
        mterror(WM_MS_GRAPH_LOGTAG, "No response recieved when attempting to obtain access token.");
    }
}

void wm_ms_graph_scan_relationships(wm_ms_graph* ms_graph) {
    char url[OS_SIZE_8192];
    char startup_timestamp[OS_SIZE_32];
    char last_scan_timestamp[OS_SIZE_32];
    struct tm time_struct = { .tm_sec = 0 };

    for(int resource_num = 0; resource_num < ms_graph->num_resources; resource_num++){
        
        for(int relationship_num = 0; relationship_num < ms_graph->resources[resource_num].num_relationships; relationship_num++){

            memset(startup_timestamp, '\0', OS_SIZE_32);
            gmtime_r(&startup_time, &time_struct);
            strftime(startup_timestamp, sizeof(startup_timestamp), "%Y-%m-%dT%H:%M:%SZ", &time_struct);

            memset(last_scan_timestamp, '\0', OS_SIZE_32);
            gmtime_r(&last_scan, &time_struct);
            strftime(last_scan_timestamp, sizeof(last_scan_timestamp), "%Y-%m-%dT%H:%M:%SZ", &time_struct);

            memset(url, '\0', OS_SIZE_8192);
            snprintf(url, OS_SIZE_8192 - 1, WM_MS_GRAPH_API_URL,
            ms_graph->version,
            ms_graph->resources[resource_num],
            ms_graph->resources[resource_num].relationships[relationship_num],
            ms_graph->only_future_events ? startup_timestamp : last_scan_timestamp);

            wurl_http_get(url, ms_graph->curl_max_size, WM_MS_GRAPH_DEFAULT_TIMEOUT);
        }
    }
}

void wm_ms_graph_check() {

    if(!ms_graph->enabled){
        mtinfo(WM_MS_GRAPH_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }
    else if (!ms_graph || !ms_graph->resources || ms_graph->num_resources == 0 || ms_graph->resources[0].num_relationships == 0){
        mtwarn(WM_MS_GRAPH_LOGTAG, "Invalid module configuration (Missing API info, resources, relationships). Exiting...");
        pthread_exit(NULL);
    }
}

void wm_ms_graph_destroy(wm_ms_graph* ms_graph) {

}

void wm_ms_graph_cleanup() {

}

cJSON wm_ms_graph_dump(wm_ms_graph* ms_graph) {

}

#endif // WIN32 || defined __linux__ || defined __MACH__
