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
void wm_ms_graph_get_access_token(wm_ms_graph_auth* auth_config);
void wm_ms_graph_scan_relationships(wm_ms_graph* ms_graph);
void wm_ms_graph_check();
void wm_ms_graph_destroy(wm_ms_graph* ms_graph);
void wm_ms_graph_cleanup();
cJSON wm_ms_graph_dump(wm_ms_graph* ms_graph);

int queue_fd; // Socket ID

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
    
    wm_ms_graph_setup(ms_graph);



}

void wm_ms_graph_setup(wm_ms_graph* _ms_graph) {

    ms_graph = _ms_graph;
    wm_ms_graph_check();

    if(wm_state_io(WM_MS_GRAPH_CONTEXT.name, WM_IO_READ, &ms_graph->state, sizeof(ms_graph->state)) < 0){
        memset(&ms_graph->state, 0, sizeof(ms_graph->state));
    }

    queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (queue_fd < 0) {
        mterror(WM_AZURE_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    atexit(wm_ms_graph_cleanup);

}

void wm_ms_graph_get_access_token(wm_ms_graph_auth* auth_config) {
    curl_response* response;

    //TODO: Handle the expiration timer for the access token
    response = wurl_http_request(WURL_POST_METHOD, "Content-Type: application/x-www-form-urlencoded", WM_MS_GRAPH_ACCESS_TOKEN_URL, WM_MS_GRAPH_ACCESS_TOKEN_PAYLOAD, ms_graph->curl_max_size, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    if(response->status_code != 200){
        //TODO
    }
    else{
        //TODO
    }
}

void wm_ms_graph_scan_relationships(wm_ms_graph* ms_graph) {

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
