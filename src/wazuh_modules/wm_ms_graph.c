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

}

void wm_ms_graph_setup(wm_ms_graph* ms_graph) {

}

void wm_ms_graph_get_access_token(wm_ms_graph_auth* auth_config) {

}

void wm_ms_graph_scan_relationships(wm_ms_graph* ms_graph) {

}

void wm_ms_graph_check() {

}

void wm_ms_graph_destroy(wm_ms_graph* ms_graph) {

}

void wm_ms_graph_cleanup() {

}

cJSON wm_ms_graph_dump(wm_ms_graph* ms_graph) {

}

#endif // WIN32 || defined __linux__ || defined __MACH__
