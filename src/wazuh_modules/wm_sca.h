/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_SCA_H
#define WM_SCA_H

#define WM_SCA_LOGTAG SCA_WM_NAME

typedef struct wm_sca_t
{
    int enabled : 1;
    int scan_on_start : 1;
} wm_sca_t;

// typedef struct cis_db_info_t {
//     char *result;
//     cJSON *event;
//     int id;
// } cis_db_info_t;

// typedef struct cis_db_hash_info_t {
//     cis_db_info_t **elem;
// } cis_db_hash_info_t;

extern const wm_context WM_SCA_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
int wm_sca_read(const OS_XML* xml, xml_node** nodes, wmodule* module);
// char* wm_sca_hash_integrity_file(const char* file);
// char** wm_sort_variables(const cJSON* const variables);
// #ifdef WIN32
// void wm_sca_push_request_win(char* msg);
// #endif

#endif // WM_SCA_H
