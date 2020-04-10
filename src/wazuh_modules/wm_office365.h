/*
 * Wazuh module for Microsoft Office 365
 * Copyright (C) 2015-2020, Wazuh Inc.
 * March 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_OFFICE365_H
#define WM_OFFICE365_H

#define WM_OFFICE365_LOGTAG ARGV0 ":office365"
#define WM_OFFICE365_DEFAULT_INTERVAL 5
#define OFFICE365_PATH WM_DEFAULT_DIR "/office365"

/**
 * @brief Microsoft Office 365 module running state
 */
typedef struct wm_office365_state_t {
    time_t next_time; /**<  Absolute time for next scan. */
    unsigned int error; /**<  Error during current scan. 0: no error. 1: error */
} wm_office365_state_t;

/**
 * @brief Microsoft Office 365 subscription.
 */
typedef struct wm_office365_subscription_t {
    char *name; /**<  Name of the subscription. */
    struct wm_office365_subscription_t *next;  /**<  Pointer to the next subscription. */
} wm_office365_subscription_t;

/**
 * @brief Microsoft Office 365 module configuration.
 */
typedef struct wm_office365_t {
    unsigned int enabled:1; /**<  Enable or disable the module. */
    unsigned int run_on_start:1; /**<  Perform a scan at startup. */
    int timeout; /**<  Timeout in seconds for HTTP requests. */
    unsigned int skip_on_error:1; /**<  Skip when an error occurs. */
    unsigned long interval; /**<  Interval between scans. Maximum 1 day. */
    char *tenant_id; /**<  Microsoft Office 365 tenant ID. */
    char *client_id; /**<  Microsoft Office 365 client ID. */
    char *client_secret; /**<  Microsoft Office 365 client secret. */
    char *client_secret_path; /**<  Path to a file containing the Microsoft Office 365 client secret. */
    wm_office365_subscription_t *subscriptions; /**<  Configured subscriptions. */
    wm_office365_state_t state; /**<  Microsoft Office 365 running state. */
} wm_office365_t;

// Microsoft Office 365 module context
extern const wm_context WM_OFFICE365_CONTEXT;

// Parse XML configuration
int wm_office365_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif // WM_OFFICE365_H
