/*
 * Wazuh Module for OpenSCAP
 * Copyright (C) 2015-2019, Wazuh Inc
 * April 25, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_OSCAP
#define WM_OSCAP

#define WM_OSCAP_DEF_TIMEOUT    1800    // Default runtime limit (30 minutes)
#define WM_OSCAP_DEF_INTERVAL   86400   // Default cycle interval (1 day)

#define WM_OSCAP_LOGTAG ARGV0 ":oscap"
#define WM_OSCAP_DEFAULT_DIR WM_DEFAULT_DIR "/oscap"
#define WM_OSCAP_SCRIPT_PATH WM_OSCAP_DEFAULT_DIR "/oscap.py"

typedef enum wm_oscap_eval_t { WM_OSCAP_XCCDF = 1, WM_OSCAP_OVAL } wm_oscap_eval_t;

typedef struct wm_oscap_profile {
    char *name;                     // Profile name (string)
    struct wm_oscap_profile *next;  // Pointer to next
} wm_oscap_profile;

typedef struct wm_oscap_flags {
    unsigned int enabled:1;
    unsigned int scan_on_start:1;
    unsigned int error:1;
} wm_oscap_flags;

typedef struct wm_oscap_eval {
    wm_oscap_eval_t type;           // Type of evaluation file
    char *path;                     // File path (string)
    char *xccdf_id;                 // XCCDF id
    char *ds_id;                    // Datastream id
    char *oval_id;                  // OVAL id
    char *cpe;                      // CPE dictionary
    wm_oscap_profile *profiles;     // Profiles (linked list)
    wm_oscap_flags flags;           // Flags
    unsigned int timeout;           // Execution time limit (seconds)
    struct wm_oscap_eval *next;     // Pointer to next
} wm_oscap_eval;

typedef struct wm_oscap_state {
    time_t next_time;               // Absolute time for next scan
} wm_oscap_state;

typedef struct wm_oscap {
    unsigned int interval;          // Default time interval between cycles
    unsigned int timeout;           // Default execution time limit (seconds)
    wm_oscap_flags flags;           // Default flags
    wm_oscap_state state;           // Running state
    wm_oscap_eval *evals;           // Evaluations (linked list)
} wm_oscap;

extern const wm_context WM_OSCAP_CONTEXT;   // Context

// Parse XML
int wm_oscap_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif // WM_OSCAP
