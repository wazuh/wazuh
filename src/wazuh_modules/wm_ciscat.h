/*
 * Wazuh Module for CIS-CAT scanner
 * Copyright (C) 2016 Wazuh Inc.
 * December, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_CISCAT
#define WM_CISCAT

#define WM_DEF_TIMEOUT      1800            // Default runtime limit (30 minutes)
#define WM_DEF_INTERVAL     86400           // Default cycle interval (1 day)

#define WM_CISCAT_LOGTAG ARGV0 ":ciscat"
#define WM_CISCAT_DEFAULT_DIR WM_DEFAULT_DIR "/ciscat"
#define WM_CISCAT_REPORTS DEFAULTDIR "/tmp"

typedef enum wm_ciscat_eval_t { WM_CISCAT_XCCDF = 1, WM_CISCAT_OVAL } wm_ciscat_eval_t;

typedef struct wm_ciscat_flags {
    unsigned int enabled:1;
    unsigned int scan_on_start:1;
    unsigned int error:1;
} wm_ciscat_flags;

typedef struct wm_ciscat_eval {
    wm_ciscat_eval_t type;           // Type of evaluation file
    char *path;                     // File path (string)
    char *profile;                  // Profile
    wm_ciscat_flags flags;           // Flags
    unsigned int timeout;           // Execution time limit (seconds)
    struct wm_ciscat_eval *next;     // Pointer to next
} wm_ciscat_eval;

typedef struct wm_ciscat_state {
    time_t next_time;               // Absolute time for next scan
} wm_ciscat_state;

typedef struct wm_ciscat {
    unsigned int interval;          // Default time interval between cycles
    unsigned int timeout;           // Default execution time limit (seconds)
    char *java_path;                // Path to Java Runtime Environment
    char *ciscat_path;              // Path to CIS-CAT scanner tool
    wm_ciscat_flags flags;          // Default flags
    wm_ciscat_state state;          // Running state
    wm_ciscat_eval *evals;          // Evaluations (linked list)
} wm_ciscat;

extern const wm_context WM_CISCAT_CONTEXT;   // Context

// Parse XML
int wm_ciscat_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif // WM_OSCAP
