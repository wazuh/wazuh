/*
 * Wazuh Module for CIS-CAT scanner
 * Copyright (C) 2015-2019, Wazuh Inc.
 * December, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef  ENABLE_CISCAT
#ifndef WM_CISCAT
#define WM_CISCAT

#define MAX_RESULT          64              // Maximum result length

#define WM_CISCAT_LOGTAG ARGV0 ":ciscat"
#define WM_CISCAT_DEFAULT_DIR WM_DEFAULT_DIR "/ciscat"
#define WM_CISCAT_DEFAULT_DIR_WIN "wodles\\ciscat"
#define WM_CISCAT_REPORTS DEFAULTDIR "/tmp"

#define WM_CISCAT_PROFILE       "<Profile id="
#define WM_CISCAT_PROFILE2      "<xccdf:Profile id="
#define WM_CISCAT_GROUP_START   "<Group id="
#define WM_CISCAT_RESULT_START  "<TestResult"
#define WM_CISCAT_RULE_START    "<Rule id="
#define WM_CISCAT_RULE_END      "</Rule>"
#define WM_CISCAT_DESC_START    "<description"
#define WM_CISCAT_RATIO_START   "<rationale"
#define WM_CISCAT_FIXTEXT_START "<fixtext"
#define WM_CISCAT_DESC_END      "</description>"
#define WM_CISCAT_RATIO_END     "</rationale>"
#define WM_CISCAT_FIXTEXT_END   "</fixtext>"
#define WM_CISCAT_GROUP_START2   "<xccdf:Group id="
#define WM_CISCAT_RULE_START2    "<xccdf:Rule id="
#define WM_CISCAT_RULE_END2      "</xccdf:Rule>"
#define WM_CISCAT_DESC_START2    "<xccdf:description"
#define WM_CISCAT_RATIO_START2   "<xccdf:rationale"
#define WM_CISCAT_FIXTEXT_START2 "<xccdf:fixtext"
#define WM_CISCAT_DESC_END2      "</xccdf:description>"
#define WM_CISCAT_RATIO_END2     "</xccdf:rationale>"
#define WM_CISCAT_FIXTEXT_END2   "</xccdf:fixtext>"



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
    int scan_day;                   // Day of month to run the CIS-CAT scan
    int scan_wday;                  // Day of the week to run the CIS-CAT scan
    char *scan_time;                // Time of the day to run the CIS-CAT scan
    unsigned int timeout;           // Default execution time limit (seconds)
    char *java_path;                // Path to Java Runtime Environment
    char *ciscat_path;              // Path to CIS-CAT scanner tool
    wm_ciscat_flags flags;          // Default flags
    wm_ciscat_state state;          // Running state
    wm_ciscat_eval *evals;          // Evaluations (linked list)
} wm_ciscat;

typedef struct wm_scan_data {
    char *benchmark;                // Benchmark evaluated
    char *profile;                  // Profile evaluated
    char *timestamp;                // Time of scan
    char *hostname;                 // Target of the evaluation
    unsigned int pass;              // Number of checks passed
    unsigned int fail;              // Number of checks failed
    unsigned int error;             // Number of check errors
    unsigned int unknown;           // Number of unknown checks
    unsigned int notchecked;        // Number of not selected checks
    char *score;                    // Pass/Fail checks ratio
} wm_scan_data;

typedef struct wm_rule_data {
    char *title;                    // Rule title
    char *id;                       // Rule ID
    char *group;                    // Group title
    char *description;              // Rule description
    char *rationale;                // Rule rationale
    char *remediation;              // Rule remediation
    char *result;                   // Rule result
    struct wm_rule_data *next;      // Pointer to the next rule data
} wm_rule_data;

extern const wm_context WM_CISCAT_CONTEXT;   // Context

// Parse XML configuration
int wm_ciscat_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif // WM_OSCAP
#endif
