/*
 * Wazuh Module to analyze vulnerabilities
 * Copyright (C) 2018 Wazuh Inc.
 * January 4, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT

#ifndef WM_VULNDETECTOR
#define WM_VULNDETECTOR

#define VU_WM_NAME "vulnerability-detector"
#define WM_VULNDETECTOR_LOGTAG ARGV0 ":" VU_WM_NAME
#define WM_VULNDETECTOR_DEFAULT_INTERVAL 86400 // 24H
#define CVE_TEMP_FILE TMP_PATH "/cve"
#define CVE_FIT_TEMP_FILE CVE_TEMP_FILE "-fitted"
#define CANONICAL_REPO "https://people.canonical.com"
#define REDHAT_REPO "https://www.redhat.com"
#define GET_COMMAND "GET "
#define UBUNTU_OVAL GET_COMMAND "/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml\r\n\r\n"
#define REDHAT_OVAL GET_COMMAND REDHAT_REPO "/security/data/oval/Red_Hat_Enterprise_Linux_%i.xml HTTP/1.1\r\n\r\n"
#define JSON_FILE_TEST "/tmp/package_test.json"
#define DEFAULT_OVAL_PORT 443
#define KEY_SIZE OS_SIZE_6144
#define VU_SSL_BUFFER OS_MAXSTR
#define VU_MAX_VERSION_ATTEMPS 15
#define VU_MAX_WAZUH_DB_ATTEMPS 5
#define VU_MAX_TIMESTAMP_ATTEMPS 4
#define VU_AGENT_REQUEST_LIMIT   0
#define VU_ALERT_HEADER "[%s] (%s) %s"
#define VU_ALERT_JSON "1:" VU_WM_NAME ":%s"
#define VU_INV_OS     2
#define VU_UBUNTU     "UBUNTU"
#define VU_PRECISE    "PRECISE"
#define VU_TRUSTY     "TRUSTY"
#define VU_XENIAL     "XENIAL"
#define VU_RHEL       "RED HAT"
#define VU_CENTOS     "CENTOS"
#define VU_RHEL5      "RHEL5"
#define VU_RHEL6      "RHEL6"
#define VU_RHEL7      "RHEL7"
#define VU_MODERATE   "Moderate"
#define VU_MEDIUM     "Medium"
#define VU_HIGH       "High"
#define VU_IMPORTANT  "Important"

extern const wm_context WM_VULNDETECTOR_CONTEXT;

typedef struct update_flags {
    unsigned int update:1;
    unsigned int update_nvd:1;
    unsigned int update_ubuntu:1;
    unsigned int update_redhat:1;
    // Ubuntu versions
    unsigned int precise:1; // 12.04
    unsigned int trusty:1;  // 14.04
    unsigned int xenial:1;  // 16.04
    // RedHat versions
    unsigned int rh5:1;
    unsigned int rh6:1;
    unsigned int rh7:1;
} update_flags;

typedef struct wm_vulnerability_detector_flags {
    unsigned int enabled:1;
    unsigned int run_on_start:1;
    update_flags u_flags;
} wm_vulnerability_detector_flags;

typedef struct wm_vulnerability_detector_state {
    time_t next_time;
} wm_vulnerability_detector_state;

typedef struct agent_software {
    char *agent_id;
    char *agent_name;
    char *agent_ip;
    char *OS;
    char info;
    struct agent_software *next;
    struct agent_software *prev;
} agent_software;

typedef struct time_intervals {
    unsigned long detect;
    unsigned long ubuntu;
    unsigned long redhat;
} time_intervals;

typedef struct wm_vulnerability_detector_t {
    time_intervals intervals;
    time_intervals remaining_intervals;
    agent_software *agents_software;
    int queue_fd;
    wm_vulnerability_detector_state state;
    wm_vulnerability_detector_flags flags;
} wm_vulnerability_detector_t;

typedef enum {
    UBUNTU,
    PRECISE,
    TRUSTY,
    XENIAL,
    REDHAT,
    RHEL5,
    RHEL6,
    RHEL7
} cve_db;

typedef enum {
    V_OVALDEFINITIONS,
    V_DEFINITIONS,
    V_TESTS,
    V_OBJECTS,
    V_HEADER,
    V_DESCRIPTION,
    V_SIGNED_TEST,
    V_STATES
} parser_state;

typedef struct oval_metadata {
    char *product_name;
    char *product_version;
    char *schema_version;
    char *timestamp;
} oval_metadata;

typedef struct info_state {
    char *id;
    char *operation;
    char *operation_value;
    struct info_state *prev;
} info_state;

typedef struct info_test {
    char *id;
    char *state;
    struct info_test *prev;
} info_test;

typedef struct info_cve {
    char *cveid;
    char *title;
    char *severity;
    char *published;
    char *updated;
    char *reference;
    char *description;
    struct info_cve *prev;
} info_cve;

typedef struct vulnerability {
    char *cve_id;
    char *state_id;
    char *package_name;
    char pending;
    struct vulnerability *prev;
} vulnerability;

typedef struct wm_vulnerability_detector_db {
    vulnerability *vulnerabilities;
    info_test *info_tests;
    info_state *info_states;
    info_cve *info_cves;
    oval_metadata metadata;
    char *OS;
} wm_vulnerability_detector_db;

int wm_vulnerability_detector_read(xml_node **nodes, wmodule *module);
int get_interval(char *source, unsigned long *interval);
int wm_vunlnerability_detector_set_agents_info(agent_software **agents_software);
agent_software * skip_agent(agent_software *agents, agent_software **agents_list);

#endif
#endif
