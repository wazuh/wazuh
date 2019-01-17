/*
 * Wazuh Module to analyze vulnerabilities
 * Copyright (C) 2015-2019, Wazuh Inc.
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

#define WM_VULNDETECTOR_LOGTAG ARGV0 ":" VU_WM_NAME
#define WM_VULNDETECTOR_DEFAULT_INTERVAL 300 // 5 minutes
#define WM_VULNDETECTOR_DEFAULT_UPDATE_INTERVAL 3600 // 1 hour
#define WM_VULNDETECTOR_RETRY_UPDATE  300 // 5 minutes
#define WM_VULNDETECTOR_DOWN_ATTEMPTS  5
#define VU_DEF_IGNORE_TIME 21600 // 6 hours
#define CVE_TEMP_FILE "tmp/cve"
#define CVE_FIT_TEMP_FILE CVE_TEMP_FILE "-fitted"
#define CANONICAL_REPO "https://people.canonical.com/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml"
#define DEBIAN_REPO "https://www.debian.org/security/oval/oval-definitions-%s.xml"
#define RED_HAT_REPO_DEFAULT_MIN_YEAR 2010
#define RED_HAT_REPO_MIN_YEAR 1999
#define RED_HAT_REPO_MAX_ATTEMPTS 3
#define RED_HAT_REPO_REQ_SIZE 1000
#define RED_HAT_REPO "https://access.redhat.com/labs/securitydataapi/cve.json?after=%d-01-01&per_page=%d&page=%d"
#define CISECURITY_REPO "oval.cisecurity.org"
#define WINDOWS_OVAL "/repository/download/5.11.2/vulnerability/microsoft_windows_%s.xml"
#define MACOSX_OVAL "/repository/download/5.11.2/vulnerability/apple_mac_os_%s.xml"
#define JSON_FILE_TEST "/tmp/package_test.json"
#define DEFAULT_OVAL_PORT 443
#define KEY_SIZE OS_SIZE_6144
#define VU_SSL_BUFFER OS_MAXSTR
#define VU_MAX_VERSION_ATTEMPS 15
#define VU_MAX_WAZUH_DB_ATTEMPS 5
#define VU_MAX_TIMESTAMP_ATTEMPS 4
#define VU_MAX_VER_COMP_IT 50
#define VU_TIMESTAMP_FAIL 0
#define VU_TIMESTAMP_UPDATED 1
#define VU_TIMESTAMP_OUTDATED 2
#define VU_AGENT_REQUEST_LIMIT   0
#define VU_ALERT_HEADER "[%03d] (%s) %s"
#define VU_ALERT_JSON "1:" VU_WM_NAME ":%s"
#define VU_MODERATE   "Moderate"
#define VU_MEDIUM     "Medium"
#define VU_HIGH       "High"
#define VU_IMPORTANT  "Important"
// Patterns for building references
#define VUL_BUILD_REF_MAX 100
#define VU_BUILD_REF_CVE_RH "https://access.redhat.com/security/cve/%s"
#define VU_BUILD_REF_BUGZ "https://bugzilla.redhat.com/show_bug.cgi?id=%s"
#define VU_BUILD_REF_RHSA "https://access.redhat.com/errata/%s"

extern const wm_context WM_VULNDETECTOR_CONTEXT;
extern const char *vu_dist_tag[];
extern const char *vu_dist_ext[];

typedef enum vu_logic {
    VU_TRUE,
    VU_FALSE,
    VU_OR,
    VU_AND,
    VU_PACKG,
    VU_FILE_TEST,
    VU_VULNERABLE,
    VU_NOT_VULNERABLE,
    VU_LESS,
    VU_HIGHER,
    VU_EQUAL,
    VU_ERROR_CMP,
    VU_NOT_FIXED
} vu_logic;

typedef enum distribution{
    DIS_UBUNTU,
    DIS_DEBIAN,
    DIS_REDHAT,
    DIS_CENTOS,
    DIS_AMAZL,
    DIS_WINDOWS,
    DIS_MACOS,
    // Ubuntu versions
    DIS_PRECISE,
    DIS_TRUSTY,
    DIS_XENIAL,
    DIS_BIONIC,
    // Debian versions
    DIS_JESSIE,
    DIS_STRETCH,
    DIS_WHEEZY,
    // RedHat versions
    DIS_RHEL5,
    DIS_RHEL6,
    DIS_RHEL7,
    // Windows versions
    DIS_WXP,
    DIS_W7,
    DIS_W8,
    DIS_W81,
    DIS_W10,
    DIS_WS2008,
    DIS_WS2008R2,
    DIS_WS2012,
    DIS_WS2012R2,
    DIS_WS2016,
    // MacOS versions
    DIS_MACOSX,
    DIS_UNKNOW
} distribution;

typedef struct update_flags {
    unsigned int update:1;
    unsigned int update_ubuntu:1;
    unsigned int update_debian:1;
    unsigned int update_redhat:1;
    unsigned int update_windows:1;
    unsigned int update_macos:1;
} update_flags;

typedef struct wm_vuldet_flags {
    unsigned int enabled:1;
    unsigned int run_on_start:1;
    update_flags u_flags;
} wm_vuldet_flags;

typedef struct wm_vuldet_state {
    time_t next_time;
} wm_vuldet_state;

typedef struct agent_software {
    char *agent_id;
    char *agent_name;
    char *agent_ip;
    char *agent_OS;
    char *arch;
    distribution dist;
    char info;
    struct agent_software *next;
    struct agent_software *prev;
} agent_software;

typedef enum {
    CVE_PRECISE,
    CVE_TRUSTY,
    CVE_XENIAL,
    CVE_BIONIC,
    CVE_JESSIE,
    CVE_STRETCH,
    CVE_WHEEZY,
    CVE_REDHAT,
    CVE_WXP,
    CVE_W7,
    CVE_W8,
    CVE_W81,
    CVE_W10,
    CVE_WS2008,
    CVE_WS2008R2,
    CVE_WS2012,
    CVE_WS2012R2,
    CVE_WS2016,
    CVE_MACOSX,
    OS_SUPP_SIZE
} cve_db;

typedef struct update_node {
    char *dist;
    char *version;
    distribution dist_ref;
    const char *dist_tag;
    const char *dist_ext;
    time_t last_update;
    unsigned long interval;
    int update_from_year; // only for Red Hat feed
    char *url;
    in_port_t port;
    char *path;
    char **allowed_OS_list;
    char **allowed_ver_list;
    unsigned int attempted:1;
    unsigned int json_format:1;
} update_node;

typedef struct wm_vuldet_t {
    update_node *updates[OS_SUPP_SIZE];
    unsigned long detection_interval;
    unsigned long ignore_time;
    time_t last_detection;
    agent_software *agents_software;
    OSHash *agents_triag;
    int queue_fd;
    wm_vuldet_state state;
    wm_vuldet_flags flags;
} wm_vuldet_t;

typedef enum {
    V_OVALDEFINITIONS,
    V_DEFINITIONS,
    V_TESTS,
    V_OBJECTS,
    V_HEADER,
    V_DESCRIPTION,
    V_SIGNED_TEST,
    V_VARIABLES,
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
    char *arch_value;
    struct info_state *prev;
} info_state;

typedef struct info_test {
    char *id;
    char *state;
    char *second_state;
    struct info_test *prev;
} info_test;

typedef struct file_test {
    char *id;
    char *state;
    char *second_state;
    struct file_test *prev;
} file_test;

typedef struct info_cve {
    char *cveid;
    char *title; // Not available in Red Hat feed
    char *severity;
    char *published;
    char *updated;
    char *reference;
    char *description;
    char *cvss;
    char *cvss3;
    char *cvss_vector;
    char *bugzilla_reference;
    char *advisories;
    char *cwe;
    int flags;
    struct info_cve *prev;
} info_cve;

typedef struct vulnerability {
    char *cve_id;
    char *state_id;
    char *second_state_id;
    char *package_name;
    char pending;
    struct vulnerability *prev;
} vulnerability;

typedef struct rh_vulnerability {
    char *cve_id;
    const char *OS;
    char *package_name;
    char *package_version;
    struct rh_vulnerability *prev;
} rh_vulnerability;

typedef struct wm_vuldet_db {
    vulnerability *vulnerabilities;
    rh_vulnerability *rh_vulnerabilities;
    info_test *info_tests;
    file_test *file_tests;
    info_state *info_states;
    info_cve *info_cves;
    oval_metadata metadata;
    const char *OS;
} wm_vuldet_db;

typedef struct last_scan {
    char *last_scan_id;
    time_t last_scan_time;
} last_scan;

int wm_vuldet_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif
#endif
