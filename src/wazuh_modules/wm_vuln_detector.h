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
#define WM_VULNDETECTOR_DEFAULT_INTERVAL 60 // 1M
#define VU_DEF_IGNORE_TIME 21600 // 6H
#define CVE_TEMP_FILE TMP_PATH "/cve"
#define CVE_FIT_TEMP_FILE CVE_TEMP_FILE "-fitted"
#define HTTP_HEADER "http://"
#define HTTPS_HEADER "https://"
#define CANONICAL_REPO "people.canonical.com"
#define DEBIAN_REPO "www.debian.org"
#define REDHAT_REPO "www.redhat.com"
#define CISECURITY_REPO "oval.cisecurity.org"
#define UBUNTU_OVAL "/~ubuntu-security/oval/com.ubuntu.%s.cve.oval.xml"
#define DEBIAN_OVAL "/security/oval/oval-definitions-%s.xml"
#define REDHAT_OVAL "/security/data/oval/Red_Hat_Enterprise_Linux_%s.xml"
#define WINDOWS_OVAL "/repository/download/5.11.2/vulnerability/microsoft_windows_%s.xml"
#define MACOSX_OVAL "/repository/download/5.11.2/vulnerability/apple_mac_os_%s.xml"
#define OVAL_REQUEST "GET %s HTTP/1.1\r\n" \
                     "User-Agent: Wazuh\r\n" \
                     "Accept: */*\r\n" \
                     "Accept-Encoding: identity\r\n" \
                     "Host: %s\r\n" \
                     "Connection: Keep-Alive\r\n\r\n"
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
#define VU_MODERATE   "Moderate"
#define VU_MEDIUM     "Medium"
#define VU_HIGH       "High"
#define VU_IMPORTANT  "Important"

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
    VU_NOT_FIXED
} vu_logic;

typedef enum distribution{
    DIS_UBUNTU,
    DIS_DEBIAN,
    DIS_REDHAT,
    DIS_CENTOS,
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
    const char *OS;
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
    CVE_RHEL5,
    CVE_RHEL6,
    CVE_RHEL7,
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
    char *url;
    in_port_t port;
    char *path;
    char **allowed_list;
} update_node;

typedef struct wm_vulnerability_detector_t {
    update_node *updates[OS_SUPP_SIZE];
    unsigned long detection_interval;
    unsigned long ignore_time;
    time_t last_detection;
    agent_software *agents_software;
    OSHash *agents_triag;
    int queue_fd;
    wm_vulnerability_detector_state state;
    wm_vulnerability_detector_flags flags;
} wm_vulnerability_detector_t;

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
    char *title;
    char *severity;
    char *published;
    char *updated;
    char *reference;
    char *description;
    char *cvss2;
    char *cvss3;
    struct info_cve *prev;
} info_cve;

typedef struct patch {
    char **patch_id;
    info_cve *cve_ref; // A CVE sublist for each patch
    struct patch *prev;
} patch;

typedef struct vulnerability {
    char *cve_id;
    char *state_id;
    char *second_state_id;
    char *package_name;
    char pending;
    struct vulnerability *prev;
} vulnerability;

typedef struct wm_vulnerability_detector_db {
    vulnerability *vulnerabilities;
    info_test *info_tests;
    file_test *file_tests;
    info_state *info_states;
    info_cve *info_cves;
    patch *patches;
    oval_metadata metadata;
    char *OS;
} wm_vulnerability_detector_db;

typedef struct last_scan {
    char *last_scan_id;
    time_t last_scan_time;
} last_scan;

int wm_vulnerability_detector_read(const OS_XML *xml, xml_node **nodes, wmodule *module);
int get_interval(char *source, unsigned long *interval);

#endif
#endif
