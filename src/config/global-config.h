/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _CCONFIG__H
#define _CCONFIG__H

#include "shared.h"

/* Configuration structure */
typedef struct __Config {
    u_int8_t logall;
    u_int8_t logall_json;
    u_int8_t stats;
    u_int8_t integrity;
    u_int8_t syscheck_auto_ignore;
    int syscheck_ignore_frequency;
    int syscheck_ignore_time;
    u_int8_t syscheck_alert_new;
    u_int8_t rootcheck;
    u_int8_t hostinfo;
    u_int8_t mailbylevel;
    u_int8_t logbylevel;

    /* Prelude support */
    u_int8_t prelude;
    /* which min. level the alert must be sent to prelude */
    u_int8_t prelude_log_level;
    /* prelude profile name */
    char *prelude_profile;

    /* GeoIP DB */
    char *geoipdb_file;

    /* ZEROMQ Export */
    u_int8_t zeromq_output;
    char *zeromq_output_uri;
    char *zeromq_output_server_cert;
    char *zeromq_output_client_cert;

    /* JSONOUT Export */
    u_int8_t jsonout_output;

    /* Standard alerts output */
    u_int8_t alerts_log;

    /* Not currently used */
    u_int8_t keeplogdate;

    /* Mail alerting */
    short int mailnotify;

    /* Custom Alert output*/
    short int custom_alert_output;
    char *custom_alert_output_format;

    /* For the active response */
    int ar;

    /* For the correlation */
    int memorysize;

    /* List of files to ignore (syscheck) */
    char **syscheck_ignore;

    /* List of ips to never block */
    os_ip **white_list;

    /* List of hostnames to never block */
    OSMatch **hostname_white_list;

    /* List of rules */
    char **includes;

    /* List of Lists */
    char **lists;

    /* List of decoders */
    char **decoders;

    /* Global rule hash */
    OSHash *g_rules_hash;

#ifdef LIBGEOIP_ENABLED
    /* GeoIP support */
    u_int8_t loggeoip;
    char *geoip_db_path;
    char *geoip6_db_path;
#endif

    wlabel_t *labels; /* null-ended label set */

    // Cluster configuration
    char *cluster_name;
    char *node_name;
    char *node_type;
    unsigned char hide_cluster_info;

    int rotate_interval;
    ssize_t max_output_size;
    long queue_size;

    /* Internal options */
    int default_timeframe;
    int stats_maxdiff;
    int stats_mindiff;
    int stats_percent_diff;
    int fts_list_size;
    unsigned int fts_min_size_for_str;
    u_int8_t log_fw;
    int decoder_order_size;
#ifdef LIBGEOIP_ENABLED    
    int geoip_jsonout;
#endif
    int label_cache_maxage;
    int show_hidden_labels;
    rlim_t rlimit_nofile;
    int min_rotate_interval;
    int event_threads;
    int syscheck_threads;
    int syscollector_threads;
    int rootcheck_threads;
    int sca_threads;
    int hostinfo_threads;
    int winevt_threads;
    int rule_matching_threads;
    int decode_event_queue_size;
    int decode_syscheck_queue_size;
    int decode_syscollector_queue_size;
    int decode_rootcheck_queue_size;
    int decode_sca_queue_size;
    int decode_hostinfo_queue_size;
    int decode_winevt_queue_size;
    int decode_output_queue_size;
    int archives_queue_size;
    int statistical_queue_size;
    int alerts_queue_size;
    int firewall_queue_size;
    int fts_queue_size;
    int state_interval;
    int logging;
} _Config;


void config_free(_Config *config);

#endif /* _CCONFIG__H */
