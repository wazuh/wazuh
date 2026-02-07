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

#ifndef WM_GCP_H
#define WM_GCP_H

#define WM_GCP_PUBSUB_LOGTAG ARGV0 ":gcp-pubsub"
#define WM_GCP_BUCKET_LOGTAG ARGV0 ":gcp-bucket"
#define WM_GCP_SCRIPT_PATH "wodles/gcloud/gcloud"
#define WM_GCP_LOGGING_TOKEN ":gcloud_wodle:"

#define WM_GCP_DEF_INTERVAL 3600

typedef struct wm_gcp_pubsub {
    int enabled;
    int pull_on_start;
    int max_messages;
    int num_threads;
    time_t next_time;
    char *project_id;
    char *subscription_name;
    char *credentials_file;
    sched_scan_config scan_config;
} wm_gcp_pubsub;

typedef struct wm_gcp_bucket {
    char *bucket;                       // Bucket name
    char *type;                         // String defining bucket type.
    char *credentials_file;             // Path to the credentials file
    char *prefix;                       // Prefix or path to filter files
    char *only_logs_after;              // Date (YYYY-MMM-DD) to only parse logs after
    unsigned int remove_from_bucket:1;  // Remove the logs from the bucket
    struct wm_gcp_bucket *next;         // Pointer to next
} wm_gcp_bucket;

typedef struct wm_gcp_bucket_base {
    unsigned int enabled:1;
    unsigned int run_on_start:1;
    sched_scan_config scan_config;
    time_t next_time;                   // Absolute time for next scan
    wm_gcp_bucket *buckets;             // buckets (linked list)
} wm_gcp_bucket_base;

extern const wm_context WM_GCP_PUBSUB_CONTEXT;   // Context
extern const wm_context WM_GCP_BUCKET_CONTEXT;   // Context

/**
 * @brief Read the configuration for Google Cloud Pub/Sub
 * @param nodes XML nodes to analyze
 * @param module Wazuh module to initialize
 */
int wm_gcp_pubsub_read(xml_node **nodes, wmodule *module);

/**
 * @brief Read the configuration for a Google Cloud bucket
 * @param nodes XML nodes to analyze
 * @param module Wazuh module to initialize
 */
int wm_gcp_bucket_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif
