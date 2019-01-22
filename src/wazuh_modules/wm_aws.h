/*
 * Wazuh Module for AWS S3 integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * January 08, 2018.
 *
 * Updated by Jeremy Phillips <jeremy@uranusbytes.com>
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_AWS_H
#define WM_AWS_H

#define WM_AWS_LOGTAG ARGV0 ":aws-s3"
#define WM_AWS_DEFAULT_INTERVAL 5
#define WM_AWS_DEFAULT_DIR WM_DEFAULT_DIR "/aws"
#define WM_AWS_SCRIPT_PATH WM_AWS_DEFAULT_DIR "/aws-s3"

typedef struct wm_aws_state_t {
    time_t next_time;               // Absolute time for next scan
} wm_aws_state_t;

typedef struct wm_aws_bucket {
    char *bucket;                       // S3 bucket
    char *access_key;                   // IAM access key
    char *secret_key;                   // IAM secret key
    char *aws_profile;                  // AWS credentials profile
    char *iam_role_arn;                 // IAM role
    char *aws_account_id;               // AWS account ID(s)
    char *aws_account_alias;            // AWS account alias
    char *trail_prefix;                 // Trail prefix
    char *only_logs_after;              // Date (YYYY-MMM-DD) to only parse logs after
    char *regions;                      // CSV of regions to parse
    char *type;                         // String defining bucket type.
    unsigned int remove_from_bucket:1;  // Remove the logs from the bucket
    struct wm_aws_bucket *next;     // Pointer to next
} wm_aws_bucket;


typedef struct wm_aws_service {
    char *type;                         // String defining service type.
    char *access_key;                   // IAM access key
    char *secret_key;                   // IAM secret key
    char *aws_profile;                  // AWS credentials profile
    char *iam_role_arn;                 // IAM role
    char *aws_account_id;               // AWS account ID(s)
    char *aws_account_alias;            // AWS account alias
    char *only_logs_after;              // Date (YYYY-MMM-DD) to only parse logs after
    char *regions;                      // CSV of regions to parse
    struct wm_aws_service *next;     // Pointer to next
} wm_aws_service;

typedef struct wm_aws {
    char *bucket;                       // DEPRECATE
    char *access_key;                   // DEPRECATE
    char *secret_key;                   // DEPRECATE
    unsigned long interval;
    int queue_fd;
    unsigned int enabled:1;
    unsigned int run_on_start:1;
    unsigned int remove_from_bucket:1;  // DEPRECATE
    unsigned int skip_on_error:1;
    wm_aws_state_t state;
    wm_aws_bucket *buckets;      // buckets (linked list)
    wm_aws_service *services;      // services (linked list)
} wm_aws;

extern const wm_context WM_AWS_CONTEXT;   // Context

// Parse XML
int wm_aws_read(const OS_XML *xml, xml_node **nodes, wmodule *module);

#endif // WM_AWS_H
