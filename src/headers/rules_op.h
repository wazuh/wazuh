/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Common API for dealing with rules */

#ifndef OS_RULESOP_H
#define OS_RULESOP_H

#include "shared.h"

typedef struct _StaticFilters
{
    unsigned int same_dodiff:1;
    unsigned int global_frequency:1;
    unsigned int same_srcuser:1;
    unsigned int different_srcuser:1;
    unsigned int same_dstuser:1;
    unsigned int different_dstuser:1;
    unsigned int same_srcip:1;
    unsigned int different_srcip:1;
    unsigned int same_dstip:1;
    unsigned int different_dstip:1;
    unsigned int same_srcport:1;
    unsigned int different_srcport:1;
    unsigned int same_dstport:1;
    unsigned int different_dstport:1;
    unsigned int same_protocol:1;
    unsigned int different_protocol:1;
    unsigned int same_action:1;
    unsigned int different_action:1;
    unsigned int same_id:1;
    unsigned int different_id:1;
    unsigned int same_url:1;
    unsigned int different_url:1;
    unsigned int same_data:1;
    unsigned int different_data:1;
    unsigned int same_extra_data:1;
    unsigned int different_extra_data:1;
    unsigned int same_status:1;
    unsigned int different_status:1;
    unsigned int same_system_name:1;
    unsigned int different_system_name:1;
    unsigned int same_srcgeoip:1;
    unsigned int different_srcgeoip:1;
    unsigned int same_dstgeoip:1;
    unsigned int different_dstgeoip:1;
    unsigned int same_location:1;
    unsigned int different_location:1;
    unsigned int same_field:1;
    unsigned int different_field:1;
    unsigned int same_agent:1;
    unsigned int different_agent:1;
} StaticFilters;

/* Alert options - stored in a uint8 */
#define DO_FTS          0x0001
#define DO_MAILALERT    0x0002
#define DO_LOGALERT     0x0004
#define NO_AR           0x0008
#define NO_ALERT        0x0010
#define DO_OVERWRITE    0x0020
#define DO_PACKETINFO   0x0040
#define DO_EXTRAINFO    0x0100
#define SAME_EXTRAINFO  0x0200
#define NO_FULL_LOG     0x0400
#define NO_COUNTER      0x1000

/* Types of events (from decoders) */
#define UNKNOWN             0   /* Unknown */
#define SYSLOG              1   /* syslog message */
#define IDS                 2   /* IDS alert */
#define FIREWALL            3   /* Firewall event */
#define WEBLOG              7   /* Apache log */
#define SQUID               8   /* Squid log */
#define DECODER_WINDOWS     9   /* Windows log */
#define HOST_INFO           10  /* Host information log (from nmap or similar) */
#define OSSEC_RL            11  /* OSSEC rule */

/* FTS allowed values */
#define FTS_NAME        001000
#define FTS_USER        002000
#define FTS_DSTUSER     004000
#define FTS_SRCIP       000100
#define FTS_DSTIP       000200
#define FTS_LOCATION    000400
#define FTS_ID          000010
#define FTS_DATA        000020
#define FTS_SYSTEMNAME  000040

typedef struct _RuleInfo {
    int sigid;  /* id attribute -- required */
    int level;  /* level attribute --required */
    int maxsize;
    int frequency;
    int timeframe;

    u_int8_t context; /* Not a user option */

    int firedtimes;   /* Not a user option */
    int time_ignored; /* Not a user option */
    int ignore_time;
    int ignore;
    int ckignore;
    int group_prev_matched_sz;

    /* Not an option in the rule */
    u_int16_t alert_opts;

    /* Context options */
    StaticFilters context_opts;

    /* Category */
    u_int8_t category;

    /* Decoded as */
    u_int16_t decoded_as;

    /* List of previously matched events */
    OSList *sid_prev_matched;

    /* Pointer to a list (points to sid_prev_matched of if_matched_sid */
    OSList *sid_search;

    /* List of previously matched events in this group
     *
     * Every rule that has if_matched_group will have this list. Every rule that
     * matches this group, is going to have a pointer to it (group_search).
     */
    OSList **group_prev_matched;

    /* Pointer to group_prev_matched */
    OSList *group_search;

    /* Function pointer to the event_search */
    void *(*event_search)(void *lf, void *rule, void *rule_match);

    char *group;
    OSMatch *match;
    OSRegex *regex;

    /* Policy-based rules */
    char *day_time;
    char *week_day;

    os_ip **srcip;
    os_ip **dstip;
    OSMatch *srcport;
    OSMatch *dstport;
    OSMatch *user;
    OSMatch *url;
    OSMatch *id;
    OSMatch *status;
    OSMatch *hostname;
    OSMatch *program_name;
    OSMatch *extra_data;
    OSMatch *location;
    char *action;

    char *comment; /* Description in the xml */
    char *info;
    char *cve;

    char *if_sid;
    char *if_level;
    char *if_group;

    OSRegex *if_matched_regex;
    OSMatch *if_matched_group;
    int if_matched_sid;

    void **ar;
    pthread_mutex_t mutex;

    /* Dynamic fields to compare between events */
    char ** same_fields;
    char ** not_same_fields;

} RuleInfo;

int OS_ReadXMLRules(const char *rulefile,
                    void *(*ruleact_function)(RuleInfo *rule_1, void *data_1),
                    void *data) __attribute__((nonnull(1, 2)));

#endif /* OS_RULESOP_H */
