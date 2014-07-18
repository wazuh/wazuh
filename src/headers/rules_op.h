/* @(#) $Id: ./src/headers/rules_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */

/* Common API for dealing with directory trees */


#ifndef _OS_RULESOP_H
#define _OS_RULESOP_H

#include "shared.h"


/* Event context  - stored on a uint8 */
#define SAME_USER       0x001 /* 1   */
#define SAME_SRCIP      0x002 /* 2   */
#define SAME_ID         0x004 /* 4   */
#define SAME_LOCATION   0x008 /* 8   */
#define DIFFERENT_URL   0x010 /* */
#define SAME_SRCPORT    0x020
#define SAME_DSTPORT    0x040
#define SAME_DODIFF     0x100
#define NOT_SAME_USER   0xffe /* 0xfff - 0x001  */
#define NOT_SAME_SRCIP  0xffd /* 0xfff - 0x002  */
#define NOT_SAME_ID     0xffb /* 0xfff - 0x004  */
#define NOT_SAME_AGENT  0xff7 /* 0xfff - 0x008 */


/* Alert options  - store on a uint8 */
#define DO_FTS          0x001
#define DO_MAILALERT    0x002
#define DO_LOGALERT     0x004
#define NO_AR           0x008
#define NO_ALERT        0x010
#define DO_OVERWRITE    0x020
#define DO_PACKETINFO   0x040
#define DO_EXTRAINFO    0x100
#define SAME_EXTRAINFO  0x200


/** Types of events (from decoders) **/
#define UNKNOWN     0   /* Unkown */
#define SYSLOG      1   /* syslog messages */
#define IDS         2   /* IDS alerts */
#define FIREWALL    3   /* Firewall events */
#define WEBLOG      7   /* Apache logs */
#define SQUID       8   /* Squid logs */
#define DECODER_WINDOWS     9   /* Windows logs */
#define HOST_INFO   10  /* Host information logs (from nmap or similar) */
#define OSSEC_RL    11  /* Ossec rules */


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




typedef struct _RuleInfo
{
    int sigid;  /* id attribute -- required*/
    int level;  /* level attribute --required */
    int maxsize;
    int frequency;
    int timeframe;

    u_int8_t context; /* Not an user option */

    int firedtimes;  /* Not an user option */
    int time_ignored; /* Not an user option */
    int ignore_time;
    int ignore;
    int ckignore;
    int group_prev_matched_sz;

    int __frequency;
    char **last_events;


    /* Not an option in the rule */
    u_int16_t alert_opts;

    /* Context options */
    u_int16_t context_opts;

    /* category */
    u_int8_t category;

    /* Decoded as */
    u_int16_t decoded_as;

    /* List of previously matched events */
    OSList *sid_prev_matched;

    /* Pointer to a list (points to sid_prev_matched of if_matched_sid */
    OSList *sid_search;

    /* List of previously matched events in this group.
     * Every rule that has if_matched_group will have this
     * list. Every rule that matches this group, it going to
     * have a pointer to it (group_search).
     */
    OSList **group_prev_matched;

    /* Pointer to group_prev_matched */
    OSList *group_search;

    /* Function pointer to the event_search. */
    void *(*event_search)(void *lf, void *rule);


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
    char *action;

    char *comment; /* description in the xml */
    char *info;
    char *cve;

    char *if_sid;
    char *if_level;
    char *if_group;

    OSRegex *if_matched_regex;
    OSMatch *if_matched_group;
    int if_matched_sid;

    void **ar;

}RuleInfo;


/** Prototypes **/
int OS_ReadXMLRules(const char *rulefile,
                    void *(*ruleact_function)(RuleInfo *rule_1, void *data_1),
                    void *data);


#endif


/* EOF */
