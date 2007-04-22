/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef _OS_RULES

#define _OS_RULES

#define MAX_LAST_EVENTS 11

#include "shared.h"
#include "active-response.h"

/* Event context  - stored on a uint8 */
#define SAME_USER       0x001 /* 1   */
#define SAME_SRCIP      0x002 /* 2   */
#define SAME_ID         0x004 /* 4   */
#define SAME_LOCATION   0x008 /* 8   */
#define DIFFERENT_URL   0x010 /* */
#define SAME_SRCPORT    0x020
#define SAME_DSTPORT    0x040
#define NOT_SAME_USER   0xffe /* 0xfff - 0x001  */
#define NOT_SAME_SRCIP  0xffd /* 0xfff - 0x002  */
#define NOT_SAME_ID     0xffb /* 0xfff - 0x004  */
#define NOT_SAME_AGENT  0xff7 /* 0xfff - 0x008 */

/* Alert options  - store on a uint8 */
#define DO_FTS          0x001
#define DO_MAILALERT    0x002
#define DO_LOGALERT     0x004
#define NO_ALERT        0x010
#define DO_OVERWRITE    0x020
#define DO_PACKETINFO   0x040
#define DO_EXTRAINFO    0x100
#define SAME_EXTRAINFO  0x200


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
    
    active_response **ar;

}RuleInfo;


typedef struct _RuleNode
{
    RuleInfo *ruleinfo;
    struct _RuleNode *next;
    struct _RuleNode *child;
}RuleNode;


RuleInfo *currently_rule; /* */

/* RuleInfo functions */
RuleInfo *zerorulemember(int id, 
                         int level,
                         int maxsize, 
                         int frequency,
                         int timeframe, 
                         int noalert,
                         int ignore_time,
                         int overwrite);


/** Rule_list Functions **/

/* create the rule list */
void OS_CreateRuleList();

/* Add rule information to the list */
int OS_AddRule(RuleInfo *read_rule);

/* Add rule information as a child */
int OS_AddChild(RuleInfo *read_rule);

/* Add an overwrite rule */
int OS_AddRuleInfo(RuleNode *r_node, RuleInfo *newrule, int sid);

/* Mark groups (if_matched_group */
int OS_MarkGroup(RuleNode *r_node, RuleInfo *orig_rule);

/* Get first rule */
RuleNode *OS_GetFirstRule();


/** Defition of the internal rule IDS **
 ** These SIGIDs cannot be used       **
 **                                   **/
   
#define STATS_MODULE        11
#define FTS_MODULE          12
#define SYSCHECK_MODULE     13   
#define HOSTINFO_MODULE     15


#define ROOTCHECK_MOD   "rootcheck"

#endif /* _OS_RULES */
