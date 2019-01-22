/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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
#include "lists.h"

/* Event context  - stored on a uint8 */
#define SAME_USER           0x001 /* 1   */
#define SAME_SRCIP          0x002 /* 2   */
#define SAME_ID             0x004 /* 4   */
#define SAME_LOCATION       0x008 /* 8   */
#define DIFFERENT_URL       0x010 /* */
#define DIFFERENT_SRCIP     0x200
#define DIFFERENT_SRCGEOIP  0x400
#define SAME_SRCPORT        0x020
#define SAME_DSTPORT        0x040
#define SAME_DODIFF         0x100
#define NOT_SAME_USER       0xffe /* 0xfff - 0x001  */
#define NOT_SAME_SRCIP      0xffd /* 0xfff - 0x002  */
#define NOT_SAME_ID         0xffb /* 0xfff - 0x004  */
#define NOT_SAME_AGENT      0xff7 /* 0xfff - 0x008 */

/* Alert options  - store on a uint16 */
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

#define RULE_MASTER     1
#define RULE_SRCIP      2
#define RULE_SRCPORT    4
#define RULE_DSTIP      8
#define RULE_DSTPORT    16
#define RULE_USER       32
#define RULE_URL        64
#define RULE_ID         128
#define RULE_HOSTNAME   256
#define RULE_PROGRAM_NAME 512
#define RULE_STATUS     1024
#define RULE_ACTION     2048
#define RULE_DYNAMIC    4096

#define RULEINFODETAIL_TEXT     0
#define RULEINFODETAIL_LINK     1
#define RULEINFODETAIL_CVE      2
#define RULEINFODETAIL_OSVDB    3
#define RULEINFODETAIL_BUGTRACK 4

#define MAX_RULEINFODETAIL  32

typedef struct _RuleInfoDetail {
    int type;
    char *data;
    struct _RuleInfoDetail *next;
} RuleInfoDetail;

typedef struct _FieldInfo {
    char *name;
    OSRegex *regex;
} FieldInfo;

typedef struct _RuleInfo {
    int sigid;  /* id attribute -- required*/
    int level;  /* level attribute --required */
    size_t maxsize;
    int frequency;
    int timeframe;

    u_int8_t context; /* Not an user option */

    int firedtimes;  /* Not an user option */
    time_t time_ignored; /* Not an user option */
    int ignore_time;
    int ignore;
    int ckignore;
    char **ignore_fields;
    char **ckignore_fields;
    unsigned int group_prev_matched_sz;

    /* Not an option in the rule */
    u_int16_t alert_opts;

    /* Context options */
    u_int16_t context_opts;

    /* Category */
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
    OSMatch *srcgeoip;
    OSMatch *dstgeoip;
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
    FieldInfo **fields;
    char *action;

    char *comment; /* description in the xml */
    char *info;
    char *cve;
    RuleInfoDetail *info_details;
    ListRule *lists;

    char *if_sid;
    char *if_level;
    char *if_group;

    OSRegex *if_matched_regex;
    OSMatch *if_matched_group;
    int if_matched_sid;

    void *(*compiled_rule)(void *lf);
    active_response **ar;

    pthread_mutex_t mutex;

    char *file;

    /* Pointer to the previous rule matched */
    void *prev_rule;
} RuleInfo;


typedef struct _RuleNode {
    RuleInfo *ruleinfo;
    struct _RuleNode *next;
    struct _RuleNode *child;
} RuleNode;



RuleInfoDetail *zeroinfodetails(int type, const char *data);
int get_info_attributes(char **attributes, char **values);

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
void OS_CreateRuleList(void);

/* Add rule information to the list */
int OS_AddRule(RuleInfo *read_rule);

/* Add rule information as a child */
int OS_AddChild(RuleInfo *read_rule);

/* Add an overwrite rule */
int OS_AddRuleInfo(RuleNode *r_node, RuleInfo *newrule, int sid);

/* Mark groups (if_matched_group) */
int OS_MarkGroup(RuleNode *r_node, RuleInfo *orig_rule);

/* Mark IDs (if_matched_sid) */
int OS_MarkID(RuleNode *r_node, RuleInfo *orig_rule);

/* Get first rule */
RuleNode *OS_GetFirstRule(void);

void Rules_OP_CreateRules(void);

int Rules_OP_ReadRules(const char *rulefile);

int AddHash_Rule(RuleNode *node);

int _setlevels(RuleNode *node, int nnode);

/** Definition of the internal rule IDS **
 ** These SIGIDs cannot be used         **
 **                                     **/

#define STATS_MODULE        11
#define FTS_MODULE          12
#define SYSCHECK_MODULE     13
#define HOSTINFO_MODULE     15

#define ROOTCHECK_MOD       "rootcheck"
#define HOSTINFO_NEW        "hostinfo_new"
#define HOSTINFO_MOD        "hostinfo_modified"
#define SYSCHECK_MOD        "syscheck_integrity_changed"
#define SYSCHECK_NEW        "syscheck_new_entry"
#define SYSCHECK_DEL        "syscheck_deleted"
#define SYSCOLLECTOR_MOD    "syscollector"
#define CISCAT_MOD          "ciscat"
#define WINEVT_MOD          "windows_eventchannel"

/* Global variables */
extern int _max_freq;
extern int default_timeframe;

#endif /* _OS_RULES */
