/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OS_RULES
#define OS_RULES

#define MAX_LAST_EVENTS 11

#include "shared.h"
#include "expression.h"
#include "active-response.h"
#include "lists.h"

/* Event fields - stored on a u_int32_t */
#define FIELD_SRCIP      0x01
#define FIELD_ID         0x02
#define FIELD_DSTIP      0x04
#define FIELD_SRCPORT    0x08
#define FIELD_DSTPORT    0x10
#define FIELD_SRCUSER    0x20
#define FIELD_USER       0x40
#define FIELD_PROTOCOL   0x80
#define FIELD_ACTION     0x100
#define FIELD_URL        0x200
#define FIELD_DATA       0x400
#define FIELD_EXTRADATA  0x800
#define FIELD_STATUS     0x1000
#define FIELD_SYSTEMNAME 0x2000
#define FIELD_SRCGEOIP   0x4000
#define FIELD_DSTGEOIP   0x8000
#define FIELD_LOCATION   0x10000
#define N_FIELDS         17

#define FIELD_DYNAMICS   0x20000
#define FIELD_AGENT      0x40000

#define FIELD_DODIFF     0x01
#define FIELD_GFREQUENCY 0x02

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
#define RULE_PROTOCOL   8192
#define RULE_SYSTEMNAME 16384
#define RULE_DATA       32768
#define RULE_EXTRA_DATA 65536

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
    w_expression_t *regex;
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
    u_int32_t same_field;
    u_int32_t different_field;

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
    w_expression_t * match;
    w_expression_t * regex;

    /* Policy-based rules */
    char *day_time;
    char *week_day;

    w_expression_t * srcip;
    w_expression_t * dstip;
    w_expression_t * srcgeoip;
    w_expression_t * dstgeoip;
    w_expression_t * srcport;
    w_expression_t * dstport;
    w_expression_t * user;
    w_expression_t * url;
    w_expression_t * id;
    w_expression_t * status;
    w_expression_t * hostname;
    w_expression_t * program_name;
    w_expression_t * data;
    w_expression_t * extra_data;
    w_expression_t * location;
    w_expression_t * system_name;
    w_expression_t * protocol;
    FieldInfo **fields;
    w_expression_t * action;

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

    /* Dynamic fields to compare between events */
    char ** same_fields;
    char ** not_same_fields;

    char ** mitre_id;
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
#define SCA_MOD             "sca"
/* Global variables */
extern int _max_freq;
extern int default_timeframe;

#endif /* OS_RULES */
