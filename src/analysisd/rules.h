/* Copyright (C) 2015, Wazuh Inc.
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
#include "logmsg.h"


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
#define DO_FTS              0x0001
#define DO_MAILALERT        0x0002
#define DO_LOGALERT         0x0004
#define NO_AR               0x0008
#define NO_ALERT            0x0010
#define DO_OVERWRITE        0x0020
#define DO_PACKETINFO       0x0040
#define DO_EXTRAINFO        0x0100
#define SAME_EXTRAINFO      0x0200
#define NO_FULL_LOG         0x0400
#define NO_COUNTER          0x1000
#define NO_PREVIOUS_OUTPUT  0x2000

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

#define RULES_DEBUG_MSG_I_MAX_LEN   1056
#define RULES_DEBUG_MSG_I           "Trying rule: %d - %s"
#define RULES_DEBUG_MSG_II_MAX_LEN  32
#define RULES_DEBUG_MSG_II          "*Rule %d matched"
#define RULES_DEBUG_MSG_III         "*Trying child rules"

typedef struct EventList EventList;
struct _Eventinfo;

extern unsigned int hourly_alerts;

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
    void *(*event_search)(void *lf, void *os_analysisd_last_events, void *rule, void *rule_match);

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


    /* Dynamic fields to compare between events */
    char ** same_fields;
    char ** not_same_fields;

    char ** mitre_id;
    char ** mitre_tactic_id;
    char ** mitre_technique_id;

    bool internal_saving;      ///< Used to free RuleInfo structure in wazuh-logtest

    /* Pointers to the rules which this one overwrites if it exists */
    OSList * rule_overwrite;
} RuleInfo;

typedef struct _rules_tmp_params_t {

    char * regex;
    char * match;
    char * url;
    char * if_matched_regex;
    char * if_matched_group;
    char * user;
    char * id;
    char * srcport;
    char * dstport;
    char * srcgeoip;
    char * dstgeoip;
    char * protocol;
    char * system_name;
    char * status;
    char * hostname;
    char * data;
    char * extra_data;
    char * program_name;
    char * location;
    char * action;

    XML_NODE rule_arr_opt;

} rules_tmp_params_t;

typedef struct _RuleNode {
    RuleInfo *ruleinfo;
    struct _RuleNode *next;
    struct _RuleNode *child;
} RuleNode;

/**
 * @brief Structure to save all rules read in starting.
 */
extern RuleNode *os_analysisd_rulelist;

/**
 * @brief FTS log writer queue
 */
extern w_queue_t * writer_queue_log_fts;

/**
 * @brief Structure to save the last list of events.
 */
extern EventList *os_analysisd_last_events;

RuleInfoDetail *zeroinfodetails(int type, const char *data);
int get_info_attributes(char **attributes, char **values, OSList* log_msg);

/**
 * @brief Allocate memory and initialize attributes with default values
 * @param id rule's identifier
 * @param level rule's level
 * @param maxsize rule's maxsize
 * @param frequency rule's frequency
 * @param timeframe rule's timeframe
 * @param noalert determine if the rule generates alerts
 * @param ignore_time rule's ignore_time
 * @param overwrite determine if it overwrites the rule
 * @param last_event_list list of previous events
 * @return rule information's structure
 */
RuleInfo *zerorulemember(int id, int level, int maxsize, int frequency,
                         int timeframe, int noalert, int ignore_time,
                         int overwrite, EventList **last_event_list);

/**
 * @brief Check if a rule matches the event
 * @param lf event to be processed
 * @param last_events list of previous events processed
 * @param cdblists list of cdbs
 * @param curr_node rule to compare with the event "lf"
 * @param rule_match stores the regex of the rule
 * @param save_fts_value determine if fts value can be saved in fts-queue file
 * @param rules_debug_list it is filled with a list of the processed rules messages if it is a non-null pointer
 * @return the rule information if it matches, otherwise null
 */
RuleInfo * OS_CheckIfRuleMatch(struct _Eventinfo *lf, EventList *last_events,
                               ListNode **cdblists, RuleNode *curr_node,
                               regex_matching *rule_match, OSList **fts_list,
                               OSHash **fts_store, const bool save_fts_value,
                               cJSON * rules_debug_list);

/**
 * @brief Set os_analysisd_rulelist to null
 */
void OS_CreateRuleList(void);

/* Add rule information to the list */
int OS_AddRule(RuleInfo *read_rule, RuleNode **r_node);

/**
 * @brief Add rule information as a child.
 * @param read_rule rule information.
 * @param r_node node to add as a child rule information.
 * @param log_msg List to save log messages.
 * @retval -1 Critical errors.
 * @retval  0 successful.
 * @retval  1 for errors.
 */
int OS_AddChild(RuleInfo *read_rule, RuleNode **r_node, OSList* log_msg);

/**
 * @brief Add an overwrite rule.
 * @param r_node node to look for the original rule and replace it
 * @param newrule overwritet rule information
 * @param sid ID of the rule to be overwritten
 * @param log_msg List to save log messages.
 * @retval -1 Critical error.
 * @retval  0 Not overwritten.
 * @retval  1 Overwritten.
 */
int OS_AddRuleInfo(RuleNode *r_node, RuleInfo *newrule, int sid, OSList* log_msg);

/* Mark groups (if_matched_group) */
int OS_MarkGroup(RuleNode *r_node, RuleInfo *orig_rule);

/* Mark IDs (if_matched_sid) */
int OS_MarkID(RuleNode *r_node, RuleInfo *orig_rule);

/**
 * @brief Get rules list
 *
 * Only used for analysisd
 * @return first node of os_analysisd_rulelist
 */
RuleNode *OS_GetFirstRule(void);

/**
 * @brief Remove rules list
 * @param node rule list to remove
 */
void os_remove_rules_list(RuleNode *node);

/**
 * @brief Remove a rule node
 * @param node rule node to remove
 * @param rules hash where save the reference to rule information
 */
void os_remove_rulenode(RuleNode *node, RuleInfo **rules, int *pos, int *max_size);

/**
 * @brief Remove a rule information
 * @param ruleinfo rule to remove
 */
void os_remove_ruleinfo(RuleInfo *ruleinfo);

/**
 * @brief
 * @param node
 * @param num_rules
 */
void os_count_rules(RuleNode *node, int *num_rules);

/**
 * @brief Call OS_CreateRuleList function
 */
void Rules_OP_CreateRules(void);

/**
 * @brief Read a rules file and save them in r_node
 * @param rulefile file name to read
 * @param r_node reference to the rule list
 * @param l_node reference to the first list of the cdb lists
 * @param last_event_list reference to first node to the previous events list
 * @param log_msg List to save log messages.
 * @return 0 on success, otherwise -1
 */
int Rules_OP_ReadRules(const char *rulefile, RuleNode **r_node, ListNode **l_node,
                       EventList **last_event_list, OSStore **decoder_list, OSList* log_msg);

int AddHash_Rule(RuleNode *node);

int _setlevels(RuleNode *node, int nnode);

int doDiff(RuleInfo *rule, struct _Eventinfo *lf);


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
#define FIM_MOD             "syscheck_integrity_changed"
#define FIM_NEW             "syscheck_new_entry"
#define FIM_DEL             "syscheck_deleted"
#define FIM_REG_KEY_MOD     "syscheck_registry_key_modified"
#define FIM_REG_KEY_NEW     "syscheck_registry_key_added"
#define FIM_REG_KEY_DEL     "syscheck_registry_key_deleted"
#define FIM_REG_VAL_MOD     "syscheck_registry_value_modified"
#define FIM_REG_VAL_NEW     "syscheck_registry_value_added"
#define FIM_REG_VAL_DEL     "syscheck_registry_value_deleted"
#define SYSCOLLECTOR_MOD    "syscollector"
#define CISCAT_MOD          "ciscat"
#define WINEVT_MOD          "windows_eventchannel"
#define SCA_MOD             "sca"
/* Global variables */
extern int _max_freq;
extern int default_timeframe;

#endif /* OS_RULES */
