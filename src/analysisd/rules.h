/*   $OSSEC, rules.h, v0.2, 2005/09/15, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.3: 2005/09/15: Adding ignore time for rule
 * v0.2: 2004/08/03
 */

#ifndef _OS_RULES

#define _OS_RULES

#define TIMEFRAME 360 /* Default timeframe */
#define MAX_LAST_EVENTS 11

#include "shared.h"
#include "active-response.h"


typedef struct _RuleInfo
{
    int sigid;  /* id attribute -- required*/
    int level;  /* level attribute --required */
    int maxsize;
    int frequency;
    int timeframe;

    int context; /* Not an user option */
    int firedtimes;  /* Not an user option */
    int time_ignored; /* Not an user option */
    int ignore_time;

    int __frequency;
    char *last_events[MAX_LAST_EVENTS+1];
    

    /* Not an option in the rule */
    u_int8_t fts ;
    u_int8_t emailalert;
    u_int8_t logalert;
    u_int8_t noalert;
    u_int8_t same_source_ip;
    u_int8_t same_user;
    u_int8_t same_loghost;
    u_int8_t category;
   
    char *group;
    char *plugin_decoded;
    OSMatch *match;
    OSRegex *regex;

    char *srcip;
    char *dstip;
    char *user;
    OSRegex *url;
    char *id;
    
    char *comment; /* description in the xml */
    char *info;
    char *cve;
    
    char *if_sid;
    char *if_level;
    char *if_group;

    OSRegex *if_matched_regex;
    char *if_matched_group;
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


/** Rule_list Functions **/

/* create the rule list */
void OS_CreateRuleList();

/* Add rule information to the list */
int OS_AddRule(RuleInfo *read_rule);

/* Add rule information as a child */
int OS_AddChild(RuleInfo *read_rule);

/* Get first rule */
RuleNode *OS_GetFirstRule();


/** Defition of the internal rule IDS **
 ** These SIGIDs cannot be used       **
 **                                   **/
   
#define STATS_PLUGIN        11
#define FTS_PLUGIN          12
#define SYSCHECK_PLUGIN     13   
#define ROOTCHECK_PLUGIN    14   


/** Rule Path **/
#define RULEPATH "/rules"


#endif /* _OS_RULES */
