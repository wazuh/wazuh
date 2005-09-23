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

typedef struct _RuleInfo
{
    int sigid;  /* id attribute -- required*/
    int level;  /* level attribute --required */

    int context; /* Not an option */
    int firedtimes;  /* Not an option */
    int time_ignored; /* Not a user option */
    int ignore_time;
    
    /* Not an option in the rule */
    short int mailresponse;
    short int logresponse;
    short int userresponse;

    int maxsize; /* maxsize attribute */
    int frequency; /* frequency attribute */
    int timeframe; /* timeframe attribute */
    int noalert;   /* No alert flag */

    int same_source_ip;
    int same_user;
    int same_loghost;

    char *group; /* group */
    char *regex; /* regex */
    char *match; /* match */

    char *comment;
    char *info;
    char *cve;
    
    /*char *external;*/ /* external command execution */

    char *if_sid;          /* If signature id was matched */
    char *if_level;        /* If any level => was matched */
    char *if_group;        /* If group was matched */
    
    char *if_matched_regex;
    char *if_matched_group;
    int if_matched_sid;

    char *srcip;
    char *dstip;
    char *user;

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
#define SNORT_FTS_PLUGIN    13
#define SYSCHECK_PLUGIN     14   


/** Rule Path **/
#define RULEPATH "/rules"


#endif /* _OS_RULES */
