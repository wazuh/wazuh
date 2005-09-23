/*   $OSSEC, rules_list.c, v0.1, 2005/05/27, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "rules.h"
#include "headers/debug_op.h"

#include "os_regex/os_regex.h"

#include "error_messages/error_messages.h"

/* Rulenode global  */
RuleNode *rulenode;

/* _OS_Addrule: Internal AddRule */
RuleNode *_OS_AddRule(RuleNode *_rulenode, RuleInfo *read_rule);

/* Create the RuleList */
void OS_CreateRuleList()
{
    rulenode = NULL;

    return;
}

/* Get first node from rule */
RuleNode *OS_GetFirstRule()
{
    RuleNode *rulenode_pt = rulenode;
    
    return(rulenode_pt);    
}

/* Add a rule as a child in the list */
void _OS_AddAfterSid(int sid, RuleInfo *read_rule)
{
    RuleNode *rulenode_pt;

    rulenode_pt = OS_GetFirstRule();

    if(!rulenode_pt)
    {
        ErrorExit("rules_list: Rules in an inconsistent state. Exiting...");
    }
    
    while(rulenode_pt) 
    {
        if(rulenode_pt->ruleinfo->sigid == sid)
        {
            rulenode_pt->child=
                _OS_AddRule(rulenode_pt->child, read_rule);
            return;
        }
        rulenode_pt = rulenode_pt->next;
    }

    /* rule ID not found */
    ErrorExit("rules_list: rule ID '%d' not found ... ",sid);
}

/* Add a child */
int OS_AddChild(RuleInfo *read_rule)
{
    if(!read_rule)
    {
        merror("rules_list: Passing a NULL rule. Inconsistent state");
        return(1);
    }

    /* Adding for if_sid */    
    if(read_rule->if_sid)
    {
        int val=0;
        char *sid;
        
        sid  = read_rule->if_sid;
        
        /* Loop to read all the rules (comma or space separated */
        do
        {
            int rule_id = 0;
            if((*sid == ',')||(*sid == ' '))
            {
                val=0;
                continue;
            }
            else if((isdigit((int)*sid)) || (*sid == '\0'))
            {
                if(val == 0)
                {
                    rule_id = atoi(sid);
                    _OS_AddAfterSid(rule_id, read_rule);
                    val=1;
                }
            }
            else
            {
                ErrorExit("rules_list: Signature ID must be an integer. "
                          "Exiting...");
            }
        }while(*sid++ != '\0');
    }

    /* Adding for if_level */
    else if(read_rule->if_level)
    {
        int  ilevel = 0;

        RuleNode *rulenode_pt;

        ilevel = atoi(read_rule->if_level);
        if(ilevel == 0)
        {
            merror("%s: Invalid level (atoi)",ARGV0);
            return(1);
        }
        
        rulenode_pt = OS_GetFirstRule();

        if(!rulenode_pt)
        {
            ErrorExit("rules_list: Rules in an inconsistent state. Exiting.");
        }

        while(rulenode_pt)
        {
            if(rulenode_pt->ruleinfo->level >= ilevel)
            {
                /* We will loop on all rules until we find */
                rulenode_pt->child=
                    _OS_AddRule(rulenode_pt->child, read_rule);
            }
            rulenode_pt = rulenode_pt->next;
        }
    }

    /* Adding for if_group */    
    else if(read_rule->if_group)
    {
        char *group;
        RuleNode *rulenode_pt;
        
        group  = read_rule->if_group;

        rulenode_pt = OS_GetFirstRule();

        if(!rulenode_pt)
        {
            ErrorExit("rules_list: Rules in an inconsistent state. Exiting.");
        }

        while(rulenode_pt) 
        {
            if(OS_WordMatch(group,rulenode_pt->ruleinfo->group))
            {
                /* We will loop on all rules until we find */
                rulenode_pt->child=
                    _OS_AddRule(rulenode_pt->child, read_rule);
            }
            rulenode_pt = rulenode_pt->next;
        }
    }


    /* done over here */
    return(0);
}



/* Add a rule in the chain */
RuleNode *_OS_AddRule(RuleNode *_rulenode, RuleInfo *read_rule)
{
    RuleNode *tmp_rulenode = _rulenode;
        
    if(tmp_rulenode != NULL)
    {
        int middle_insertion = 0;
        RuleNode *prev_rulenode = NULL;
        RuleNode *new_rulenode = NULL;
        
        while(tmp_rulenode != NULL)
        {
            if(read_rule->level >= tmp_rulenode->ruleinfo->level)
            {
                middle_insertion = 1;
                break;
            }
            prev_rulenode = tmp_rulenode;
            tmp_rulenode = tmp_rulenode->next;
        }
        
        new_rulenode = (RuleNode *)calloc(1,sizeof(RuleNode));

        if(!new_rulenode)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        if(middle_insertion == 1)
        {
            if(prev_rulenode == NULL)
            {
                _rulenode = new_rulenode;
            }
            else
            {
                prev_rulenode->next = new_rulenode;
            }
            
            new_rulenode->next = tmp_rulenode;
            new_rulenode->ruleinfo = read_rule;
            new_rulenode->child = NULL;
        }
       
        else
        {
            prev_rulenode->next = new_rulenode;
            prev_rulenode->next->ruleinfo = read_rule;
            prev_rulenode->next->next = NULL;            
            prev_rulenode->next->child = NULL;            
        }
    }
    
    else
    {
        _rulenode = (RuleNode *)calloc(1,sizeof(RuleNode));
        if(_rulenode == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        _rulenode->ruleinfo = read_rule;
        _rulenode->next = NULL;
        _rulenode->child= NULL;
    }

    return(_rulenode);
}

/* External AddRule */
int OS_AddRule(RuleInfo *read_rule)
{
    rulenode = _OS_AddRule(rulenode,read_rule);

    return(0);
}
/* EOF */
