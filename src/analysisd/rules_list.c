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


/* Search all rules, including childs */
int _AddtoRule(int sid, int level, int none, char *group, 
               RuleNode *r_node, RuleInfo *read_rule)
{
    int r_code = 0;
    
    /* If we don't have the first node, start from
     * the beginning of the list
     */
    if(!r_node)
    {
        r_node = OS_GetFirstRule();
    }

    while(r_node)
    {

        /* Checking if the sigid matches */
        if(sid)
        {    
            if(r_node->ruleinfo->sigid == sid)
            {
                /* Assign the category of this rule to the child 
                 * as they must match
                 */
                read_rule->category = r_node->ruleinfo->category;

                /* If matched sid */
                if(read_rule->if_matched_sid)
                {
                    /* If child does not have a list, create one */
                    if(!r_node->ruleinfo->prev_matched)
                    {
                        r_node->ruleinfo->prev_matched = OSList_Create();
                        if(!r_node->ruleinfo->prev_matched)
                        {
                            ErrorExit(MEM_ERROR, ARGV0);
                        }
                    }

                    /* Assigning the parent pointer to it */
                    read_rule->sid_search = r_node->ruleinfo->prev_matched;
                }

                /* If no context for rule, check if the parent has
                 * and use it.
                 */
                if(!read_rule->last_events && r_node->ruleinfo->last_events)
                {
                    read_rule->last_events = r_node->ruleinfo->last_events;
                }
                
                r_node->child=
                    _OS_AddRule(r_node->child, read_rule);
                return(1);
            }
        }
        
        /* Checking if the group matches */
        else if(group)
        {
            if(OS_WordMatch(group, r_node->ruleinfo->group))
            {
                /* If no context for rule, check if the parent has
                 * and use it.
                 */
                if(!read_rule->last_events && r_node->ruleinfo->last_events)
                {
                    read_rule->last_events = r_node->ruleinfo->last_events;
                }

                /* We will loop on all rules until we find */
                r_node->child =
                    _OS_AddRule(r_node->child, read_rule);
                r_code = 1;
            }
        }
        
        /* If we are not searching for the sid/group, the category must
         * be the same. 
         */
        else if(read_rule->category != r_node->ruleinfo->category)
        {
            r_node = r_node->next;
            continue;
        }

        
        /* Checking if the level matches */
        else if(level)
        {
            if((r_node->ruleinfo->level >= level) && 
               (r_node->ruleinfo->sigid != read_rule->sigid) &&
               (r_node->ruleinfo->context == 0))
            {
                r_node->child=
                    _OS_AddRule(r_node->child, read_rule);
                r_code = 1;
            }
        }
        
        /* If none of them is set, add for the category */
        else
        {
            /* Setting the parent category to it */
            read_rule->category = r_node->ruleinfo->category;
            r_node->child =
                    _OS_AddRule(r_node->child, read_rule);
            return(1);
        }

        /* Checking if the child has a rule */
        if(r_node->child)
        {
            if(_AddtoRule(sid, level, none, group, r_node->child, read_rule))
            {
                r_code = 1;
            }
        }

        r_node = r_node->next;
    }
    
    return(r_code);    
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
        int val = 0;
        char *sid;
        
        sid  = read_rule->if_sid;
        
        /* Loop to read all the rules (comma or space separated */
        do
        {
            int rule_id = 0;
            if((*sid == ',')||(*sid == ' '))
            {
                val = 0;
                continue;
            }
            else if((isdigit((int)*sid)) || (*sid == '\0'))
            {
                if(val == 0)
                {
                    rule_id = atoi(sid);
                    if(!_AddtoRule(rule_id, 0, 0, NULL, NULL, read_rule))
                    {
                        ErrorExit("rules_list: Signature ID '%d' not "
                                  "found. Invalid 'if_sid'.", rule_id);
                    }
                    val = 1;
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

        ilevel = atoi(read_rule->if_level);
        if(ilevel == 0)
        {
            merror("%s: Invalid level (atoi)",ARGV0);
            return(1);
        }

        ilevel*=100;

        if(!_AddtoRule(0, ilevel, 0, NULL, NULL, read_rule))
        {
            ErrorExit("rules_list: Level ID '%d' not "
                    "found. Invalid 'if_level'.", ilevel);
        }
    }

    /* Adding for if_group */    
    else if(read_rule->if_group)
    {
        if(!_AddtoRule(0, 0, 0, read_rule->if_group, NULL, read_rule))
        {
            ErrorExit("rules_list: Group '%s' not "
                      "found. Invalid 'if_group'.", read_rule->if_group);
        }
    }
    
    /* Just add based on the category */
    else
    {
        if(!_AddtoRule(0, 0, 0, NULL, NULL, read_rule))
        {
            ErrorExit("rules_list: Category '%d' not "
                    "found. Invalid 'category'.", read_rule->category);
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
            if(read_rule->level > tmp_rulenode->ruleinfo->level)
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
