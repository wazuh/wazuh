/*   $OSSEC, rules.c, v0.5, 2005/09/21, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Functions to handle operation with the rules
 */

/* v0.1: 2004/04/05
 * v0.2: 2004/08/09
 * v0,3: 2005/03/27 (support to new OS_XML)
 * v0.4: 2005/05/30 (using a list instead of an array)
 * v0.5: 2005/09/21: Adding if_matched_sid and fix the priority of level 0
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"

#include "headers/defs.h"
#include "headers/debug_op.h"

#include "rules.h"
#include "config.h"

#include "error_messages/error_messages.h"

extern short int dbg_flag;

/* Internal functions */
int getattributes(char **attributes, char **values,
    int *id, int *level, int *maxsize, int *timeframe,
    int *frequency,int *accuracy, int *noalert, int *ignore_time);
void printrule(RuleInfo *config_rule);

RuleInfo *zerorulemember(int id, int level, int maxsize,
                           int frequency,int timeframe,
                           int noalert, int ignore_time
                           );
char *loadmemory(char *at, char *str);

/* Rules_OP_ReadRules, v0.1, 2005/07/04
 * Will initialize the rules list
 */
void Rules_OP_CreateRules()
{

     /* Initializing the rule list */
    OS_CreateRuleList();

    return;
}

/* Rules_OP_ReadRules, v0.3, 2005/03/21
 * Read the log rules.
 * v0.3: Fixed many memory problems.
 */ 
int Rules_OP_ReadRules(char * rulefile)
{
    OS_XML xml;
    XML_NODE node=NULL;

    /* XML variables */ 
    /* These are the available options for the rule configuration */
    
    char *xml_group="group";
    char *xml_rule="rule";

    char *xml_regex="regex";
    char *xml_match="match";
    char *xml_cve="cve";
    char *xml_info="info";
    char *xml_comment="comment";
    
    char *xml_srcip="srcip";
    char *xml_dstip="dstip";
    char *xml_user="user";
    
    char *xml_if_sid="if_sid";
    char *xml_if_group="if_group";
    char *xml_if_level="if_level";
    
    char *xml_if_matched_regex="if_matched_regex";
    char *xml_if_matched_group="if_matched_group";
    char *xml_if_matched_sid="if_matched_sid";
    
    char *xml_same_source_ip="same_source_ip";
    char *xml_same_user="same_user";
    char *xml_same_loghost="same_loghost";

    char *rulepath;
    
    int i;


    /* Building the rule file name + path */
    i = strlen(RULEPATH) + strlen(rulefile) + 2;
    rulepath = (char *)calloc(i,sizeof(char));
    if(!rulepath)
    {
        ErrorExit(MEM_ERROR,ARGV0);
    }
    
    snprintf(rulepath,i,"%s/%s",RULEPATH,rulefile);
    
    i = 0;    
    /* Reading the XML */       
    if(OS_ReadXML(rulepath,&xml) < 0)
    {
        merror("rules_op: XML error: %s",xml.err);
        return(-1);	
    }

    /* Zeroing the rule memory -- not used anymore */
    free(rulepath);
    
    
    /* Applying any variable found */
    if(OS_ApplyVariables(&xml) != 0)
    {
        merror("rules_op: Impossible to apply the variables.");
        return(-1);
    }


    /* Getting the root elements */
    node = OS_GetElementsbyNode(&xml,NULL);
    if(!node)
    {
        merror("rules_op: Bad configuration file syntax");
        OS_ClearXML(&xml);
        return(-1);    
    }

    /* Checking if there is any invalid global option */
    while(node[i])
    {
        if(node[i]->element)
        {
            if(strcasecmp(node[i]->element,xml_group) != 0)
            {
                merror("rules_op: Invalid root element \"%s\"."
                        "Only \"group\" is allowed",node[i]->element);
                OS_ClearXML(&xml);
                return(-1);
            }
            if((!node[i]->attributes) || (!node[i]->values)||
                    (!node[i]->values[0]) || (!node[i]->attributes[0]) ||
                    (strcasecmp(node[i]->attributes[0],"name") != 0) ||
                    (node[i]->attributes[1]))
            {
                merror("rules_op: Invalid root element '%s'."
                        "Only the group name is allowed",node[i]->element);
                OS_ClearXML(&xml);
                return(-1);
            }
        }
        else
        {
            merror("rules_op: Invalid root element. Unknown location");
            OS_ClearXML(&xml);
            return(-1);
        }
        i++;
    }

   
    i=0;
    while(node[i])
    {
        XML_NODE rule=NULL;

        char *group_name;
        int j=0;

        /* Getting all rules for a global group */        
        rule = OS_GetElementsbyNode(&xml,node[i]);
        if(rule == NULL)
        {
            merror("rules_op: Group \"%s\" without any rule.",
                    node[i]->element);
            i++;
            continue;
        }

        /* Group name. We Already checked it before */
        group_name = strdup(node[i]->values[0]);

        /* No recovery for that */
        if(!group_name)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }


        while(rule[j])
        {
            RuleInfo *config_ruleinfo=NULL;
            
            /* Checking if the rule name is correct */
            if((!rule[j]->element)||
                    (strcasecmp(rule[j]->element,xml_rule) != 0))
            {
                merror("rules_op: Invalid rules configuration. \"%s\""
                        " is not a valid element",rule[j]->element);
                OS_ClearXML(&xml);
                return(-1);
            }


            /* Checking for the attributes of the rule */
            if((!rule[j]->attributes) || (!rule[j]->values))
            {
                merror("rules_op: Invalid rule %d. You must specify"
                        " an ID and level (at least).",j);
                OS_ClearXML(&xml);
                return(-1);
            }

            /* Attribute block */
            {
                int id = -1,level = -1,maxsize = 0,timeframe = TIMEFRAME;
                int frequency = 0, accuracy = 1, noalert = 0, ignore_time = 0;
                if(getattributes(rule[j]->attributes,rule[j]->values,
                            &id,&level,&maxsize,&timeframe,
                            &frequency,&accuracy,&noalert,&ignore_time) < 0)
                {
                    merror("rules_op: Invalid attributes for rule %d",j);
                    OS_ClearXML(&xml);
                    return(-1);
                }
                if((id == -1) || (level == -1))
                {
                    merror("rules_op: No rule id or level specified for "
                            "rule %d.",j);
                    OS_ClearXML(&xml);
                    return(-1);
                }

                if((Config.accuracy == 1)&&(accuracy == 0))
                {
                    merror("rules_op: Ignoring rule %d. Not accurate",id);
                    continue;
                }
                
                /* Allocating memory and initializing structure */
                if((config_ruleinfo = zerorulemember(id, level, maxsize,
                            frequency,timeframe, noalert,ignore_time)) == NULL)
                {
                    merror("rules_op: Error accessing rules structure");
                    OS_ClearXML(&xml);
                    return(-1);
                }

                /* If rule is 0, set it to level 99 to have high priority.
                 * set it to 0 again later 
                 */
                 if(config_ruleinfo->level == 0)
                     config_ruleinfo->level = 99;
                     

            } /* end attributes/memory allocation block */


            /* Here we can assign the group name to the rule.
             * The level is correct so the rule is probably going to
             * be fine
             */

            config_ruleinfo -> group = strdup(group_name);
            
            if(!config_ruleinfo -> group)  
            {
                /* Every rule MUST be in some group */
                ErrorExit(MEM_ERROR,ARGV0);
            }

            /* Rule elements block */
            {
                XML_NODE rule_opt=NULL;
                int k=0;
                rule_opt =  OS_GetElementsbyNode(&xml,rule[j]);
                if(rule_opt == NULL)
                {
                    merror("rules_op: Rule %d without any element. "
                            "It may lead to false positives and some "
                            "other problems for the system.",
                            config_ruleinfo -> sigid);
                    break;
                    j++;
                }
                while(rule_opt[k])
                {
                    if((!rule_opt[k]->element)||(!rule_opt[k]->content))
                        break;
                    else if(strcasecmp(rule_opt[k]->element,xml_regex)==0)
                    {
                        config_ruleinfo-> regex =
                            loadmemory(config_ruleinfo-> regex,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_match)==0)
                    {
                        config_ruleinfo-> match=
                            loadmemory(config_ruleinfo-> match,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_info)==0)
                    {
                        config_ruleinfo-> info=
                            loadmemory(config_ruleinfo-> info,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_cve)==0)
                    {
                        config_ruleinfo-> cve=
                            loadmemory(config_ruleinfo-> cve,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_comment)==0)
                    {
                        config_ruleinfo-> comment=
                            loadmemory(config_ruleinfo-> comment,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_srcip)==0)
                    {
                        config_ruleinfo-> srcip=
                            loadmemory(config_ruleinfo->srcip,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_dstip)==0)
                    {
                        config_ruleinfo->dstip=
                            loadmemory(config_ruleinfo->dstip,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_user)==0)
                    {
                        config_ruleinfo->user=
                            loadmemory(config_ruleinfo->user,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_if_sid)==0)
                    {
                        config_ruleinfo->if_sid=
                            loadmemory(config_ruleinfo->if_sid,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_if_level)==0)
                    {
                        if(!OS_StrIsNum(rule_opt[k]->content))
                        {
                            ErrorExit("%s: Invalid configuration. If_level"
                                      "must be a valid level",ARGV0);
                        }

                        config_ruleinfo->if_level=
                            loadmemory(config_ruleinfo->if_level,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_if_group)==0)
                    {
                        config_ruleinfo->if_group=
                            loadmemory(config_ruleinfo->if_group,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_if_matched_regex)==0)
                    {
                        config_ruleinfo->context = 1;
                        config_ruleinfo->if_matched_regex=
                            loadmemory(config_ruleinfo->if_matched_regex,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_if_matched_group)==0)
                    {
                        config_ruleinfo->context = 1;
                        config_ruleinfo->if_matched_group=
                            loadmemory(config_ruleinfo->if_matched_group,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_if_matched_sid)==0)
                    {
                        config_ruleinfo->context = 1;
                        if(!OS_StrIsNum(rule_opt[k]->content))
                        {
                            ErrorExit("%s: Invalid configuration. If_match_sid"
                                    "must be an integer",ARGV0);
                        }
                        config_ruleinfo->if_matched_sid = atoi(rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_same_source_ip)==0)
                    {
                        config_ruleinfo->context = 1;
                        config_ruleinfo->same_source_ip = 1;
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_same_user)==0)
                    {
                        config_ruleinfo->context = 1;
                        config_ruleinfo->same_user = 1;
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_same_loghost)==0)
                    {
                        config_ruleinfo->context = 1;
                        config_ruleinfo->same_loghost = 1;
                    }
                    else
                    {
                        merror("rules_op: Invalid element \"%s\" for "
                                "rule %d",rule_opt[k]->element,
                                config_ruleinfo->sigid);
                        OS_ClearXML(&xml);
                        return(-1);
                    }
                    k++;
                }
            } /* enf of elements block */

            j++; /* next rule */

            printrule(config_ruleinfo);

            /* Adding rule to the rules list */
            /* If the rule dependes from some other,
             * add as a child */

            if((config_ruleinfo->if_sid)
                ||(config_ruleinfo->if_group)
                ||(config_ruleinfo->if_level))
            {
                OS_AddChild(config_ruleinfo);
            }
            else
            {    
                OS_AddRule(config_ruleinfo);
            }
            
            
        } /* while(rule[j]) */
        OS_ClearNode(rule);
        i++;
    } /* while (node[i]) */

    /* Cleaning global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    /* Setting levels 99 to zero again */
    {
        RuleNode *tmp_node = OS_GetFirstRule();
        while(tmp_node)
        {
            if(tmp_node->ruleinfo->level == 99)
                tmp_node->ruleinfo->level = 0;
            
            if(tmp_node->child)
            {
                RuleNode *child_node = tmp_node->child;
                while(child_node)
                {
                    if(child_node->ruleinfo->level == 99)
                        child_node->ruleinfo->level = 0;

                    child_node = child_node->next;
                }
            }
            tmp_node = tmp_node->next;
        }
        
    } /* Done with the levels */
    
    #ifdef DEBUG
    {
        RuleNode *dbg_node = OS_GetFirstRule();
        while(dbg_node)
        {
            printrule(dbg_node->ruleinfo);
            if(dbg_node->child)
            {
                RuleNode *child_node = dbg_node->child;

                printf("** Child Node for %d **\n",dbg_node->ruleinfo->sigid);
                while(child_node)
                {
                    printrule(child_node->ruleinfo);
                    child_node = child_node->next;
                }
            }
            dbg_node = dbg_node->next;
        }
    }
    #endif
    /* Done over here */
    return(0);
}


/* loadmemory: v0.1
 * Allocate memory at "*at" and copy *str to it.
 * If *at already exist, realloc the memory and cat str
 * on it.
 * It will return the new string
 */
char *loadmemory(char *at, char *str)
{
    if(at == NULL)
    {
        int strsize = 0;
        if((strsize = strlen(str)) < OS_RULESIZE)
        {
            at = calloc(strsize+1,sizeof(char));
            if(at == NULL)
            {
                merror(MEM_ERROR,ARGV0);
                return(NULL);
            }
            strncpy(at,str,strsize);
            return(at);
        }
        else
        {
            merror(SIZE_ERROR,ARGV0,str);
            return(NULL);
        }
    }
    else /*at is not null. Need to reallocat its memory and copy str to it*/
    {
        int strsize = strlen(str);
        int atsize = strlen(at);
        int finalsize = atsize+strsize+1;
        
        if((atsize > OS_RULESIZE) || (strsize > OS_RULESIZE))
        {
            merror(SIZE_ERROR,ARGV0,str);
            return(NULL);
        }
        
        at = realloc(at, (finalsize)*sizeof(char));
        
        if(at == NULL)
        {
            merror(MEM_ERROR,ARGV0);
            return(NULL);
        }
        
        strncat(at,str,strsize);
        
        at[finalsize-1]='\0';
        
        return(at);
    }
    return(NULL);
}

/* Print the rule info */
void printrule(RuleInfo *config_rule)
{
    #ifdef DEBUG
    void (*print_function) (const char * msg,... ) = &verbose;
    #else
    void (*print_function) (const char * msg,... ) = &debug1;
    #endif
     
    print_function("%s: Reading rule %d\n"
            "\t\tLevel: %d\n"
            "\t\tMatch: %s\n"
            "\t\tregex: %s\n"
            "\t\tContext: %d\n\n",
            ARGV0,
            config_rule -> sigid,
            config_rule -> level,
            config_rule ->match,
            config_rule ->regex,
            config_rule ->context);
}


/* Zero a rule member */
RuleInfo *zerorulemember(int id, int level, int maxsize,
                  int frequency, int timeframe, int noalert, int ignore_time)
{
    RuleInfo *ruleinfo_pt = NULL;
    
    /* Allocation memory for structure */
    /* int */
    ruleinfo_pt = (RuleInfo *)calloc(1,sizeof(RuleInfo));

    if(ruleinfo_pt == NULL)
    {
        merror(MEM_ERROR,ARGV0);
        return(NULL);
    }
    
    /* Default values */
    ruleinfo_pt->level = level;

    ruleinfo_pt->mailresponse = 0;
    ruleinfo_pt->logresponse = 0;

    if(Config.mailbylevel <= level)
        ruleinfo_pt->mailresponse = 1;
    if(Config.logbylevel <= level)    
        ruleinfo_pt->logresponse = 1;
    
    ruleinfo_pt->userresponse = 0;
    
    ruleinfo_pt->context = 0;
    
    ruleinfo_pt->sigid = id;
    ruleinfo_pt->firedtimes = 0;
    ruleinfo_pt->maxsize = maxsize;
    ruleinfo_pt->frequency = frequency;
    ruleinfo_pt->noalert = noalert;
    ruleinfo_pt->ignore_time = ignore_time;
    ruleinfo_pt->timeframe = timeframe;
    ruleinfo_pt->time_ignored = 0;
    
    ruleinfo_pt->same_source_ip = 0;
    ruleinfo_pt->same_user = 0;
    ruleinfo_pt->same_loghost = 0;

    ruleinfo_pt->group = NULL;
    ruleinfo_pt->regex = NULL;
    ruleinfo_pt->match = NULL;

    ruleinfo_pt->comment = NULL;
    ruleinfo_pt->info = NULL;
    ruleinfo_pt->cve = NULL;
    /*    ruleinfo_pt->external = NULL;*/
    
    ruleinfo_pt->if_sid = NULL;
    ruleinfo_pt->if_group = NULL;
    ruleinfo_pt->if_level = NULL;
    
    ruleinfo_pt->if_matched_regex = NULL;
    ruleinfo_pt->if_matched_group = NULL;
   
    ruleinfo_pt->user = NULL; 
    ruleinfo_pt->srcip = NULL;
    ruleinfo_pt->dstip = NULL;
    
    return(ruleinfo_pt);
}


/* Get the attributes */
int getattributes(char **attributes, char **values,
    int *id, int *level, int *maxsize, int *timeframe,
    int *frequency, int *accuracy, int *noalert, int *ignore_time)
{
    int k=0;
    
    char *xml_id="id";
    char *xml_level="level";
    char *xml_maxsize="maxsize";
    char *xml_timeframe="timeframe";
    char *xml_frequency="frequency";
    char *xml_accuracy="accuracy";
    char *xml_noalert="noalert";
    char *xml_ignore_time="ignore";
   
    /* Getting attributes */
    while(attributes[k])
    {
        if(!values[k])
        {
            merror("rules_op: Attribute \"%s\" without value."
                    ,attributes[k]);
            return(-1);
        }
        /* Getting rule Id */
        else if(strcasecmp(attributes[k],xml_id) == 0)
        {
            if(OS_StrIsNum(values[k]))
            {
                sscanf(values[k],"%6d",id);
            }
            else
            {
                merror("rules_op: Invalid rule id: %s. "
                        "Must be integer" ,
                        values[k]);
                return(-1);
            }
        }
        /* Getting level */
        else if(strcasecmp(attributes[k],xml_level) == 0)
        {
            if(OS_StrIsNum(values[k]))
            {
                sscanf(values[k],"%4d",level);
            }
            else
            {
                merror("rules_op: Invalid level: %s. "
                        "Must be integer" ,
                        values[k]);
                return(-1);
            }
        }
        /* Getting maxsize */
        else if(strcasecmp(attributes[k],xml_maxsize) == 0)
        {
            if(OS_StrIsNum(values[k]))
            {
                sscanf(values[k],"%4d",maxsize);
            }
            else
            {
                merror("rules_op: Invalid maxsize: %s. "
                        "Must be integer" ,
                        values[k]);
                return(-1);
            }
        }
        /* Getting timeframe */
        else if(strcasecmp(attributes[k],xml_timeframe) == 0)
        {
            if(OS_StrIsNum(values[k]))
            {
                sscanf(values[k],"%5d",timeframe);
            }
            else
            {
                merror("rules_op: Invalid timeframe: %s. "
                        "Must be integer" ,
                        values[k]);
                return(-1);
            }
        }
        /* Getting frequency */
        else if(strcasecmp(attributes[k],xml_frequency) == 0)
        {
            if(OS_StrIsNum(values[k]))
            {
                sscanf(values[k],"%4d",frequency);
            }
            else
            {
                merror("rules_op: Invalid frequency: %s. "
                        "Must be integer" ,
                        values[k]);
                return(-1);
            }
        }
        /* Rule accuracy */
        else if(strcasecmp(attributes[k],xml_accuracy) == 0)
        {
            if(OS_StrIsNum(values[k]))
            {
                sscanf(values[k],"%4d",accuracy);
            }
            else
            {
                merror("rules_op: Invalid accuracy: %s. "
                       "Must be integer" ,
                       values[k]);
                return(-1); 
            }
        }
         /* Rule ignore_time */
        else if(strcasecmp(attributes[k],xml_ignore_time) == 0)
        {
            if(OS_StrIsNum(values[k]))
            {
                sscanf(values[k],"%4d",ignore_time);
            }
            else
            {
                merror("rules_op: Invalid ignore_time: %s. "
                       "Must be integer" ,
                       values[k]);
                return(-1); 
            }
        }
        /* Rule noalert */
        else if(strcasecmp(attributes[k],xml_noalert) == 0)
        {
            *noalert = 1;
        }
        else
        {
            merror("rules_op: Invalid attribute \"%s\". "
                    "Only id, level, maxsize, accuracy, noalert and timeframe "
                    "are allowed.", attributes[k]);
            return(-1);
        }
        k++;
    }
    return(0);
}
