/*   $OSSEC, rules.c, v0.6, 2005/10/30, Daniel B. Cid$   */

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
 * v0.6: 2005/10/30: Adding support for the active response
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"

#include "shared.h"

#include "rules.h"
#include "config.h"
#include "eventinfo.h"
#include "active-response.h"


/* Internal functions */
int getattributes(char **attributes, 
                  char **values,
                  int *id, int *level, 
                  int *maxsize, int *timeframe,
                  int *frequency, int *accuracy, 
                  int *noalert, int *ignore_time);

RuleInfo *zerorulemember(int id, int level, 
                         int maxsize, int frequency,
                         int timeframe, int noalert,
                         int ignore_time);

void printrule(RuleInfo *config_rule);
void Rule_AddAR(RuleInfo *config_rule);
char *loadmemory(char *at, char *str);
void _setlevels(RuleNode *node);



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
    XML_NODE node = NULL;

    /* XML variables */ 
    /* These are the available options for the rule configuration */
    
    char *xml_group = "group";
    char *xml_rule = "rule";

    char *xml_regex = "regex";
    char *xml_match = "match";
    char *xml_decoded = "decoded_as";
    char *xml_category = "category";
    char *xml_cve = "cve";
    char *xml_info = "info";
    char *xml_comment = "description";
    
    char *xml_srcip = "srcip";
    char *xml_dstip = "dstip";
    char *xml_user = "user";
    char *xml_url = "url";
    char *xml_id = "id";
    
    char *xml_if_sid = "if_sid";
    char *xml_if_group = "if_group";
    char *xml_if_level = "if_level";
    char *xml_fts = "if_fts";
    
    char *xml_if_matched_regex = "if_matched_regex";
    char *xml_if_matched_group = "if_matched_group";
    char *xml_if_matched_sid = "if_matched_sid";
    
    char *xml_same_source_ip = "same_source_ip";
    char *xml_same_user = "same_user";
    char *xml_same_loghost = "same_loghost";

    char *xml_options = "options";
    
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
        merror(XML_ERROR, ARGV0, xml.err, xml.err_line);
        free(rulepath);
        return(-1);	
    }

    /* Zeroing the rule memory -- not used anymore */
    free(rulepath);
    
    
    /* Applying any variable found */
    if(OS_ApplyVariables(&xml) != 0)
    {
        merror(XML_ERROR_VAR, ARGV0);
        return(-1);
    }


    /* Getting the root elements */
    node = OS_GetElementsbyNode(&xml,NULL);
    if(!node)
    {
        merror(CONFIG_ERROR, ARGV0);
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
            merror(XML_READ_ERROR, ARGV0);
            OS_ClearXML(&xml);
            return(-1);
        }
        i++;
    }


    /* Getting the rules now */   
    i=0;
    while(node[i])
    {
        XML_NODE rule = NULL;

        char *group_name;
        int j = 0;

        /* Getting all rules for a global group */        
        rule = OS_GetElementsbyNode(&xml,node[i]);
        if(rule == NULL)
        {
            merror("%s: Group '%s' without any rule.",
                    ARGV0, node[i]->element);
            OS_ClearXML(&xml);
            return(-1);
        }

        
        /* Group name. We Already checked it before */
        os_strdup(node[i]->values[0], group_name);


        while(rule[j])
        {
            RuleInfo *config_ruleinfo = NULL;
           

            /* Checking if the rule element is correct */
            if((!rule[j]->element)||
                    (strcasecmp(rule[j]->element,xml_rule) != 0))
            {
                merror("%s: Invalid configuration. '%s' is not "
                       "a valid element.", ARGV0, rule[j]->element);
                OS_ClearXML(&xml);
                return(-1);
            }


            /* Checking for the attributes of the rule */
            if((!rule[j]->attributes) || (!rule[j]->values))
            {
                merror("%s: Invalid rule '%d'. You must specify"
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
                    merror("%s: Invalid attributes for rule '%d'", ARGV0, j);
                    OS_ClearXML(&xml);
                    return(-1);
                }
                
                if((id == -1) || (level == -1))
                {
                    merror("%s: No rule id or level specified for "
                            "rule '%d'.",ARGV0, j);
                    OS_ClearXML(&xml);
                    return(-1);
                }

                /* Allocating memory and initializing structure */
                config_ruleinfo = zerorulemember(id, level, maxsize,
                            frequency,timeframe, noalert,ignore_time);
                

                /* If rule is 0, set it to level 99 to have high priority.
                 * set it to 0 again later 
                 */
                 if(config_ruleinfo->level == 0)
                     config_ruleinfo->level = 99;

                 
                 /* Each level now is going to be multiplied by 100.
                  * If the accuracy is set to 0 we don't multiply,
                  * so it will be at the end of the list. We will
                  * divide by 100 later.
                  */
                 if(accuracy)
                 {
                     config_ruleinfo->level *= 100;
                 }
                     

            } /* end attributes/memory allocation block */


            /* Here we can assign the group name to the rule.
             * The level is correct so the rule is probably going to
             * be fine
             */
            os_strdup(group_name, config_ruleinfo->group);
            

            /* Rule elements block */
            {
                int k = 0;
                char *regex = NULL;
                char *url = NULL;
                char *if_matched_regex = NULL;
                
                XML_NODE rule_opt = NULL;
                rule_opt =  OS_GetElementsbyNode(&xml,rule[j]);
                if(rule_opt == NULL)
                {
                    merror("%s: Rule '%d' without any option. "
                            "It may lead to false positives and some "
                            "other problems for the system. Exiting.",
                            ARGV0, config_ruleinfo->sigid);
                    OS_ClearXML(&xml);
                    return(-1);       
                }
                
                while(rule_opt[k])
                {
                    if((!rule_opt[k]->element)||(!rule_opt[k]->content))
                        break;
                    else if(strcasecmp(rule_opt[k]->element,xml_regex)==0)
                    {
                        regex =
                            loadmemory(regex,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_match)==0)
                    {
                        config_ruleinfo->match=
                            loadmemory(config_ruleinfo->match,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element, xml_decoded)==0)
                    {
                        config_ruleinfo->plugin_decoded =
                            loadmemory(config_ruleinfo->plugin_decoded,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_info)==0)
                    {
                        config_ruleinfo->info=
                            loadmemory(config_ruleinfo->info,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_cve)==0)
                    {
                        config_ruleinfo->cve=
                            loadmemory(config_ruleinfo->cve,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_comment)==0)
                    {
                        config_ruleinfo->comment=
                            loadmemory(config_ruleinfo->comment,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_srcip)==0)
                    {
                        config_ruleinfo->srcip=
                            loadmemory(config_ruleinfo->srcip,
                                    rule_opt[k]->content);
                        if(!OS_IsValidIP(config_ruleinfo->srcip))
                        {
                            merror(INVALID_IP, ARGV0, config_ruleinfo->srcip);
                            return(-1);
                        }
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_dstip)==0)
                    {
                        config_ruleinfo->dstip=
                            loadmemory(config_ruleinfo->dstip,
                                    rule_opt[k]->content);
                        if(!OS_IsValidIP(config_ruleinfo->dstip))
                        {
                            merror(INVALID_IP, ARGV0, config_ruleinfo->dstip);
                            return(-1);
                        }

                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_user)==0)
                    {
                        config_ruleinfo->user=
                            loadmemory(config_ruleinfo->user,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_id)==0)
                    {
                        config_ruleinfo->id=
                            loadmemory(config_ruleinfo->id,
                                    rule_opt[k]->content);
                    }
                    
                    else if(strcasecmp(rule_opt[k]->element,xml_url)==0)
                    {
                        url=
                            loadmemory(url,
                                    rule_opt[k]->content);
                    }
                    
                    /* We allow these four categories so far */
                    else if(strcasecmp(rule_opt[k]->element, xml_category)==0)
                    {
                        if(strcmp(rule_opt[k]->content, "firewall") == 0)
                        {
                            config_ruleinfo->category = FIREWALL;
                        }
                        else if(strcmp(rule_opt[k]->content, "ids") == 0)
                        {
                            config_ruleinfo->category = IDS;
                        }
                        else if(strcmp(rule_opt[k]->content, "syslog") == 0)
                        {
                            config_ruleinfo->category = SYSLOG;
                        }
                        else if(strcmp(rule_opt[k]->content, "apache") == 0)
                        {
                            config_ruleinfo->category = APACHE;
                        }
                        else
                        {
                            ErrorExit("%s: Invalid category '%s' chosen",
                                      ARGV0, rule_opt[k]->content);
                        }
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
                            merror("%s: Invalid configuration. If_level '%s'"
                                      "must be a valid level.",
                                      ARGV0, rule_opt[k]->content);
                            return(-1);
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
                        if_matched_regex=
                            loadmemory(if_matched_regex,
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
                            merror("%s: Invalid configuration. If_match_sid '%s' "
                                   "must be an integer",ARGV0, rule_opt[k]->content);
                            return(-1);
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
                                xml_fts) == 0)
                    {
                        config_ruleinfo->fts = 1;
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
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_options) == 0)
                    {
                        if(OS_Regex("notify_by_email", rule_opt[k]->content))
                        {
                            config_ruleinfo->emailalert = 1;
                        }
                        if(OS_Regex("generate_log", rule_opt[k]->content))
                        {
                            config_ruleinfo->logalert = 1;
                        }
                    }
                    else
                    {
                        merror("%s: Invalid option '%s' for "
                                "rule '%d'",ARGV0, rule_opt[k]->element,
                                config_ruleinfo->sigid);
                        OS_ClearXML(&xml);
                        return(-1);
                    }
                    k++;
                }

                /* Checking the regexes */
                if(regex)
                {
                    os_calloc(1, sizeof(OSRegex), config_ruleinfo->regex);
                    if(!OSRegex_Compile(regex, config_ruleinfo->regex, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, regex, 
                                config_ruleinfo->regex->error);
                    }
                }
                
                if(url)
                {
                    os_calloc(1, sizeof(OSRegex), config_ruleinfo->url);
                    if(!OSRegex_Compile(url, config_ruleinfo->url, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, url, 
                                config_ruleinfo->url->error);
                    }
                }
                
                if(if_matched_regex)
                {
                    os_calloc(1, sizeof(OSRegex), 
                            config_ruleinfo->if_matched_regex);
                    if(!OSRegex_Compile(if_matched_regex, 
                                config_ruleinfo->if_matched_regex, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, if_matched_regex, 
                                config_ruleinfo->if_matched_regex->error);
                    }
                }
            } /* enf of elements block */


            /* Assigning an active response to the rule */
            Rule_AddAR(config_ruleinfo);

            
            j++; /* next rule */

            
            printrule(config_ruleinfo);


            /* Adding the rule to the rules list.
             * Only the template rules are supposed
             * to be at the top level. All others
             * will be a "child" of someone.
             */
            if(config_ruleinfo->sigid < 10)
            {    
                OS_AddRule(config_ruleinfo);
            }
            else
            {
                OS_AddChild(config_ruleinfo);
            }

            
        } /* while(rule[j]) */
        OS_ClearNode(rule);
        i++;
        
    } /* while (node[i]) */

    /* Cleaning global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    /* Setting the levels to the right place again */
    {
        RuleNode *tmp_node = OS_GetFirstRule();

        _setlevels(tmp_node);
        
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
            config_rule ->sigid,
            config_rule ->level,
            config_rule ->match,
            config_rule ->regex,
            config_rule ->context);
}



RuleInfo *zerorulemember(int id, int level, 
                         int maxsize, int frequency,
                         int timeframe, int noalert, 
                         int ignore_time)
{
    RuleInfo *ruleinfo_pt = NULL;
    
    /* Allocation memory for structure */
    ruleinfo_pt = (RuleInfo *)calloc(1,sizeof(RuleInfo));

    if(ruleinfo_pt == NULL)
    {
        ErrorExit(MEM_ERROR,ARGV0);
    }
    
    /* Default values */
    ruleinfo_pt->level = level;

    /* Default category is syslog */
    ruleinfo_pt->category = SYSLOG;

    ruleinfo_pt->emailalert = 0;
    ruleinfo_pt->logalert = 0;

    if(Config.mailbylevel <= level)
        ruleinfo_pt->emailalert = 1;
    if(Config.logbylevel <= level)    
        ruleinfo_pt->logalert = 1;
   
    ruleinfo_pt->ar = NULL; 
    
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
    ruleinfo_pt->fts = 0;
    ruleinfo_pt->same_user = 0;
    ruleinfo_pt->same_loghost = 0;

    ruleinfo_pt->group = NULL;
    ruleinfo_pt->regex = NULL;
    ruleinfo_pt->match = NULL;
    ruleinfo_pt->plugin_decoded = NULL;

    ruleinfo_pt->comment = NULL;
    ruleinfo_pt->info = NULL;
    ruleinfo_pt->cve = NULL;
    
    ruleinfo_pt->if_sid = NULL;
    ruleinfo_pt->if_group = NULL;
    ruleinfo_pt->if_level = NULL;
    
    ruleinfo_pt->if_matched_regex = NULL;
    ruleinfo_pt->if_matched_group = NULL;
   
    ruleinfo_pt->user = NULL; 
    ruleinfo_pt->srcip = NULL;
    ruleinfo_pt->dstip = NULL;
    ruleinfo_pt->url = NULL;
    ruleinfo_pt->id = NULL;
    
    /* Zeroing last matched events */
    ruleinfo_pt->__frequency = 0;
    {
        int i = 0;
        while(i <= MAX_LAST_EVENTS)
        { 
            ruleinfo_pt->last_events[i] = NULL;
            i++;
        }
    }

    return(ruleinfo_pt);
}


/* Get the attributes */
int getattributes(char **attributes, char **values,
                  int *id, int *level, 
                  int *maxsize, int *timeframe,
                  int *frequency, int *accuracy, 
                  int *noalert, int *ignore_time)
{
    int k=0;
    
    char *xml_id = "id";
    char *xml_level = "level";
    char *xml_maxsize = "maxsize";
    char *xml_timeframe = "timeframe";
    char *xml_frequency = "frequency";
    char *xml_accuracy = "accuracy";
    char *xml_noalert = "noalert";
    char *xml_ignore_time = "ignore";
   
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


/* Bind active responses to the rule.
 * No return.
 */
void Rule_AddAR(RuleInfo *rule_config)
{
    int rule_ar_size = 0;
    int mark_to_ar = 0;
    int rule_real_level = 0;
    
    OSListNode *my_ars_node;
    
    
    /* Setting the correctly levels 
     * We play internally with the rules, to set
     * the priorities... Rules with 0 of accuracy,
     * receive a low level and go down in the list
     */
    if(rule_config->level == 9900)
        rule_real_level = 0;
    
    if(rule_config->level > 100)
        rule_real_level = rule_config->level/100;
    
    
    /* No AR for ignored rules */
    if(rule_config->level == 0)
    {
        return;
    }
    
    /* Looping on all AR */
    my_ars_node = OSList_GetFirstNode(active_responses);
    while(my_ars_node)
    {
        active_response *my_ar;

        my_ar = (active_response *)my_ars_node->data;
        mark_to_ar = 0;

        /* Checking if the level for the ar is higher */
        if(my_ar->level)
        {
            int ar_level = atoi(my_ar->level);

            if(rule_config->level >= ar_level)
            {
                mark_to_ar = 1;
            }
        }
       
        /* Checking if group matches */
        if(my_ar->rules_group)
        {
           if(OS_Regex(my_ar->rules_group, rule_config->group))
           {
               mark_to_ar = 1;
           }
        }
        
        /* Checking if rule id matches */
        if(my_ar->rules_id)
        {
            int r_id = 0;
            char *str_pt = my_ar->rules_id;

            while(*str_pt != '\0')
            {
                /* We allow spaces in between */
                if(*str_pt == ' ')
                {
                    str_pt++;
                    continue;
                }

                /* If is digit, we get the value
                 * and search for the next digit
                 * available
                 */
                else if(isdigit(*str_pt))
                {
                    r_id = atoi(str_pt);
                    
                    /* mark to ar if id matches */
                    if(r_id == rule_config->sigid)
                    {
                        mark_to_ar = 1;
                    }
                    
                    str_pt = index(str_pt, ',');
                    if(str_pt)
                    {
                        str_pt++;
                    }
                    else
                    {
                        break;
                    }
                }

                else
                {
                    break;
                }
            }
        } /* eof of rules_id */
 
        
        /* Bind AR to the rule */ 
        if(mark_to_ar == 1)
        {
            rule_ar_size++;

            rule_config->ar = realloc(rule_config->ar,
                                      (rule_ar_size + 1)
                                      *sizeof(active_response *));
            
            /* Always set the last node to NULL */
            rule_config->ar[rule_ar_size - 1] = my_ar;
            rule_config->ar[rule_ar_size] = NULL;  
        }
        
        my_ars_node = OSList_GetNextNode(active_responses);
    }

    return;
}

/* _set levels */
void _setlevels(RuleNode *node)
{
    while(node)
    {
        if(node->ruleinfo->level == 9900)
            node->ruleinfo->level = 0;

        if(node->ruleinfo->level > 100)
            node->ruleinfo->level/=100;

        if(node->child)
        {
            _setlevels(node->child);
        }

        node = node->next;
    }
}

/* EOF */
