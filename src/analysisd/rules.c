/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "os_regex/os_regex.h"
#include "os_xml/os_xml.h"


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


void Rule_AddAR(RuleInfo *config_rule);
char *loadmemory(char *at, char *str);

extern int _max_freq;



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
    char *xml_day_time = "time";
    char *xml_week_day = "weekday";
    char *xml_comment = "description";
    char *xml_ignore = "ignore";
    char *xml_check_if_ignored = "check_if_ignored";
    
    char *xml_srcip = "srcip";
    char *xml_dstip = "dstip";
    char *xml_user = "user";
    char *xml_url = "url";
    char *xml_id = "id";
    char *xml_data = "extra_data";
    char *xml_hostname = "hostname";
    char *xml_program_name = "program_name";
    char *xml_status = "status";
    char *xml_action = "action";
    
    char *xml_if_sid = "if_sid";
    char *xml_if_group = "if_group";
    char *xml_if_level = "if_level";
    char *xml_fts = "if_fts";
    
    char *xml_if_matched_regex = "if_matched_regex";
    char *xml_if_matched_group = "if_matched_group";
    char *xml_if_matched_sid = "if_matched_sid";
    
    char *xml_same_source_ip = "same_source_ip";
    char *xml_same_user = "same_user";
    char *xml_same_agent = "same_agent";
    char *xml_same_id = "same_id";

    char *xml_different_url = "different_url";
    
    char *xml_notsame_source_ip = "not_same_source_ip";
    char *xml_notsame_user = "not_same_user";
    char *xml_notsame_agent = "not_same_agent";
    char *xml_notsame_id = "not_same_id";

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
        merror(XML_ERROR, ARGV0, rulepath, xml.err, xml.err_line);
        free(rulepath);
        return(-1);	
    }

    /* Zeroing the rule memory -- not used anymore */
    free(rulepath);
    
    
    /* Applying any variable found */
    if(OS_ApplyVariables(&xml) != 0)
    {
        merror(XML_ERROR_VAR, ARGV0, rulepath);
        return(-1);
    }


    /* Getting the root elements */
    node = OS_GetElementsbyNode(&xml,NULL);
    if(!node)
    {
        merror(CONFIG_ERROR, ARGV0, rulepath);
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
                        " an ID and a level at least.",j);
                OS_ClearXML(&xml);
                return(-1);
            }

            
            /* Attribute block */
            {
                int id = -1,level = -1,maxsize = 0,timeframe = 0;
                int frequency = 0, accuracy = 1, noalert = 0, ignore_time = 0;
                
                /* Getting default time frame */
                timeframe = getDefine_Int("analysisd", 
                                          "default_timeframe", 
                                          60, 3600);
                
                if(getattributes(rule[j]->attributes,rule[j]->values,
                            &id,&level,&maxsize,&timeframe,
                            &frequency,&accuracy,&noalert,&ignore_time) < 0)
                {
                    merror("%s: Invalid attribute for rule.", ARGV0);
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
            os_strdup(node[i]->values[0], config_ruleinfo->group);
            

            /* Rule elements block */
            {
                int k = 0;
                char *regex = NULL;
                char *match = NULL;
                char *url = NULL;
                char *if_matched_regex = NULL;
                char *if_matched_group = NULL;
                char *user = NULL;
                char *id = NULL;
                char *status = NULL;
                char *hostname = NULL;
                char *extra_data = NULL;
                char *program_name = NULL;
                
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
                        match =
                            loadmemory(match,
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
                    else if(strcasecmp(rule_opt[k]->element,xml_day_time)==0)
                    {
                        config_ruleinfo->day_time = 
                            OS_IsValidTime(rule_opt[k]->content);
                        if(!config_ruleinfo->day_time)
                        {
                            merror(INVALID_CONFIG, ARGV0,
                                    rule_opt[k]->element,
                                    rule_opt[k]->content);
                            return(-1);
                        }
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_week_day)==0)
                    {
                        config_ruleinfo->week_day = 
                            OS_IsValidDay(rule_opt[k]->content);
                            
                        if(!config_ruleinfo->week_day)
                        {
                            merror(INVALID_CONFIG, ARGV0,
                                    rule_opt[k]->element,
                                    rule_opt[k]->content);
                            return(-1);
                        }

                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_group)==0)
                    {
                        config_ruleinfo->group =
                            loadmemory(config_ruleinfo->group,
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
                        int ip_s = 0;
                        
                        /* Getting size of source ip list */
                        while(config_ruleinfo->srcip && 
                              config_ruleinfo->srcip[ip_s])
                        {
                            ip_s++;
                        }
                        
                        config_ruleinfo->srcip = 
                                    realloc(config_ruleinfo->srcip,
                                    (ip_s + 2) * sizeof(os_ip *));
                        
                        
                        /* Allocating memory for the individual entries */
                        os_calloc(1, sizeof(os_ip), 
                                     config_ruleinfo->srcip[ip_s]);
                        config_ruleinfo->srcip[ip_s +1] = NULL;
                        
                        
                        /* Checking if the ip is valid */
                        if(!OS_IsValidIP(rule_opt[k]->content, 
                                         config_ruleinfo->srcip[ip_s]))
                        {
                            merror(INVALID_IP, ARGV0, rule_opt[k]->content);
                            return(-1);
                        }
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_dstip)==0)
                    {
                        int ip_s = 0;

                        /* Getting size of source ip list */
                        while(config_ruleinfo->dstip &&
                                config_ruleinfo->dstip[ip_s])
                        {
                            ip_s++;
                        }

                        config_ruleinfo->dstip =
                                    realloc(config_ruleinfo->dstip,
                                    (ip_s + 2) * sizeof(os_ip *));


                        /* Allocating memory for the individual entries */
                        os_calloc(1, sizeof(os_ip),
                                config_ruleinfo->dstip[ip_s]);
                        config_ruleinfo->dstip[ip_s +1] = NULL;


                        /* Checking if the ip is valid */
                        if(!OS_IsValidIP(rule_opt[k]->content,
                                    config_ruleinfo->dstip[ip_s]))
                        {
                            merror(INVALID_IP, ARGV0, rule_opt[k]->content);
                            return(-1);
                        }
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_user)==0)
                    {
                        user =
                            loadmemory(user,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_id)==0)
                    {
                        id =
                            loadmemory(id,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_status)==0)
                    {
                        status =
                            loadmemory(status,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_hostname)==0)
                    {
                        hostname =
                            loadmemory(hostname,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_data)==0)
                    {
                        extra_data =
                            loadmemory(extra_data,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                       xml_program_name)==0)
                    {
                        program_name =
                            loadmemory(program_name,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_action)==0)
                    {
                        config_ruleinfo->action = 
                            loadmemory(config_ruleinfo->action,
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
                        else if(strcmp(rule_opt[k]->content, "web-log") == 0)
                        {
                            config_ruleinfo->category = WEBLOG;
                        }
                        else if(strcmp(rule_opt[k]->content, "squid") == 0)
                        {
                            config_ruleinfo->category = SQUID;
                        }
                        else if(strcmp(rule_opt[k]->content,"windows") == 0)
                        {
                            config_ruleinfo->category = WINDOWS;
                        }
                        else
                        {
                            merror(INVALID_CAT, ARGV0, rule_opt[k]->content);
                            return(-1);
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
                            merror(INVALID_CONFIG, ARGV0, 
                                    "if_level",
                                    rule_opt[k]->content); 
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
                        if_matched_group=
                            loadmemory(if_matched_group,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,xml_if_matched_sid)==0)
                    {
                        config_ruleinfo->context = 1;
                        if(!OS_StrIsNum(rule_opt[k]->content))
                        {
                            merror(INVALID_CONFIG, ARGV0,
                                    "if_matched_sid",
                                    rule_opt[k]->content);
                            return(-1);
                        }
                        config_ruleinfo->if_matched_sid = 
                            atoi(rule_opt[k]->content);

                        /* If_matched_sid, we need to get the if_sid */
                        config_ruleinfo->if_sid=
                            loadmemory(config_ruleinfo->if_sid,
                                    rule_opt[k]->content);
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_same_source_ip)==0)
                    {
                        config_ruleinfo->context_opts|= SAME_SRCIP;
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_notsame_source_ip)==0)
                    {
                        config_ruleinfo->context_opts&= NOT_SAME_SRCIP;
                    }
                    else if(strcmp(rule_opt[k]->element, xml_same_id) == 0)
                    {
                        config_ruleinfo->context_opts|= SAME_ID;
                    }
                    else if(strcmp(rule_opt[k]->element,xml_different_url)== 0)
                    {
                        config_ruleinfo->context_opts|= DIFFERENT_URL;
                    }
                    else if(strcmp(rule_opt[k]->element, xml_notsame_id) == 0)
                    {
                        config_ruleinfo->context_opts&= NOT_SAME_ID;
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_fts) == 0)
                    {
                        config_ruleinfo->alert_opts |= DO_FTS;
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_same_user)==0)
                    {
                        config_ruleinfo->context_opts|= SAME_USER;
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_notsame_user)==0)
                    {
                        config_ruleinfo->context_opts&= NOT_SAME_USER;
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_same_agent)==0)
                    {
                        config_ruleinfo->context_opts|= SAME_AGENT;
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_notsame_agent)==0)
                    {
                        config_ruleinfo->context_opts&= NOT_SAME_AGENT;
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_options) == 0)
                    {
                        if(OS_Regex("alert_by_email", rule_opt[k]->content))
                        {
                            if(!(config_ruleinfo->alert_opts & DO_MAILALERT))
                            {
                                config_ruleinfo->alert_opts|= DO_MAILALERT;
                            }
                        }
                        else if(OS_Regex("no_email_alert",rule_opt[k]->content))
                        {
                            if(config_ruleinfo->alert_opts & DO_MAILALERT)
                            {
                              config_ruleinfo->alert_opts&=0xfff-DO_MAILALERT;
                            }
                        }
                        if(OS_Regex("log_alert", rule_opt[k]->content))
                        {
                            if(!(config_ruleinfo->alert_opts & DO_LOGALERT))
                            {
                                config_ruleinfo->alert_opts|= DO_LOGALERT;
                            }
                        }
                        else if(OS_Regex("no_log", rule_opt[k]->content))
                        {
                            if(config_ruleinfo->alert_opts & DO_LOGALERT)
                            {
                              config_ruleinfo->alert_opts &=0xfff-DO_LOGALERT;
                            }
                        }
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_ignore) == 0)
                    {
                        if(strstr(rule_opt[k]->content, "user") != NULL)
                        {
                            config_ruleinfo->ignore|=FTS_USER;
                        }
                        if(strstr(rule_opt[k]->content, "srcip") != NULL)
                        {
                            config_ruleinfo->ignore|=FTS_SRCIP;
                        }
                        if(strstr(rule_opt[k]->content, "dstip") != NULL)
                        {
                            config_ruleinfo->ignore|=FTS_DSTIP;
                        }
                        if(strstr(rule_opt[k]->content, "id") != NULL)
                        {
                            config_ruleinfo->ignore|=FTS_ID;
                        }
                        if(strstr(rule_opt[k]->content,"location")!= NULL)
                        {
                            config_ruleinfo->ignore|=FTS_LOCATION;
                        }
                        if(strstr(rule_opt[k]->content,"data")!= NULL)
                        {
                            config_ruleinfo->ignore|=FTS_DATA;
                        }
                        if(strstr(rule_opt[k]->content, "name") != NULL)
                        {
                            config_ruleinfo->ignore|=FTS_NAME;

                        }
                        if(!config_ruleinfo->ignore)
                        {
                            merror("%s: Wrong ignore option: '%s'", 
                                                    ARGV0,
                                                    rule_opt[k]->content);
                            return(-1);
                        }
                    }
                    else if(strcasecmp(rule_opt[k]->element,
                                xml_check_if_ignored) == 0)
                    {
                        if(strstr(rule_opt[k]->content, "user") != NULL)
                        {
                            config_ruleinfo->ckignore|=FTS_USER;
                        }
                        if(strstr(rule_opt[k]->content, "srcip") != NULL)
                        {
                            config_ruleinfo->ckignore|=FTS_SRCIP;
                        }
                        if(strstr(rule_opt[k]->content, "dstip") != NULL)
                        {
                            config_ruleinfo->ckignore|=FTS_DSTIP;
                        }
                        if(strstr(rule_opt[k]->content, "id") != NULL)
                        {
                            config_ruleinfo->ckignore|=FTS_ID;
                        }
                        if(strstr(rule_opt[k]->content,"location")!= NULL)
                        {
                            config_ruleinfo->ckignore|=FTS_LOCATION;
                        }
                        if(strstr(rule_opt[k]->content,"data")!= NULL)
                        {
                            config_ruleinfo->ignore|=FTS_DATA;
                        }
                        if(strstr(rule_opt[k]->content, "name") != NULL)
                        {
                            config_ruleinfo->ckignore|=FTS_NAME;

                        }
                        if(!config_ruleinfo->ckignore)
                        {
                            merror("%s: Wrong check_if_ignored option: '%s'", 
                                                    ARGV0,
                                                    rule_opt[k]->content);
                            return(-1);
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

                /* If if_matched_group we must have a if_sid or if_group */
                if(if_matched_group)
                {
                    if(!config_ruleinfo->if_sid && !config_ruleinfo->if_group)
                    {
                        os_strdup(if_matched_group, 
                                  config_ruleinfo->if_group);        
                    }
                }
                
                /* Checking the regexes */
                if(regex)
                {
                    os_calloc(1, sizeof(OSRegex), config_ruleinfo->regex);
                    if(!OSRegex_Compile(regex, config_ruleinfo->regex, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, regex, 
                                config_ruleinfo->regex->error);
                        return(-1);
                    }
                    free(regex);
                    regex = NULL;
                }
                
                /* Adding in match */
                if(match)
                {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->match);
                    if(!OSMatch_Compile(match, config_ruleinfo->match, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, match,
                                config_ruleinfo->match->error);
                        return(-1);
                    }
                    free(match);
                    match = NULL;
                }
                
                /* Adding in id */
                if(id)
                {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->id);
                    if(!OSMatch_Compile(id, config_ruleinfo->id, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, id, 
                                              config_ruleinfo->id->error);
                        return(-1);
                    }
                    free(id);
                    id = NULL;
                }

                /* Adding in status */
                if(status)
                {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->status);
                    if(!OSMatch_Compile(status, config_ruleinfo->status, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, status,
                                              config_ruleinfo->status->error);
                        return(-1);
                    }
                    free(status);
                    status = NULL;
                }

                /* Adding in hostname */
                if(hostname)
                {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->hostname);
                    if(!OSMatch_Compile(hostname, config_ruleinfo->hostname,0))
                    {
                        merror(REGEX_COMPILE, ARGV0, hostname,
                                config_ruleinfo->hostname->error);
                        return(-1);
                    }
                    free(hostname);
                    hostname = NULL;
                }

                /* Adding extra data */
                if(extra_data)
                {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->extra_data);
                    if(!OSMatch_Compile(extra_data, 
                                        config_ruleinfo->extra_data, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, extra_data,
                                config_ruleinfo->extra_data->error);
                        return(-1);
                    }
                    free(extra_data);
                    extra_data = NULL;
                }

                /* Adding in program name */
                if(program_name)
                {
                    os_calloc(1,sizeof(OSMatch),config_ruleinfo->program_name);
                    if(!OSMatch_Compile(program_name,
                                        config_ruleinfo->program_name,0))
                    {
                        merror(REGEX_COMPILE, ARGV0, program_name,
                                config_ruleinfo->program_name->error);
                        return(-1);
                    }
                    free(program_name);
                    program_name = NULL;
                }
                
                /* Adding in user */
                if(user)
                {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->user);
                    if(!OSMatch_Compile(user, config_ruleinfo->user, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, user,
                                              config_ruleinfo->user->error);
                        return(-1);
                    }
                    free(user);
                    user = NULL;
                }
                
                /* Adding in url */
                if(url)
                {
                    os_calloc(1, sizeof(OSMatch), config_ruleinfo->url);
                    if(!OSMatch_Compile(url, config_ruleinfo->url, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, url, 
                                config_ruleinfo->url->error);
                        return(-1);
                    }
                    free(url);
                    url = NULL;
                }
                
                /* Adding matched_group */
                if(if_matched_group)
                {
                    os_calloc(1, sizeof(OSMatch), 
                                 config_ruleinfo->if_matched_group);
                    
                    if(!OSMatch_Compile(if_matched_group, 
                                        config_ruleinfo->if_matched_group,
                                        0))
                    {
                        merror(REGEX_COMPILE, ARGV0, if_matched_group,
                                config_ruleinfo->if_matched_group->error);
                        return(-1);
                    }
                    free(if_matched_group);
                    if_matched_group = NULL;
                }
                
                /* Adding matched_regex */
                if(if_matched_regex)
                {
                    os_calloc(1, sizeof(OSRegex), 
                            config_ruleinfo->if_matched_regex);
                    if(!OSRegex_Compile(if_matched_regex, 
                                config_ruleinfo->if_matched_regex, 0))
                    {
                        merror(REGEX_COMPILE, ARGV0, if_matched_regex, 
                                config_ruleinfo->if_matched_regex->error);
                        return(-1);
                    }
                    free(if_matched_regex);
                    if_matched_regex = NULL;
                }
            } /* enf of elements block */


            /* Assigning an active response to the rule */
            Rule_AddAR(config_ruleinfo);

            j++; /* next rule */


            /* Creating the last_events if necessary */
            if(config_ruleinfo->context)
            {
                int ii = 0;
                os_calloc(MAX_LAST_EVENTS + 1, sizeof(char *), 
                          config_ruleinfo->last_events);
                
                /* Zeroing each entry */
                for(;ii<=MAX_LAST_EVENTS;ii++)
                {
                    config_ruleinfo->last_events[ii] = NULL;
                }
            }

            
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

            /* Cleaning what we do not need */
            if(config_ruleinfo->if_group)
            {
                free(config_ruleinfo->if_group);
                config_ruleinfo->if_group = NULL;
            }

        } /* while(rule[j]) */
        OS_ClearNode(rule);
        i++;
        
    } /* while (node[i]) */

    /* Cleaning global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);

    #ifdef DEBUG
    {
        RuleNode *dbg_node = OS_GetFirstRule();
        while(dbg_node)
        {
            if(dbg_node->child)
            {
                RuleNode *child_node = dbg_node->child;

                printf("** Child Node for %d **\n",dbg_node->ruleinfo->sigid);
                while(child_node)
                {
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
        if((strsize = strlen(str)) < OS_SIZE_1024)
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
        
        if((atsize > OS_SIZE_1024) || (strsize > OS_SIZE_1024))
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

    ruleinfo_pt->ar = NULL; 
    
    ruleinfo_pt->context = 0;
    
    ruleinfo_pt->sigid = id;
    ruleinfo_pt->firedtimes = 0;
    ruleinfo_pt->maxsize = maxsize;
    ruleinfo_pt->frequency = frequency;
    if(ruleinfo_pt->frequency > _max_freq)
    {
        _max_freq = ruleinfo_pt->frequency;
    }
    ruleinfo_pt->ignore_time = ignore_time;
    ruleinfo_pt->timeframe = timeframe;
    ruleinfo_pt->time_ignored = 0;
   
    ruleinfo_pt->context_opts = 0; 
    ruleinfo_pt->alert_opts = 0; 
    ruleinfo_pt->ignore = 0; 
    ruleinfo_pt->ckignore = 0; 

    if(noalert)
    {
        ruleinfo_pt->alert_opts |= NO_ALERT;
    }
    if(Config.mailbylevel <= level)
        ruleinfo_pt->alert_opts |= DO_MAILALERT;
    if(Config.logbylevel <= level)    
        ruleinfo_pt->alert_opts |= DO_LOGALERT;

    ruleinfo_pt->day_time = NULL;
    ruleinfo_pt->week_day = NULL;

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
    ruleinfo_pt->status = NULL;
    ruleinfo_pt->hostname = NULL;
    ruleinfo_pt->program_name = NULL;
    ruleinfo_pt->action = NULL;
    
    /* Zeroing last matched events */
    ruleinfo_pt->__frequency = 0;
    ruleinfo_pt->last_events = NULL;

    /* zeroing the list of previous matches */
    ruleinfo_pt->prev_matched = NULL;
    ruleinfo_pt->sid_search = NULL;

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
    if(rule_real_level == 0)
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
            if(rule_real_level >= my_ar->level)
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
                else if(isdigit((int)*str_pt))
                {
                    r_id = atoi(str_pt);
                    
                    /* mark to ar if id matches */
                    if(r_id == rule_config->sigid)
                    {
                        mark_to_ar = 1;
                    }
                    
                    str_pt = strchr(str_pt, ',');
                    if(str_pt)
                    {
                        str_pt++;
                    }
                    else
                    {
                        break;
                    }
                }

                /* Checking for duplicate commas */
                else if(*str_pt == ',')
                {
                    str_pt++;
                    continue;
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


/* print rule */
void printRuleinfo(RuleInfo *rule, int node)
{
    debug1("%d : rule:%d, level %d, timeout: %d", 
            node,
            rule->sigid, 
            rule->level,
            rule->ignore_time,
            rule->frequency);
}


/* _set levels */
int _setlevels(RuleNode *node, int nnode)
{
    int l_size = 0;
    while(node)
    {
        if(node->ruleinfo->level == 9900)
            node->ruleinfo->level = 0;

        if(node->ruleinfo->level > 100)
            node->ruleinfo->level/=100;

        l_size++;
        
        /* Rule information */
        printRuleinfo(node->ruleinfo, nnode);
        
        if(node->child)
        {
            int chl_size = 0;
            chl_size = _setlevels(node->child, nnode+1);

            l_size += chl_size;
        }

        node = node->next;
    }

    return(l_size);
}

/* EOF */
