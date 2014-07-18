/* @(#) $Id: ./src/shared/rules_op.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */



#include "rules_op.h"

/* Chaging path for test rule. */
#ifdef TESTRULE
  #undef RULEPATH
  #define RULEPATH "rules/"
#endif


/** Prototypes **/
static int _OS_GetRulesAttributes(char **attributes,
                           char **values,
                           RuleInfo *ruleinfo_pt) __attribute__((nonnull));
static RuleInfo *_OS_AllocateRule(void);




/* Rules_OP_ReadRules, v0.3, 2005/03/21
 * Read the log rules.
 * v0.3: Fixed many memory problems.
 */
int OS_ReadXMLRules(const char *rulefile,
                    void *(*ruleact_function)(RuleInfo *rule_1, void *data_1),
                    void *data)
{
    OS_XML xml;
    XML_NODE node = NULL;


    /** XML variables **/
    /* These are the available options for the rule configuration */

    const char *xml_group = "group";
    const char *xml_rule = "rule";

    const char *xml_regex = "regex";
    const char *xml_match = "match";
    const char *xml_decoded = "decoded_as";
    const char *xml_category = "category";
    const char *xml_cve = "cve";
    const char *xml_info = "info";
    const char *xml_day_time = "time";
    const char *xml_week_day = "weekday";
    const char *xml_comment = "description";
    const char *xml_ignore = "ignore";
    const char *xml_check_if_ignored = "check_if_ignored";

    const char *xml_srcip = "srcip";
    const char *xml_srcport = "srcport";
    const char *xml_dstip = "dstip";
    const char *xml_dstport = "dstport";
    const char *xml_user = "user";
    const char *xml_url = "url";
    const char *xml_id = "id";
    const char *xml_data = "extra_data";
    const char *xml_hostname = "hostname";
    const char *xml_program_name = "program_name";
    const char *xml_status = "status";
    const char *xml_action = "action";
    const char *xml_compiled = "compiled_rule";

    const char *xml_if_sid = "if_sid";
    const char *xml_if_group = "if_group";
    const char *xml_if_level = "if_level";
    const char *xml_fts = "if_fts";

    const char *xml_if_matched_regex = "if_matched_regex";
    const char *xml_if_matched_group = "if_matched_group";
    const char *xml_if_matched_sid = "if_matched_sid";

    const char *xml_same_source_ip = "same_source_ip";
    const char *xml_same_src_port = "same_src_port";
    const char *xml_same_dst_port = "same_dst_port";
    const char *xml_same_user = "same_user";
    const char *xml_same_location = "same_location";
    const char *xml_same_id = "same_id";
    const char *xml_dodiff = "check_diff";

    const char *xml_different_url = "different_url";

    const char *xml_notsame_source_ip = "not_same_source_ip";
    const char *xml_notsame_user = "not_same_user";
    const char *xml_notsame_agent = "not_same_agent";
    const char *xml_notsame_id = "not_same_id";

    const char *xml_options = "options";

    char *rulepath;

    size_t i;


    /* If no directory in the rulefile add the default */
    if((strchr(rulefile, '/')) == NULL)
    {
        /* Building the rule file name + path */
        i = strlen(RULEPATH) + strlen(rulefile) + 2;
        rulepath = (char *)calloc(i,sizeof(char));
        if(!rulepath)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }
        snprintf(rulepath,i,"%s/%s",RULEPATH,rulefile);
    }
    else
    {
        os_strdup(rulefile, rulepath);
        debug1("%s is the rulefile", rulefile);
        debug1("Not modifing the rule path");
    }


    /* Reading the XML */
    if(OS_ReadXML(rulepath,&xml) < 0)
    {
        merror(XML_ERROR, __local_name, rulepath, xml.err, xml.err_line);
        free(rulepath);
        return(-1);
    }


    /* Debug wrapper */
    debug1("%s: DEBUG: read xml for rule '%s'.", __local_name, rulepath);


    /* Applying any variable found */
    if(OS_ApplyVariables(&xml) != 0)
    {
        merror(XML_ERROR_VAR, __local_name, rulepath, xml.err);
        return(-1);
    }


    /* Debug wrapper */
    debug1("%s: DEBUG: XML Variables applied.", __local_name);


    /* Getting the root elements */
    node = OS_GetElementsbyNode(&xml, NULL);
    if(!node)
    {
        merror(CONFIG_ERROR, __local_name, rulepath);
        OS_ClearXML(&xml);
        return(-1);
    }


    /* Zeroing the rule memory -- not used anymore */
    free(rulepath);


    /* Checking if there is any invalid global option */
    i = 0;
    while(node[i])
    {
        if(node[i]->element)
        {
            /* Verifying group */
            if(strcasecmp(node[i]->element,xml_group) != 0)
            {
                merror(RL_INV_ROOT, __local_name, node[i]->element);
                OS_ClearXML(&xml);
                return(-1);
            }
            /* Checking group attribute -- only name is allowed */
            if((!node[i]->attributes) || (!node[i]->values)||
               (!node[i]->values[0]) || (!node[i]->attributes[0]) ||
               (strcasecmp(node[i]->attributes[0],"name") != 0) ||
               (node[i]->attributes[1]))
            {
                merror(RL_INV_ROOT, __local_name, node[i]->element);
                OS_ClearXML(&xml);
                return(-1);
            }
        }
        else
        {
            merror(XML_READ_ERROR, __local_name);
            OS_ClearXML(&xml);
            return(-1);
        }
        i++;
    }


    /* Getting the rules now */
    i = 0;
    while(node[i])
    {
        int j = 0;
        XML_NODE rule = NULL;


        /* Getting all rules for a global group */
        rule = OS_GetElementsbyNode(&xml,node[i]);
        if(rule == NULL)
        {
            i++;
            continue;
        }

        /* Looping on the rules node */
        while(rule[j])
        {
            /* Rules options */
            int k = 0;
            char *regex = NULL, *match = NULL, *url = NULL,
                 *if_matched_regex = NULL, *if_matched_group = NULL,
                 *user = NULL, *id = NULL, *srcport = NULL,
                 *dstport = NULL, *status = NULL, *hostname = NULL,
                 *extra_data = NULL, *program_name = NULL;

            RuleInfo *config_ruleinfo = NULL;
            XML_NODE rule_opt = NULL;


            /* Checking if the rule element is correct */
            if((!rule[j]->element)||
               (strcasecmp(rule[j]->element,xml_rule) != 0))
            {
                merror(RL_INV_RULE, __local_name, node[i]->element);
                OS_ClearXML(&xml);
                return(-1);
            }


            /* Checking for the attributes of the rule */
            if((!rule[j]->attributes) || (!rule[j]->values))
            {
                merror(RL_INV_RULE, __local_name, rulefile);
                OS_ClearXML(&xml);
                return(-1);
            }


            /* Attribute block */
            config_ruleinfo = _OS_AllocateRule();

            if(_OS_GetRulesAttributes(rule[j]->attributes, rule[j]->values,
                                      config_ruleinfo) < 0)
            {
                merror(RL_INV_ATTR, __local_name, rulefile);
                OS_ClearXML(&xml);
                return(-1);
            }

            /* We must have an id or level */
            if((config_ruleinfo->sigid == -1)||(config_ruleinfo->level == -1))
            {
                merror(RL_INV_ATTR, __local_name, rulefile);
                OS_ClearXML(&xml);
                return(-1);
            }


            /* Here we can assign the group name to the rule.
             * The level is correct so the rule is probably going to
             * be fine
             */
            os_strdup(node[i]->values[0], config_ruleinfo->group);


            /* Getting rules options */
            rule_opt =  OS_GetElementsbyNode(&xml, rule[j]);
            if(rule_opt == NULL)
            {
                merror(RL_NO_OPT, __local_name, config_ruleinfo->sigid);
                OS_ClearXML(&xml);
                return(-1);
            }


            /* Reading the whole rule block */
            while(rule_opt[k])
            {
                if((!rule_opt[k]->element)||(!rule_opt[k]->content))
                {
                    break;
                }
                else if(strcasecmp(rule_opt[k]->element,xml_regex)==0)
                {
                    regex =
                        os_LoadString(regex,
                                rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,xml_match)==0)
                {
                    match =
                        os_LoadString(match,
                                rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element, xml_decoded) == 0)
                {
                }
                else if(strcasecmp(rule_opt[k]->element,xml_info) == 0)
                {
                    config_ruleinfo->info=
                        os_LoadString(config_ruleinfo->info,
                                      rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,xml_day_time) == 0)
                {
                    config_ruleinfo->day_time =
                                     OS_IsValidTime(rule_opt[k]->content);
                    if(!config_ruleinfo->day_time)
                    {
                        merror(INVALID_CONFIG, __local_name,
                                rule_opt[k]->element,
                                rule_opt[k]->content);
                        return(-1);
                    }

                    if(!(config_ruleinfo->alert_opts & DO_EXTRAINFO))
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,xml_week_day) == 0)
                {
                    config_ruleinfo->week_day =
                        OS_IsValidDay(rule_opt[k]->content);

                    if(!config_ruleinfo->week_day)
                    {
                        merror(INVALID_CONFIG, __local_name,
                                rule_opt[k]->element,
                                rule_opt[k]->content);
                        return(-1);
                    }
                    if(!(config_ruleinfo->alert_opts & DO_EXTRAINFO))
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,xml_group) == 0)
                {
                    config_ruleinfo->group =
                        os_LoadString(config_ruleinfo->group,
                                      rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,xml_cve) == 0)
                {
                    config_ruleinfo->cve=
                        os_LoadString(config_ruleinfo->cve,
                                      rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,xml_comment) == 0)
                {
                    char *newline;

                    newline = strchr(rule_opt[k]->content, '\n');
                    if(newline)
                    {
                        *newline = ' ';
                    }
                    config_ruleinfo->comment=
                        os_LoadString(config_ruleinfo->comment,
                                      rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,xml_srcip)==0)
                {
                    size_t ip_s = 0;

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
                        merror(INVALID_IP, __local_name, rule_opt[k]->content);
                        return(-1);
                    }

                    if(!(config_ruleinfo->alert_opts & DO_PACKETINFO))
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,xml_dstip)==0)
                {
                    size_t ip_s = 0;

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
                        merror(INVALID_IP, __local_name, rule_opt[k]->content);
                        return(-1);
                    }

                    if(!(config_ruleinfo->alert_opts & DO_PACKETINFO))
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,xml_user) == 0)
                {
                    user = os_LoadString(user, rule_opt[k]->content);

                    if(!(config_ruleinfo->alert_opts & DO_EXTRAINFO))
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,xml_id) == 0)
                {
                    id = os_LoadString(id, rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,xml_srcport) == 0)
                {
                    srcport = os_LoadString(srcport, rule_opt[k]->content);

                    if(!(config_ruleinfo->alert_opts & DO_PACKETINFO))
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,xml_dstport) == 0)
                {
                    dstport = os_LoadString(dstport, rule_opt[k]->content);

                    if(!(config_ruleinfo->alert_opts & DO_PACKETINFO))
                        config_ruleinfo->alert_opts |= DO_PACKETINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,xml_status)==0)
                {
                    status = os_LoadString(status, rule_opt[k]->content);

                    if(!(config_ruleinfo->alert_opts & DO_EXTRAINFO))
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,xml_hostname) == 0)
                {
                    hostname = os_LoadString(hostname, rule_opt[k]->content);

                    if(!(config_ruleinfo->alert_opts & DO_EXTRAINFO))
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,xml_data)==0)
                {
                    extra_data = os_LoadString(extra_data, rule_opt[k]->content);

                    if(!(config_ruleinfo->alert_opts & DO_EXTRAINFO))
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_program_name)==0)
                {
                    program_name = os_LoadString(program_name,
                                              rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,xml_action) == 0)
                {
                    config_ruleinfo->action =
                                os_LoadString(config_ruleinfo->action,
                                rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,xml_url) == 0)
                {
                    url= os_LoadString(url, rule_opt[k]->content);
                }

                else if(strcasecmp(rule_opt[k]->element, xml_compiled)==0)
                {
                    /* Not using this in here. */
                }

                /* We allow these categories so far */
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
                        config_ruleinfo->category = DECODER_WINDOWS;
                    }
                    else if(strcmp(rule_opt[k]->content,"ossec") == 0)
                    {
                        config_ruleinfo->category = OSSEC_RL;
                    }
                    else
                    {
                        merror(INVALID_CAT, __local_name, rule_opt[k]->content);
                        return(-1);
                    }
                }
                else if(strcasecmp(rule_opt[k]->element,xml_if_sid)==0)
                {
                    config_ruleinfo->if_sid=
                                os_LoadString(config_ruleinfo->if_sid,
                                rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,xml_if_level)==0)
                {
                    if(!OS_StrIsNum(rule_opt[k]->content))
                    {
                        merror(INVALID_CONFIG, __local_name,
                                xml_if_level,
                                rule_opt[k]->content);
                        return(-1);
                    }

                    config_ruleinfo->if_level=
                                os_LoadString(config_ruleinfo->if_level,
                                rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,xml_if_group)==0)
                {
                    config_ruleinfo->if_group=
                                os_LoadString(config_ruleinfo->if_group,
                                rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_if_matched_regex) == 0)
                {
                    config_ruleinfo->context = 1;
                    if_matched_regex=
                                os_LoadString(if_matched_regex,
                                rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_if_matched_group) == 0)
                {
                    config_ruleinfo->context = 1;
                    if_matched_group=
                                os_LoadString(if_matched_group,
                                rule_opt[k]->content);
                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_if_matched_sid) == 0)
                {
                    config_ruleinfo->context = 1;
                    if(!OS_StrIsNum(rule_opt[k]->content))
                    {
                        merror(INVALID_CONFIG, __local_name,
                                rule_opt[k]->element,
                                rule_opt[k]->content);
                        return(-1);
                    }
                    config_ruleinfo->if_matched_sid =
                        atoi(rule_opt[k]->content);

                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_same_source_ip)==0)
                {
                    config_ruleinfo->context_opts|= SAME_SRCIP;
                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_same_src_port)==0)
                {
                    config_ruleinfo->context_opts|= SAME_SRCPORT;

                    if(!(config_ruleinfo->alert_opts & SAME_EXTRAINFO))
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,
                                   xml_dodiff)==0)
                {
                    config_ruleinfo->context++;
                    config_ruleinfo->context_opts|= SAME_DODIFF;
                    if(!(config_ruleinfo->alert_opts & DO_EXTRAINFO))
                    {
                        config_ruleinfo->alert_opts |= DO_EXTRAINFO;
                    }
                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_same_dst_port) == 0)
                {
                    config_ruleinfo->context_opts|= SAME_DSTPORT;

                    if(!(config_ruleinfo->alert_opts & SAME_EXTRAINFO))
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
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
                else if(strcmp(rule_opt[k]->element,
                            xml_different_url) == 0)
                {
                    config_ruleinfo->context_opts|= DIFFERENT_URL;

                    if(!(config_ruleinfo->alert_opts & SAME_EXTRAINFO))
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                }
                else if(strcmp(rule_opt[k]->element,xml_notsame_id) == 0)
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

                    if(!(config_ruleinfo->alert_opts & SAME_EXTRAINFO))
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_notsame_user)==0)
                {
                    config_ruleinfo->context_opts&= NOT_SAME_USER;
                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_same_location)==0)
                {
                    config_ruleinfo->context_opts|= SAME_LOCATION;
                    if(!(config_ruleinfo->alert_opts & SAME_EXTRAINFO))
                        config_ruleinfo->alert_opts |= SAME_EXTRAINFO;
                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_notsame_agent)==0)
                {
                    config_ruleinfo->context_opts&= NOT_SAME_AGENT;
                }
                else if(strcasecmp(rule_opt[k]->element,
                            xml_options) == 0)
                {
                    if(strcmp("alert_by_email",
                                rule_opt[k]->content) == 0)
                    {
                        if(!(config_ruleinfo->alert_opts & DO_MAILALERT))
                        {
                            config_ruleinfo->alert_opts|= DO_MAILALERT;
                        }
                    }
                    else if(strcmp("no_email_alert",
                                rule_opt[k]->content) == 0)
                    {
                        if(config_ruleinfo->alert_opts & DO_MAILALERT)
                        {
                            config_ruleinfo->alert_opts&=0xfff-DO_MAILALERT;
                        }
                    }
                    else if(strcmp("log_alert",
                                rule_opt[k]->content) == 0)
                    {
                        if(!(config_ruleinfo->alert_opts & DO_LOGALERT))
                        {
                            config_ruleinfo->alert_opts|= DO_LOGALERT;
                        }
                    }
                    else if(strcmp("no_log", rule_opt[k]->content) == 0)
                    {
                        if(config_ruleinfo->alert_opts & DO_LOGALERT)
                        {
                            config_ruleinfo->alert_opts &=0xfff-DO_LOGALERT;
                        }
                    }
                    else if(strcmp("no_ar", rule_opt[k]->content) == 0)
                    {
                        if(!(config_ruleinfo->alert_opts & NO_AR))
                        {
                            config_ruleinfo->alert_opts|= NO_AR;
                        }
                    }
                    else
                    {
                        merror(XML_VALUEERR, __local_name, xml_options,
                                rule_opt[k]->content);

                        merror(INVALID_ELEMENT, __local_name,
                                                rule_opt[k]->element,
                                                rule_opt[k]->content);
                        OS_ClearXML(&xml);
                        return(-1);
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
                        merror(INVALID_ELEMENT, __local_name,
                                rule_opt[k]->element,
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
                        merror(INVALID_ELEMENT, __local_name,
                                rule_opt[k]->element,
                                rule_opt[k]->content);

                        return(-1);
                    }
                }
                /* XXX As new features are added into ../analysisd/rules.c
                 * This code needs to be updated to match, but is out of date
                 * it's become a nightmare to correct with out just make the
                 * problem for someone later.
                 *
                 * This hack will allow any crap xml to pass without an
                 * error.  The correct fix is to refactor the code so that
                 * ../analysisd/rules* and this code are not duplicates
                 *
                else
                {
                    merror(XML_INVELEM, __local_name, rule_opt[k]->element);
                    OS_ClearXML(&xml);
                    return(-1);
                }
                */

                k++;
            }


            /* Checking for a valid use of frequency */
            if((config_ruleinfo->context_opts ||
                config_ruleinfo->frequency) &&
               !config_ruleinfo->context)
            {
                merror("%s: Invalid use of frequency/context options. "
                        "Missing if_matched on rule '%d'.",
                        __local_name, config_ruleinfo->sigid);
                OS_ClearXML(&xml);
                return(-1);
            }


            /* If if_matched_group we must have a if_sid or if_group */
            if(if_matched_group)
            {
                if(!config_ruleinfo->if_sid && !config_ruleinfo->if_group)
                {
                    os_strdup(if_matched_group, config_ruleinfo->if_group);
                }
            }


            /* If_matched_sid, we need to get the if_sid */
            if(config_ruleinfo->if_matched_sid &&
               !config_ruleinfo->if_sid &&
               !config_ruleinfo->if_group)
            {
                os_calloc(16, sizeof(char), config_ruleinfo->if_sid);
                snprintf(config_ruleinfo->if_sid, 15, "%d",
                        config_ruleinfo->if_matched_sid);
            }


            /* Checking the regexes */
            if(regex)
            {
                os_calloc(1, sizeof(OSRegex), config_ruleinfo->regex);
                if(!OSRegex_Compile(regex, config_ruleinfo->regex, 0))
                {
                    merror(REGEX_COMPILE, __local_name, regex,
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
                    merror(REGEX_COMPILE, __local_name, match,
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
                    merror(REGEX_COMPILE, __local_name, id,
                            config_ruleinfo->id->error);
                    return(-1);
                }
                free(id);
                id = NULL;
            }


            /* Adding srcport */
            if(srcport)
            {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->srcport);
                if(!OSMatch_Compile(srcport, config_ruleinfo->srcport, 0))
                {
                    merror(REGEX_COMPILE, __local_name, srcport,
                            config_ruleinfo->id->error);
                    return(-1);
                }
                free(srcport);
                srcport = NULL;
            }


            /* Adding dstport */
            if(dstport)
            {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->dstport);
                if(!OSMatch_Compile(dstport, config_ruleinfo->dstport, 0))
                {
                    merror(REGEX_COMPILE, __local_name, dstport,
                            config_ruleinfo->id->error);
                    return(-1);
                }
                free(dstport);
                dstport = NULL;
            }


            /* Adding in status */
            if(status)
            {
                os_calloc(1, sizeof(OSMatch), config_ruleinfo->status);
                if(!OSMatch_Compile(status, config_ruleinfo->status, 0))
                {
                    merror(REGEX_COMPILE, __local_name, status,
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
                    merror(REGEX_COMPILE, __local_name, hostname,
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
                    merror(REGEX_COMPILE, __local_name, extra_data,
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
                    merror(REGEX_COMPILE, __local_name, program_name,
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
                    merror(REGEX_COMPILE, __local_name, user,
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
                    merror(REGEX_COMPILE, __local_name, url,
                            config_ruleinfo->url->error);
                    return(-1);
                }
                free(url);
                url = NULL;
            }


            /* Adding matched_group */
            if(if_matched_group)
            {
                os_calloc(1,sizeof(OSMatch),config_ruleinfo->if_matched_group);

                if(!OSMatch_Compile(if_matched_group,
                            config_ruleinfo->if_matched_group,0))
                {
                    merror(REGEX_COMPILE, __local_name, if_matched_group,
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
                    merror(REGEX_COMPILE, __local_name, if_matched_regex,
                            config_ruleinfo->if_matched_regex->error);
                    return(-1);
                }
                free(if_matched_regex);
                if_matched_regex = NULL;
            }


            /* Calling the function provided. */
            ruleact_function(config_ruleinfo, data);


            j++; /* next rule */


        } /* while(rule[j]) */
        OS_ClearNode(rule);
        i++;

    } /* while (node[i]) */

    /* Cleaning global node */
    OS_ClearNode(node);
    OS_ClearXML(&xml);


    /* Done over here */
    return(0);
}



/** RuleInfo *_OS_AllocateRule()
 * Allocates the memory for the rule.
 */
static RuleInfo *_OS_AllocateRule()
{
    RuleInfo *ruleinfo_pt = NULL;


    /* Allocation memory for structure */
    ruleinfo_pt = (RuleInfo *)calloc(1,sizeof(RuleInfo));
    if(ruleinfo_pt == NULL)
    {
        ErrorExit(MEM_ERROR,__local_name);
    }


    /* Default values */
    ruleinfo_pt->level = -1;

    /* Default category is syslog */
    ruleinfo_pt->category = SYSLOG;

    ruleinfo_pt->ar = NULL;

    ruleinfo_pt->context = 0;

    /* Default sigid of -1 */
    ruleinfo_pt->sigid = -1;
    ruleinfo_pt->firedtimes = 0;
    ruleinfo_pt->maxsize = 0;
    ruleinfo_pt->frequency = 0;
    ruleinfo_pt->ignore_time = 0;
    ruleinfo_pt->timeframe = 0;
    ruleinfo_pt->time_ignored = 0;

    ruleinfo_pt->context_opts = 0;
    ruleinfo_pt->alert_opts = 0;
    ruleinfo_pt->ignore = 0;
    ruleinfo_pt->ckignore = 0;

    ruleinfo_pt->day_time = NULL;
    ruleinfo_pt->week_day = NULL;

    ruleinfo_pt->group = NULL;
    ruleinfo_pt->regex = NULL;
    ruleinfo_pt->match = NULL;
    ruleinfo_pt->decoded_as = 0;

    ruleinfo_pt->comment = NULL;
    ruleinfo_pt->info = NULL;
    ruleinfo_pt->cve = NULL;

    ruleinfo_pt->if_sid = NULL;
    ruleinfo_pt->if_group = NULL;
    ruleinfo_pt->if_level = NULL;

    ruleinfo_pt->if_matched_regex = NULL;
    ruleinfo_pt->if_matched_group = NULL;
    ruleinfo_pt->if_matched_sid = 0;

    ruleinfo_pt->user = NULL;
    ruleinfo_pt->srcip = NULL;
    ruleinfo_pt->srcport = NULL;
    ruleinfo_pt->dstip = NULL;
    ruleinfo_pt->dstport = NULL;
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
    ruleinfo_pt->sid_prev_matched = NULL;
    ruleinfo_pt->group_prev_matched = NULL;

    ruleinfo_pt->sid_search = NULL;
    ruleinfo_pt->group_search = NULL;

    ruleinfo_pt->event_search = NULL;

    return(ruleinfo_pt);
}



/** int _OS_GetRulesAttributes
 * Reads the rules attributes and assign them.
 */
static int _OS_GetRulesAttributes(char **attributes, char **values,
                           RuleInfo *ruleinfo_pt)
{
    int k = 0;

    const char *xml_id = "id";
    const char *xml_level = "level";
    const char *xml_maxsize = "maxsize";
    const char *xml_timeframe = "timeframe";
    const char *xml_frequency = "frequency";
    const char *xml_accuracy = "accuracy";
    const char *xml_noalert = "noalert";
    const char *xml_ignore_time = "ignore";
    const char *xml_overwrite = "overwrite";


    /* Getting attributes */
    while(attributes[k])
    {
        if(!values[k])
        {
            merror(RL_EMPTY_ATTR, __local_name, attributes[k]);
            return(-1);
        }
        /* Getting rule Id */
        else if(strcasecmp(attributes[k], xml_id) == 0)
        {
            if(OS_StrIsNum(values[k]) && (strlen(values[k]) <= 6 ))
            {
                ruleinfo_pt->sigid = atoi(values[k]);
            }
            else
            {
                merror(XML_VALUEERR,__local_name, attributes[k], values[k]);
                return(-1);
            }
        }
        /* Getting level */
        else if(strcasecmp(attributes[k],xml_level) == 0)
        {
            if(OS_StrIsNum(values[k]) && (strlen(values[k]) <= 3))
            {
                ruleinfo_pt->level = atoi(values[k]);
            }
            else
            {
                merror(XML_VALUEERR,__local_name, attributes[k], values[k]);
                return(-1);
            }
        }
        /* Getting maxsize */
        else if(strcasecmp(attributes[k],xml_maxsize) == 0)
        {
            if(OS_StrIsNum(values[k]) && (strlen(values[k]) <= 4))
            {
                ruleinfo_pt->maxsize = atoi(values[k]);

                /* adding EXTRAINFO options */
                if(ruleinfo_pt->maxsize > 0 &&
                   !(ruleinfo_pt->alert_opts & DO_EXTRAINFO))
                {
                    ruleinfo_pt->alert_opts |= DO_EXTRAINFO;
                }
            }
            else
            {
                merror(XML_VALUEERR,__local_name, attributes[k], values[k]);
                return(-1);
            }
        }
        /* Getting timeframe */
        else if(strcasecmp(attributes[k],xml_timeframe) == 0)
        {
            if(OS_StrIsNum(values[k]) && (strlen(values[k]) <= 5))
            {
                ruleinfo_pt->timeframe = atoi(values[k]);
            }
            else
            {
                merror(XML_VALUEERR,__local_name, attributes[k], values[k]);
                return(-1);
            }
        }
        /* Getting frequency */
        else if(strcasecmp(attributes[k],xml_frequency) == 0)
        {
            if(OS_StrIsNum(values[k]) && (strlen(values[k]) <= 4))
            {
                ruleinfo_pt->frequency = atoi(values[k]);
            }
            else
            {
                merror(XML_VALUEERR,__local_name, attributes[k], values[k]);
                return(-1);
            }
        }
        /* Rule accuracy */
        else if(strcasecmp(attributes[k],xml_accuracy) == 0)
        {
            merror("%s: XXX: Use of 'accuracy' isn't supported. Ignoring.",
                   __local_name);
        }
         /* Rule ignore_time */
        else if(strcasecmp(attributes[k],xml_ignore_time) == 0)
        {
            if(OS_StrIsNum(values[k]) && (strlen(values[k]) <= 4))
            {
                ruleinfo_pt->ignore_time = atoi(values[k]);
            }
            else
            {
                merror(XML_VALUEERR,__local_name, attributes[k], values[k]);
                return(-1);
            }
        }
        /* Rule noalert */
        else if(strcasecmp(attributes[k],xml_noalert) == 0)
        {
            ruleinfo_pt->alert_opts |= NO_ALERT;
        }
        else if(strcasecmp(attributes[k], xml_overwrite) == 0)
        {
            if(strcmp(values[k], "yes") == 0)
            {
                ruleinfo_pt->alert_opts |= DO_OVERWRITE;
            }
            else if(strcmp(values[k], "no") == 0)
            {
            }
            else
            {
                merror(XML_VALUEERR,__local_name, attributes[k], values[k]);
                return(-1);
            }
        }
        else
        {
            merror(XML_INVELEM, __local_name, attributes[k]);
            return(-1);
        }
        k++;
    }
    return(0);
}



/* print rule */
/*void OS_PrintRuleinfo(RuleInfo *rule)
{
    debug1("%s: __local_name: Print Rule:%d, level %d, ignore: %d, frequency:%d",
            __local_name,
            rule->sigid,
            rule->level,
            rule->ignore_time,
            rule->frequency);
}*/



/* EOF */
