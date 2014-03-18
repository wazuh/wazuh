/* @(#) $Id: ./src/config/csyslogd-config.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle the configuration files
 */


#include "csyslogd-config.h"
#include "config.h"


int Read_CSyslog(XML_NODE node, void *config, void *config2)
{
    int i = 0,s = 0;

    /* XML definitions */
    char *xml_syslog_server = "server";
    char *xml_syslog_port = "port";
    char *xml_syslog_format = "format";
    char *xml_syslog_level = "level";
    char *xml_syslog_id = "rule_id";
    char *xml_syslog_group = "group";
    char *xml_syslog_location = "event_location";


    GeneralConfig *gen_config = (GeneralConfig *)config;
    SyslogConfig **syslog_config = (SyslogConfig **)gen_config->data;


    /* Getting Granular mail_to size */
    if(syslog_config)
    {
        while(syslog_config[s])
            s++;
    }


    /* Allocating the memory for the config. */
    os_realloc(syslog_config, (s + 2) * sizeof(SyslogConfig *), syslog_config);
    os_calloc(1, sizeof(SyslogConfig), syslog_config[s]);
    syslog_config[s + 1] = NULL;


    /* Zeroing the elements. */
    syslog_config[s]->server = NULL;
    syslog_config[s]->rule_id = NULL;
    syslog_config[s]->group = NULL;
    syslog_config[s]->location = NULL;
    syslog_config[s]->level = 0;
    syslog_config[s]->port = "514";
    syslog_config[s]->format = DEFAULT_CSYSLOG;
    /* local 0 facility (16) + severity 4 - warning. --default */
    syslog_config[s]->priority = (16 * 8) + 4;

    while(node[i])
    {
        if(!node[i]->element)
        {
            merror(XML_ELEMNULL, ARGV0);
            return(OS_INVALID);
        }
        else if(!node[i]->content)
        {
            merror(XML_VALUENULL, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        else if(strcmp(node[i]->element, xml_syslog_level) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }

            syslog_config[s]->level = atoi(node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_syslog_port) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            os_strdup(node[i]->content, syslog_config[s]->port);
        }
        else if(strcmp(node[i]->element, xml_syslog_server) == 0)
        {
            os_strdup(node[i]->content, syslog_config[s]->server);
        }
        else if(strcmp(node[i]->element, xml_syslog_id) == 0)
        {
            int r_id = 0;
            char *str_pt = node[i]->content;

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
                    int id_i = 0;

                    r_id = atoi(str_pt);
                    debug1("%s: DEBUG: Adding '%d' to syslog alerting",
                           ARGV0, r_id);

                    if(syslog_config[s]->rule_id)
                    {
                        while(syslog_config[s]->rule_id[id_i])
                            id_i++;
                    }

                    os_realloc(syslog_config[s]->rule_id,
                               (id_i +2) * sizeof(int),
                               syslog_config[s]->rule_id);

                    syslog_config[s]->rule_id[id_i + i] = 0;
                    syslog_config[s]->rule_id[id_i] = r_id;

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

        }
        else if(strcmp(node[i]->element, xml_syslog_format) == 0)
        {
            if(strcmp(node[i]->content, "default") == 0)
            {
                /* Default is full format */
            }
            else if (strcmp(node[i]->content, "cef") == 0)
            {
                /* Enable the CEF format */
                syslog_config[s]->format = CEF_CSYSLOG;
            }
            else if (strcmp(node[i]->content, "json") == 0)
            {
                /* Enable the JSON format */
                syslog_config[s]->format = JSON_CSYSLOG;
            }
            else if (strcmp(node[i]->content, "splunk") == 0)
            {
                /* Enable the Splunk Key/Value format */
                syslog_config[s]->format = SPLUNK_CSYSLOG;
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_syslog_location) == 0)
        {
            os_calloc(1, sizeof(OSMatch),syslog_config[s]->location);
            if(!OSMatch_Compile(node[i]->content,
                                syslog_config[s]->location, 0))
            {
                merror(REGEX_COMPILE, ARGV0, node[i]->content,
                       syslog_config[s]->location->error);
                return(-1);
            }
        }
        else if(strcmp(node[i]->element, xml_syslog_group) == 0)
        {
            os_calloc(1, sizeof(OSMatch),syslog_config[s]->group);
            if(!OSMatch_Compile(node[i]->content,
                                syslog_config[s]->group, 0))
            {
                merror(REGEX_COMPILE, ARGV0, node[i]->content,
                       syslog_config[s]->group->error);
                return(-1);
            }
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    }


    /* We must have at least one entry set */
    if(!syslog_config[s]->server)
    {
        merror(XML_INV_CSYSLOG, ARGV0);
        return(OS_INVALID);
    }


    gen_config->data = syslog_config;
    return(0);
}


/* EOF */
