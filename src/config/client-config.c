/*   $OSSEC, client-config.c, v0.1, 2005/04/01, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include "shared.h"
#include "client-config.h"
#include "os_net/os_net.h"

#include "config.h"

int Read_Client(XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;

    /* XML definitions */
    const char *xml_client_ip = "server-ip";
    const char *xml_client_hostname = "server-hostname";
    const char *xml_local_ip = "local_ip";
    const char *xml_client_port = "port";
    const char *xml_ar_disabled = "disable-active-response";
    const char *xml_notify_time = "notify_time";
    const char *xml_max_time_reconnect_try = "time-reconnect";

    /* cmoraes */
    const char *xml_profile_name = "config-profile";

    agent *logr;

    logr = (agent *)d1;

    logr->notify_time = 0;
    logr->max_time_reconnect_try = 0;

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
        /* Getting local ip. */
        else if(strcmp(node[i]->element, xml_local_ip) == 0)
        {
            os_strdup(node[i]->content, logr->lip);
            if(OS_IsValidIP(logr->lip, NULL) != 1)
            {
                merror(INVALID_IP, ARGV0, logr->lip);
                return(OS_INVALID);
            }
        }
        /* Getting server ip */
        else if(strcmp(node[i]->element,xml_client_ip) == 0)
        {
            unsigned int ip_id = 0;

            /* Getting last ip */
            if(logr->rip)
            {
                while(logr->rip[ip_id])
                {
                    ip_id++;
                }
            }
            os_realloc(logr->rip, (ip_id + 2) * sizeof(char*), logr->rip);
            logr->rip[ip_id] = NULL;
            logr->rip[ip_id +1] = NULL;

            os_strdup(node[i]->content, logr->rip[ip_id]);
            if(OS_IsValidIP(logr->rip[ip_id], NULL) != 1)
            {
                merror(INVALID_IP, ARGV0, logr->rip[ip_id]);
                return(OS_INVALID);
            }
            logr->rip_id++;
        }
        else if(strcmp(node[i]->element,xml_client_hostname) == 0)
        {
            unsigned int ip_id = 0;
            char *s_ip;
            char f_ip[128];


            /* Getting last ip. */
            if(logr->rip)
            {
                while(logr->rip[ip_id])
                {
                    ip_id++;
                }
            }

            os_realloc(logr->rip, (ip_id + 2) * sizeof(char*),
                       logr->rip);


            s_ip = OS_GetHost(node[i]->content, 5);
            if(!s_ip)
            {
                merror("%s: WARN: Unable to get hostname for '%s'.",
                       ARGV0, node[i]->content);
                merror(AG_INV_HOST, ARGV0, node[i]->content);

                os_strdup("invalid_ip", s_ip);
            }


            f_ip[127] = '\0';
            snprintf(f_ip, 127, "%s/%s", node[i]->content, s_ip);

            os_strdup(f_ip, logr->rip[ip_id]);
            logr->rip[ip_id +1] = NULL;

            free(s_ip);

            logr->rip_id++;
        }
        else if(strcmp(node[i]->element,xml_client_port) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            logr->port = atoi(node[i]->content);

            if(logr->port <= 0 || logr->port > 65535)
            {
                merror(PORT_ERROR, ARGV0, logr->port);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element,xml_notify_time) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            logr->notify_time = atoi(node[i]->content);
        }
        else if(strcmp(node[i]->element,xml_max_time_reconnect_try) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            logr->max_time_reconnect_try = atoi(node[i]->content);
        }
        else if(strcmp(node[i]->element,xml_ar_disabled) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                logr->execdq = -1;
            else if(strcmp(node[i]->content, "no") == 0)
                logr->execdq = 0;
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        /* cmoraes */
        else if(strcmp(node[i]->element,xml_profile_name) == 0)
        {
            /* profile name can be anything hence no validation */
            os_strdup(node[i]->content, logr->profile);
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    }

    if(!logr->rip)
    {
        return(OS_INVALID);
    }

    return(0);
}


/* EOF */
