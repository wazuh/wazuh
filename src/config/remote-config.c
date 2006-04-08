/*   $OSSEC, remote-config.c, v0.3, 2005/11/09, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "remote-config.h"


/* Read_Remote: Reads remote config
 */
int Read_Remote(XML_NODE node, void *d1, void *d2)
{
    int i = 0;
    int pl = 0;

    int allow_size = 1;
    int deny_size = 1;
    remoted *logr;

    /*** XML Definitions ***/

    /* Allowed and denied IPS */
    char *xml_allowips = "allowed-ips";
    char *xml_denyips = "denied-ips";

    /* Remote options */	
    char *xml_remote_port = "port";
    char *xml_remote_connection = "connection";

    logr = (remoted *)d1;


    /* Cleaning */
    while(logr->conn[pl] != NULL)
        pl++;


    logr->port[pl] = 0;
    logr->conn[pl] = 0;

    
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

        else if(strcasecmp(node[i]->element,xml_remote_connection) == 0)
        {
            if(strcmp(node[i]->content, "syslog") == 0)
            {
                logr->conn[pl] = SYSLOG_CONN;
            }
            else if(strcmp(node[i]->content, "secure") == 0)
            {
                logr->conn[pl] = SECURE_CONN;
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcasecmp(node[i]->element,xml_remote_port) == 0)
        {
            logr->port[pl] = atoi(node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_allowips) == 0)
        {
            allow_size++;
            logr->allowips = realloc(logr->allowips,sizeof(char *)*allow_size);
            if(!logr->allowips)
            {
                merror(MEM_ERROR, ARGV0);
                return(OS_INVALID);
            }

            os_strdup(node[i]->content, logr->allowips[allow_size -2]);
            logr->allowips[allow_size -1] = NULL;
            if(!OS_IsValidIP(logr->allowips[allow_size -2]))
            {
                merror(INVALID_IP, ARGV0, logr->allowips[allow_size -2]);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_denyips) == 0)
        {
            deny_size++;
            logr->denyips = realloc(logr->denyips,sizeof(char *)*deny_size);
            if(!logr->denyips)             
            {
                merror(MEM_ERROR, ARGV0);
                return(OS_INVALID);
            }

            os_strdup(node[i]->content, logr->denyips[deny_size -2]);
            logr->denyips[deny_size -1] = NULL;
            if(!OS_IsValidIP(logr->denyips[deny_size -2]))
            {
                merror(INVALID_IP, ARGV0, logr->denyips[deny_size -2]);
                return(OS_INVALID);
            }
        }
        else
        {
            merror(XML_INVELEM, ARGV0, node[i]->element);
            return(OS_INVALID);
        }
        i++;
    }

    /* conn must be set */
    if(logr->conn[pl] == 0)
    {
    }
    
    /* Set port in here */
    if(logr->port[pl] == 0)
    {
    }

    
    return(0);
}


/* EOF */
