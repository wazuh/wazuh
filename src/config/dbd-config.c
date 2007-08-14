/* @(#) $Id$ */

/* Copyright (C) 2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle the dbd configuration files
 */


#include "shared.h"
#include "dbd-config.h"


int Read_DB(XML_NODE node, void *config1, void *config2)
{
    int i = 0;
    DBConfig *db_config;


    /* XML definitions */
    char *xml_dbhost = "hostname";
    char *xml_dbuser = "username";
    char *xml_dbpass = "password";
    char *xml_dbdb = "database";
    char *xml_dbtype = "type";

    
    db_config = (DBConfig *)config2;
    if(!db_config)
    {
        return(0);
    }


    /* Reading the xml */ 
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
        /* Mail notification */
        else if(strcmp(node[i]->element, xml_dbhost) == 0)
        {
            os_strdup(node[i]->content, db_config->host);
        }
        else if(strcmp(node[i]->element, xml_dbuser) == 0)
        {
            os_strdup(node[i]->content, db_config->user);
        }
        else if(strcmp(node[i]->element, xml_dbpass) == 0)
        {
            os_strdup(node[i]->content, db_config->pass);
        }
        else if(strcmp(node[i]->element, xml_dbdb) == 0)
        {
            os_strdup(node[i]->content, db_config->db);
        }
        else if(strcmp(node[i]->element, xml_dbtype) == 0)
        {
            if(strcmp(node[i]->content, "mysql") == 0)
            {
            }
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
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


    return(0);
}


/* EOF */
