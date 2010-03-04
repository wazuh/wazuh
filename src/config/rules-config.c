/* @(#) $Id$ */

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


#include "shared.h"
#include "global-config.h"


int Read_Rules(XML_NODE node, void *configp, void *mailp)
{
    int i = 0;

    /* White list size */
    int rules_size = 1;


    /* XML definitions */
    char *xml_rules_include = "include";

    _Config *Config;
     
    Config = (_Config *)configp;
     
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
        else if(strcmp(node[i]->element, xml_rules_include) == 0)
        {
            rules_size++;
            Config->includes = realloc(Config->includes, 
                                       sizeof(char *)*rules_size);
            if(!Config->includes)
            {
                merror(MEM_ERROR, ARGV0);
                return(OS_INVALID);
            }

            os_strdup(node[i]->content,Config->includes[rules_size -2]);
            Config->includes[rules_size -1] = NULL;
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
