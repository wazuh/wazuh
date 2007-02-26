/*   $OSSEC, alerts-config.c, v0.1, 2005/04/02, Daniel B. Cid$   */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
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
#include "mail-config.h"


int Read_EmailAlerts(XML_NODE node, void *configp, void *mailp)
{
    int i = 0;
    int granto_size = 1;

    /* XML definitions */
    char *xml_email_to = "email_to";
    char *xml_email_level = "level";
    char *xml_email_location = "event_location";

    MailConfig *Mail;
     
    Mail = (MailConfig *)mailp;
    if(!Mail)
    {
        return(0);
    }


    /* Getting Granular mail_to size */
    if(Mail && Mail->gran_to)
    {
        char **ww;
        ww = Mail->gran_to;
        while(*ww != NULL)
        {
            ww++;
            granto_size++;
        }
    }


    if(Mail)
    {
        os_realloc(Mail->gran_to, 
                   sizeof(char *)*(granto_size +1), Mail->gran_to);
        os_realloc(Mail->gran_level, 
                   sizeof(int)*(granto_size +1), Mail->gran_level);
        os_realloc(Mail->gran_set, 
                   sizeof(int)*(granto_size +1), Mail->gran_set);
        os_realloc(Mail->gran_location, 
                   sizeof(OSMatch)*(granto_size +1), Mail->gran_location);
        
        Mail->gran_to[granto_size -1] = NULL;
        Mail->gran_to[granto_size] = NULL;
        Mail->gran_location[granto_size -1] = NULL;
        Mail->gran_location[granto_size] = NULL;
        Mail->gran_level[granto_size -1] = 0;
        Mail->gran_level[granto_size] = 0;
        Mail->gran_set[granto_size -1] = 0;
        Mail->gran_set[granto_size] = 0;
    }
    
    
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
        else if(strcmp(node[i]->element, xml_email_level) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }

            Mail->gran_level[granto_size -1] = atoi(node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_email_to) == 0)
        {
            os_strdup(node[i]->content, Mail->gran_to[granto_size -1]);
        }
        else if(strcmp(node[i]->element, xml_email_location) == 0)
        {
            os_calloc(1, sizeof(OSMatch),Mail->gran_location[granto_size -1]);
            if(!OSMatch_Compile(node[i]->content, 
                                Mail->gran_location[granto_size -1], 0))
            {
                merror(REGEX_COMPILE, ARGV0, node[i]->content,
                        Mail->gran_location[granto_size -1]->error);
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
    if((Mail->gran_location[granto_size -1] == NULL &&
       Mail->gran_level[granto_size -1] == 0) ||
       Mail->gran_to[granto_size -1] == NULL)
       {
           merror(XML_INV_GRAN_MAIL, ARGV0);
           return(OS_INVALID);
       }
    return(0);
}


/* EOF */
