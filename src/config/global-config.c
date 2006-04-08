/*   $OSSEC, global-config.c, v0.1, 2005/04/02, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
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
#include "os_net/os_net.h"
#include "global-config.h"
#include "mail-config.h"


/* GlobalConf vv0.2: 2005/03/03
 * v0.2: Changing to support the new OS_XML
 */
int Read_Global(XML_NODE node, void *configp, void *mailp)
{
    int i = 1;

    /* White list size */
    int white_size = 1;
    int mailto_size = 1;


    /* XML definitions */
    char *xml_mailnotify = "email_notification";
    char *xml_logall = "logall";
    char *xml_integrity = "integrity_checking";
    char *xml_rootcheckd = "rootkit_detection";
    char *xml_stats = "stats";
    char *xml_memorysize = "memory_size";
    char *xml_white_list = "white_list";

    char *xml_emailto = "email_to";
    char *xml_emailfrom = "email_from";
    char *xml_smtpserver = "smtp_server";
    char *xml_mailmaxperhour = "email_maxperhour";

    _Config *Config;
    MailConfig *Mail;
     
    Config = (_Config *)configp;
    Mail = (MailConfig *)mailp;
    
    
    /* Mail structure */
    if(Mail)
    {
        Mail->to = NULL;
        Mail->from = NULL;
        Mail->smtpserver = NULL;
        Mail->maxperhour = 12;
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
        else if(strcmp(node[i]->element, xml_mailnotify) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                Config->mailnotify = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                Config->mailnotify = 0;
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        /* Log all */
        else if(strcmp(node[i]->element, xml_logall) == 0)
        {
            if(strcmp(node[i]->content, "yes") == 0)
                Config->logall = 1;
            else if(strcmp(node[i]->content, "no") == 0)
                Config->logall = 0;
            else
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);                return(OS_INVALID);
            }
        }
        /* Integrity */
        else if(strcmp(node[i]->element, xml_integrity) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            Config->integrity = atoi(node[i]->content);
        }
        /* rootcheck */
        else if(strcmp(node[i]->element, xml_rootcheckd) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            Config->rootcheck = atoi(node[i]->content);
        }
        /* stats */
        else if(strcmp(node[i]->element, xml_stats) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            Config->stats = atoi(node[i]->content);
        }
        else if(strcmp(node[i]->element, xml_memorysize) == 0)
        {
            if(!OS_StrIsNum(node[i]->content))
            {
                merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
            Config->memorysize = atoi(node[i]->content);
        }
        /* whitelist */
        else if(strcmp(node[i]->element, xml_white_list) == 0)
        {
            white_size++;
            Config->white_list = realloc(Config->white_list, sizeof(char *)*white_size);
            if(!Config->white_list)
            {
                merror(MEM_ERROR, ARGV0);
                return(OS_INVALID);
            }

            os_strdup(node[i]->content,Config->white_list[white_size -2]);
            Config->white_list[white_size -1] = NULL;
            if(!OS_IsValidIP(Config->white_list[white_size -2]))
            {
                merror(INVALID_IP, ARGV0, Config->white_list[white_size -2]);
                return(OS_INVALID);
            }
        }
        
        /* For the email now 
         * email_to, email_from, smtp_Server and maxperhour.
         * We will use a separate structure for that.
         */
        else if(strcmp(node[i]->element, xml_emailto) == 0)
        {
            if(Mail)
            {
                mailto_size++;
                Mail->to = realloc(Mail->to, sizeof(char *)*mailto_size);
                if(!Mail->to)
                {
                    merror(MEM_ERROR, ARGV0);
                    return(OS_INVALID);
                }

                os_strdup(node[i]->content, Mail->to[mailto_size - 2]);
                Mail->to[mailto_size - 1] = NULL;
            }
        }
        else if(strcmp(node[i]->element, xml_emailfrom) == 0)
        {
            if(Mail)
            {
                if(Mail->from)
                {
                    free(Mail->from);
                }
                os_strdup(node[i]->content, Mail->from);
            }
        }
        else if(strcmp(node[i]->element, xml_smtpserver) == 0)
        {
            if(Mail)
            {
                Mail->smtpserver = OS_GetHost(node[i]->content);
                if(!Mail->smtpserver)
                {
                    merror(INVALID_SMTP, ARGV0, node[i]->content);
                    return(OS_INVALID);
                }
            }
        }
        else if(strcmp(node[i]->element, xml_mailmaxperhour) == 0)
        {
            if(Mail)
            {
                if(!OS_StrIsNum(node[i]->content))
                {
                   merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                   return(OS_INVALID);
                }
                Mail->maxperhour = atoi(node[i]->content);

                if((Mail->maxperhour <= 0) || (Mail->maxperhour > 9999))
                {
                   merror(XML_VALUEERR,ARGV0,node[i]->element,node[i]->content);
                   return(OS_INVALID);
                }
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
