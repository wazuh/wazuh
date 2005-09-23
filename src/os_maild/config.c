/*   $OSSEC, config.c, v0.1, 2005/04/01, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "headers/defs.h"
#include "headers/os_err.h"

#include "headers/file_op.h"
#include "headers/config_op.h"
#include "headers/debug_op.h"

#include "os_xml/os_xml.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"

#include "maild.h"

extern short int dbg_flag;

/* MailConf v0.1: 2005/04/01
 * Reads the Mail configuration
 */
int MailConf(char *cfgfile, MailConfig *Mail)
{
    OS_XML xml;
    char *str = NULL;
    int mailnotify=0;

    char *(xml_global_emailto[])={xml_global,"emailto",NULL};
    char *(xml_global_emailfrom[])={xml_global,"emailfrom",NULL};
    char *(xml_global_smtpserver[])={xml_global, "smtpserver",NULL};
    char *(xml_global_mailnotify[])={xml_global, "mail-notify",NULL};
    char *(xml_global_mailmaxperhour[])={xml_global, "mail-maxperhour",NULL};

    if(OS_ReadXML(cfgfile,&xml) < 0)
    {
        merror("config_op: XML Error: %s",xml.err);
        return(OS_INVALID);
    }

    /* Checking if the e-mail notification is enable */
    if(OS_ElementExist(&xml,xml_global_mailnotify))
    {
        str = OS_GetOneContentforElement(&xml, xml_global_mailnotify);
        if(str != NULL)
        {
            if(str[0] == 'y')
                mailnotify=1;
                
            free(str);
            str = NULL;
        }
    }

    /* Getting the mail variables */	
    if(mailnotify == 1)
    {
        char **mails;
       
        Mail->to = NULL;
        Mail->from = NULL;
        Mail->smtpserver = NULL;
        Mail->maxperhour = 12;
         
        /* Getting the emailto */
        Mail->to = OS_GetElementContent(&xml, xml_global_emailto);
        if((Mail->to == NULL)||(Mail->to[0] == NULL))
        {
            merror("config_op: You need to specify the mailto.");
            return(OS_INVALID);
        }

        mails = Mail->to;
        while(*mails)
        {
            debug2("config_op: Sending e-mails to: %s",*mails);
            mails++;
        }

        /* Getting the emailfrom */
        Mail->from=OS_GetOneContentforElement(&xml, xml_global_emailfrom);
        if(Mail->from == NULL)
        {
            merror("config_op: You need to specify the mailfrom.");
            return(OS_INVALID);
        }

        
        /* Max number of emails per hour */
        str = OS_GetOneContentforElement(&xml, xml_global_mailmaxperhour);
        if(str)
        {
            if(OS_StrIsNum(str))
            {
                Mail->maxperhour = atoi(str);
            }

            free(str);
            str = NULL;    
        }
        
        /* Getting the smtp server */
        str = OS_GetOneContentforElement(&xml, xml_global_smtpserver);
        if(str == NULL)
        {
            merror("config_op: You need to specify the smtpserver.");
            return(OS_INVALID);
        }
        else
        {
            if((Mail->smtpserver = OS_GetHost(str)) == NULL)
            {
                merror("SMTP server \"%s\" invalid or host not found",
                        str);
                free(str);
                return(OS_INVALID);
            }
            free(str);
            str = NULL;
        }

        return (0);
    }
    
    /* Mail notification disabled
     * We can exit from here.
     */
    verbose("%s: E-Mail notification disabled. Nothing to be"
            " done over here. Clean exit.",ARGV0);
    exit(0); 
}

/* EOF */
