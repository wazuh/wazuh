/*   $OSSEC, mail.c, v0.2, 2005/02/10, Daniel B. Cid$   */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */

/* Basic e-mailing operations */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "mail.h"
#include "alerts.h"

#include "headers/defs.h"
#include "headers/os_err.h"
#include "headers/debug_op.h"
#include "rules.h"
#include "config.h"
#include "headers/mq_op.h"

#include "os_net/os_net.h"
#include "os_regex/os_regex.h"
#include "os_maild/maild.h"

#include "eventinfo.h"

#include "error_messages/error_messages.h"

#ifndef SUBJECTMSG
    #define SUBJECTMSG 	"OSSEC HIDS Notification"
#endif

/* OS_Createmail v0.2 
 * v0.2: Added snort fts message
 */
void OS_Createmail(int *mailq, Eventinfo *lf)
{
    char snd_msg[1512];
    char snd_msg2[512];

    MailMsg msg;
    
    /* Do not mail cases */
    if(Config.mailnotify <= 0)
    {
        if(Config.mailnotify < 0)
            return;
            
        merror("logaudit: E-mail configured, but impossible to send.");
        Config.mailnotify = -1;
        return;
    }
    
    else if(Config.mailnotify > 10)
    {
        merror("%s: E-mail notification disabled. Too many errors.", ARGV0);
        Config.mailnotify=-1;
        return;
    }

    msg.body = NULL;
    msg.subject = NULL;
    msg.body_size = 0;
    msg.subject_size = 0;
    msg.type = 0;



    /* Sending headers and subject */
    snprintf(snd_msg,127,"%s - Alert level %d",
                SUBJECTMSG,lf->level);

    msg.subject = calloc(strlen(snd_msg)+1,sizeof(char *));
    if(msg.subject == NULL)
    {
        merror(MEM_ERROR,ARGV0);
        return;
    }
    
    msg.subject_size = strlen(snd_msg);	
    
    strcpy(msg.subject,snd_msg);	


    /* Building the body msg */
    //snprintf(snd_ms2, 255,
      //       "Received From: %s\r\nRule: %d fired (level %d) -> \"%s\"\r\n",
        //     lf->location, lf->sigid,
          //   lf->level, lf->comment);	
    
    if(lf->last_events[0])
    {
        char **lasts = lf->last_events;
        int snd_size = 508;
        int lasts_size = 0;
        
        snd_msg2[0] = '\0';
        snd_msg2[511] = '\0';
        
        while(*lasts)
        {
            lasts_size = strlen(*lasts);
            
            /* Stop if no more space is left on the string */
            if(lasts_size > snd_size)
                break;
                
            strncat(snd_msg2, *lasts, snd_size);
            strcat(snd_msg2, "\r\n");
            
            snd_size-=(lasts_size+2); 
            
            lasts++;    
        }
    }

    /* New format string ... who did it? */
    snprintf(snd_msg, 1511,
            "\r\nOSSEC HIDS Notification.\r\n"
            "%d %s %02d %s\r\n\r\n"
            "Received From: %s\r\nRule: %d fired (level %d) -> \"%s\"\r\n"
            "%s%s\r\n%s"
            "\"\r\n\r\n --END OF NOTIFICATION\r\n\r\n\r\n",
            lf->year,lf->mon,lf->day,lf->hour,
            lf->location, lf->sigid, lf->level, lf->comment,
            "Portion of the log(s):\r\n\r\n\"",
            lf->sigid == STATS_PLUGIN?
                "No Log Available (HOURLY_STATS)":lf->log,
            lf->last_events[0] == NULL?
            "":    
            snd_msg2 
            );    
           
           /* 
    snprintf(snd_msg,512,"%s%d %s %02d %s\r\n\r\n%s%s%s%s",
            "\r\nOSSEC HIDS Notification.\r\n",
            lf->year,lf->mon,lf->day,lf->hour,
            snd_ms2,
            "Portion of the log:\r\n\r\n\"",
            lf->sigid == STATS_PLUGIN?"No Log Available (HOURLY_STATS)":lf->log,
            "\"\r\n\r\n --END OF NOTIFICATION\r\n\r\n");
            */
            
    msg.body = calloc(strlen(snd_msg)+1,sizeof(char *));
    
    if(msg.body == NULL)
    {
        free(msg.subject);
        merror(MEM_ERROR,ARGV0);
        return;
    }
    
    strcpy(msg.body,snd_msg);

    msg.body_size = strlen(snd_msg);	

    if(OS_SendMailQ(*mailq, &msg) < 0)
    {
        /* Impossible to send. Trying again.. */
        merror("%s: Error sending alert information to maild.",ARGV0);
        
        if((*mailq = StartMQ(MAILQUEUE,WRITE)) < 0)
        {
            merror("%s: Attempt to reconnect to the mail queue failed",
                                                         ARGV0);
            Config.mailnotify+=1;
        }
        
        if(OS_SendMailQ(*mailq, &msg) < 0)
        {
            if((*mailq = StartMQ(MAILQUEUE,WRITE)) < 0)
            {
                merror("%s: Attempt to reconnect to the mail queue failed",
                            ARGV0);
            }
            
            Config.mailnotify+=1;
        }
        
         
        /* If reaches here, error++ */
        Config.mailnotify+=1;
    }
    else
        Config.mailnotify=1;
  
  
    /* Freeing the memory */
    free(msg.body);
    free(msg.subject);
    
    msg.body = NULL;
    msg.subject = NULL;
     
    return;
}

/* EOF */
