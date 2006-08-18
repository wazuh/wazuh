/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "maild.h"


/* OS_RecvMailQ, 
 * v0.1, 2005/03/15
 * Receive a Message on the Mail queue
 * v0,2: Using the new file-queue.
 */
MailMsg *OS_RecvMailQ(file_queue *fileq, struct tm *p)
{
    int i = 0, body_size = OS_MAXSTR -1, log_size;
    char logs[OS_MAXSTR + 1];
    char *subject_host;
    
    MailMsg *mail;
    alert_data *al_data;


    /* Get message if available */
    al_data = Read_FileMon(fileq, p, mail_timeout);

    if(!al_data)
        return(NULL);


    /* If e-mail came correctly, generate the e-mail body/subject */
    os_calloc(1,sizeof(MailMsg), mail);
    os_calloc(BODY_SIZE, sizeof(char), mail->body);
    os_calloc(SUBJECT_SIZE, sizeof(char), mail->subject);


    /* Generating the logs */
    logs[0] = '\0';
    logs[OS_MAXSTR] = '\0';
    while(al_data->log[i])
    {
        log_size = strlen(al_data->log[i]) + 4;
        
        /* If size left is small than the size of the log, stop it */
        if(body_size <= log_size)
        {
            break;
        }
        
        strncat(logs, al_data->log[i], body_size);
        strncat(logs, "\r\n", body_size);
        body_size -= log_size;
        i++;
    }

    /* Subject */
    subject_host = strchr(al_data->location, '>');
    if(subject_host)
    {
        subject_host--;
        *subject_host = '\0';
    }
    snprintf(mail->subject, SUBJECT_SIZE -1, MAIL_SUBJECT, 
                                             al_data->location,
                                             al_data->level);

    /* fixing subject back */
    if(subject_host)
    {
        *subject_host = '-';
    }
    
    /* Body */
    snprintf(mail->body, BODY_SIZE -1, MAIL_BODY,
            al_data->date,
            al_data->location,
            al_data->rule,
            al_data->level,
            al_data->comment,
            logs);

    
    /* Clearing the memory */
    FreeAlertData(al_data);
    
    return(mail);

}
/* EOF */
