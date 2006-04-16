/*   $OSSEC, os_maild_client.c, v0.3, 2006/04/14, Daniel B. Cid$   */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.2 (2005/08/24): Adding variable timeout
 * v0.1 (2005/03/15)
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
    int i = 0;
    char logs[OS_MAXSTR +1];
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
        strncat(logs, al_data->log[i], OS_MAXSTR - strlen(logs) -1);
        i++;
    }

    /* Subject */
    snprintf(mail->subject, SUBJECT_SIZE -1, MAIL_SUBJECT, al_data->level);

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
