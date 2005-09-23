/*   $OSSEC, os_maild_client.c, v0.2, 2005/08/24, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
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

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>

#include "headers/defs.h"
#include "headers/debug_op.h"
#include "headers/mem_op.h"

#include "os_regex/os_regex.h"

#include "maild.h"

#include "error_messages/error_messages.h"

int OS_SendMailQ(int socket, MailMsg *mail)
{
    char tmpstr[MAIL_MAXSIZE+1];

    tmpstr[0] = '\0';
    tmpstr[MAIL_MAXSIZE] = '\0'; /* Always garantee null termination
                                     * we never know what a crappy 
                                     * implementation can do with snprintf
                                     */
    
    snprintf(tmpstr, MAIL_MAXSIZE,"%d:%d:%d:%s%s",mail->type,
            mail->subject_size,
            mail->body_size,
            mail->subject,
            mail->body);

    /* We can't block in here */
    if(send(socket,tmpstr,strlen(tmpstr),MSG_DONTWAIT) < 0)
    {
        if(errno == EAGAIN)
        {
            merror("%s: Error sending to the mailq. Would block.",
                                ARGV0);
            return(1);            
        }
        else
        {
            close(socket);
            return(-1);
        }
    }
    
    
    return(0);
}

/* OS_RecvMailQ, v0.1, 2005/03/15
 * Receive a Message on the Mail queue
 */
MailMsg *OS_RecvMailQ(int socket)
{
    int ts=0;

    char  tmpstr[MAIL_MAXSIZE+1];
    char  *body = NULL;
    char  **pieces = NULL;

    fd_set fdset;
    struct timeval socket_timeout;
    
    MailMsg *mail;

    tmpstr[0] = '\0';
    tmpstr[MAIL_MAXSIZE] = '\0';    /* Always garantee null termination
                                     * we never know what a crappy 
                                     * implementation can do ..
                                     */

    /* default values */
    socket_timeout.tv_sec = mail_timeout;
    socket_timeout.tv_usec= 0;
    
    mail = (MailMsg *)calloc(1,sizeof(MailMsg));
    if(mail == NULL)
    {
        merror(MEM_ERROR,ARGV0);
        return(NULL);
    }
    
    mail->body = NULL;
    mail->subject = NULL;
    mail->type = 0;
    mail->subject_size = 0;
    mail->body_size = 0;


    /* Setting FD values */
    FD_ZERO(&fdset);

    FD_SET(socket, &fdset);

    /* Adding timeout */
    if(select(socket+1, &fdset, NULL, NULL, &socket_timeout) == 0)
    {
        /* timeout gone */
        free(mail);
        return(NULL);
    }
    
    if(!FD_ISSET(socket, &fdset))
    {
        merror("%s: Socket error (select)",ARGV0);
        free(mail);
        return(NULL);
    }
   
    /* Receive if there is anything available */ 
    if((ts = recvfrom(socket,tmpstr,MAIL_MAXSIZE,0,NULL,0)) < 0)
    {
        merror("%s: Error receving from the queue");
        free(mail);
        return(NULL);
    }

    
    /* Breaking in 4 pieces */
    pieces = OS_StrBreak(':', tmpstr, 4);
    if(pieces == NULL)
    {
        merror(MEM_ERROR,ARGV0);
        free(mail);
        return(NULL);
    }

    /* Can't have any pieces as null */
    else if(pieces[0] == NULL || pieces[1] == NULL ||
            pieces[2] == NULL || pieces[3] == NULL)
    {
        ClearStrMem(NULL, pieces);
        free(mail);
        goto mail_error;
    }
    
        
    if(OS_StrIsNum(pieces[0]))
        mail->type = atoi(pieces[0]);
    if(OS_StrIsNum(pieces[1]))
        mail->subject_size = atoi(pieces[1]);
    if(OS_StrIsNum(pieces[2]))
        mail->body_size = atoi(pieces[2]);

   
    mail->subject = (char *)calloc(mail->subject_size+1,sizeof(char));
    
    mail->body = (char *)calloc(mail->body_size+1,sizeof(char));
    
    if((mail->subject == NULL)||(mail->body == NULL))
    {
        if(mail->subject)
            free(mail->subject);
        if(mail->body)
            free(mail->body);
        ClearStrMem(NULL, pieces);
        free(mail);
        goto mail_error;
    }

    
    strncpy(mail->subject,pieces[3],mail->subject_size);

    body = pieces[3];

    body += mail->subject_size;
    
    strncpy(mail->body,body,mail->body_size);
    
    /* Cleaning the memory */
    ClearStrMem(NULL, pieces);
    return(mail);

    mail_error:
        merror(QUEUE_ERROR,ARGV0,MAILQUEUE); 
        return(NULL);

}
/* EOF */
