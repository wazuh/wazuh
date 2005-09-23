/*  $OSSEC, os_maild/sendmail.c, v0.1, 2005/03/18, Daniel B. Cid$   */

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

#include "maild.h"
#include "mail_list.h"

#include "headers/defs.h"
#include "headers/os_err.h"
#include "headers/debug_op.h"
#include "os_net/os_net.h"
#include "os_regex/os_regex.h"

/* Return codes (from SMTP server) */
#define VALIDBANNER		"220"
#define VALIDMAIL		"250"
#define VALIDDATA		"354"

/* Default values use to connect */
#define SMTP_DEFAULT_PORT	25
#define HELOMSG 		"HELO notify.ossec.net\r\n"
#define MAILFROM		"Mail From: <%s>\r\n"
#define RCPTTO			"RCPT TO: <%s>\r\n"
#define DATAMSG 		"DATA\r\n"
#define FROM			"From: OSSEC HIDS <%s>\r\n"
#define TO			    "To: <%s>\r\n"
#define SUBJECT			"Subject: %s\r\n"
#define ENDDATA			"\r\n.\r\n"
#define QUITMSG 		"QUIT\r\n"


/* Error messages - Can be translated */
#define INTERNAL_ERROR	"os_maild (1701): Memory/configuration error"
#define BANNER_ERROR	"os_sendmail(1702): Banner not received from server"
#define HELO_ERROR	"os_sendmail(1703): Hello not accepted by server"
#define FROM_ERROR	"os_sendmail(1704): Mail from not accepted by server"
#define TO_ERROR	"os_sendmail(1705): RCPT TO not accepted by server"
#define DATA_ERROR	"os_sendmail(1706): DATA not accepted by server"
#define END_DATA_ERROR	"os_sendmail(1707): End of DATA not accepted by server"

/* OS_Sendmail v0.1: 2005/03/18
 */
int OS_Sendmail(MailConfig *mail)
{
    int socket,i=0;
    char *msg;
    char snd_msg[128];

    MailNode *mailmsg;
   
    mailmsg = OS_PopLastMail();
    
    if(mailmsg == NULL)
    {
        merror("%s: No email to be sent. Inconsistent state",ARGV0);
    }
     
    /* Connecting to the smtp server */	
    socket = OS_ConnectTCP(SMTP_DEFAULT_PORT, mail->smtpserver);
    if(socket < 0)
        return(socket);

    /* Receiving the banner */
    msg = OS_RecvTCP(socket, OS_MAXSTR);
    if((msg == NULL)||(!OS_Match(VALIDBANNER, msg)))
    {
        merror(BANNER_ERROR);
        free(msg);
        close(socket);
        return(OS_INVALID);	
    }
    free(msg);

    /* Sending HELO message */
    OS_SendTCP(socket,HELOMSG);
    msg = OS_RecvTCP(socket, OS_MAXSTR);
    if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
    {
        merror("%s:%s",HELO_ERROR,msg);
        free(msg);
        close(socket);
        return(OS_INVALID);	
    }
    free(msg);	


    /* Building "Mail from" msg */
    memset(snd_msg,'\0',128);
    snprintf(snd_msg,127,MAILFROM, mail->from);
    OS_SendTCP(socket,snd_msg);
    msg = OS_RecvTCP(socket, OS_MAXSTR);
    if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
    {
        merror("%s:%s",FROM_ERROR,msg);
        free(msg);
        close(socket);
        return(OS_INVALID);	
    }
    free(msg);	

    /* Building "RCPT TO" msg */
    while(1)
    {
        if(mail->to[i] == NULL)
        {
            if(i == 0)
            {
                merror(INTERNAL_ERROR);
                close(socket);
                return(OS_INVALID);
            }
            break;
        }
        memset(snd_msg,'\0',128);
        snprintf(snd_msg,127,RCPTTO, mail->to[i++]);
        OS_SendTCP(socket,snd_msg);
        msg = OS_RecvTCP(socket, OS_MAXSTR);
        if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
        {
            merror(TO_ERROR);
            free(msg);
            close(socket);
            return(OS_INVALID);	
        }
        free(msg);
    }


    /* Sending the "DATA" msg */
    OS_SendTCP(socket,DATAMSG);
    msg = OS_RecvTCP(socket, OS_MAXSTR);
    if((msg == NULL)||(!OS_Match(VALIDDATA, msg)))
    {
        merror(DATA_ERROR);
        free(msg);
        close(socket);
        return(OS_INVALID);	
    }
    free(msg);


    /* Building "From" and "To" in the e-mail header */
    memset(snd_msg,'\0',128);
    snprintf(snd_msg,127,TO,mail->to[0]);
    OS_SendTCP(socket, snd_msg);

    memset(snd_msg,'\0',128);
    snprintf(snd_msg,127,FROM,mail->from);
    OS_SendTCP(socket, snd_msg);

    /* Sending subject */
    memset(snd_msg,'\0',128);
    snprintf(snd_msg,127,SUBJECT,mailmsg->mail->subject);	
    OS_SendTCP(socket,snd_msg);

    /* Sending body */

    /* Sending multiple emails together if we have to */
    do
    {
        OS_SendTCP(socket,mailmsg->mail->body);
        mailmsg = OS_PopLastMail();
    }while(mailmsg);
    
    /* Sending end of data \r\n.\r\n */
    OS_SendTCP(socket,ENDDATA);	
    msg = OS_RecvTCP(socket, OS_MAXSTR);
    if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
    {
        merror(END_DATA_ERROR);
        free(msg);
        close(socket);
        return(OS_INVALID);	
    }
    free(msg);

    /* quitting and closing socket */
    OS_SendTCP(socket,QUITMSG);
    msg = OS_RecvTCP(socket, OS_MAXSTR);
    free(msg);
    memset(snd_msg,'\0',128);	

    /* Returning 0 (sucess) */
    close(socket);
    return(0);
}
/* EOF */
