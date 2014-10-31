/* @(#) $Id: ./src/os_maild/sendmail.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Basic e-mailing operations */


#include "shared.h"
#include "os_net/os_net.h"
#include "maild.h"
#include "mail_list.h"


/* Return codes (from SMTP server) */
#define VALIDBANNER		"220"
#define VALIDMAIL		"250"
#define VALIDDATA		"354"


/* Default values use to connect */
#define SMTP_DEFAULT_PORT	25
#define MAILFROM		"Mail From: <%s>\r\n"
#define RCPTTO			"Rcpt To: <%s>\r\n"
#define DATAMSG 		"DATA\r\n"
#define FROM			"From: OSSEC HIDS <%s>\r\n"
#define TO			    "To: <%s>\r\n"
/*#define CC			    "Cc: <%s>\r\n"*/
#define SUBJECT			"Subject: %s\r\n"
#define ENDHEADER               "\r\n"
#define ENDDATA			"\r\n.\r\n"
#define QUITMSG 		"QUIT\r\n"
#define XHEADER 		"X-IDS-OSSEC: %s\r\n"


/* Error messages - Can be translated */
#define INTERNAL_ERROR	"os_maild (1760): ERROR: Memory/configuration error"
#define BANNER_ERROR	"os_sendmail(1762): WARN: Banner not received from server"
#define HELO_ERROR	    "os_sendmail(1763): WARN: Hello not accepted by server"
#define FROM_ERROR	    "os_sendmail(1764): WARN: Mail from not accepted by server"
#define TO_ERROR	    "os_sendmail(1765): WARN: RCPT TO not accepted by server - '%s'."
#define DATA_ERROR	    "os_sendmail(1766): WARN: DATA not accepted by server"
#define END_DATA_ERROR	"os_sendmail(1767): WARN: End of DATA not accepted by server"


#define MAIL_DEBUG_FLAG     0
#define MAIL_DEBUG(x,y,z) if(MAIL_DEBUG_FLAG) merror(x,y,z)


/* OS_Sendsms.
 */
int OS_Sendsms(MailConfig *mail, struct tm *p, MailMsg *sms_msg)
{
    int socket;
    size_t final_to_sz;
    char *msg;
    char snd_msg[128];
    char final_to[512];


    /* Connecting to the smtp server */
    socket = OS_ConnectTCP(SMTP_DEFAULT_PORT, mail->smtpserver, 0);
    if(socket < 0)
    {
        return(socket);
    }


    /* Receiving the banner */
    msg = OS_RecvTCP(socket, OS_SIZE_1024);
    if((msg == NULL)||(!OS_Match(VALIDBANNER, msg)))
    {
        merror(BANNER_ERROR);
        if(msg)
            free(msg);
        close(socket);
        return(OS_INVALID);
    }
    MAIL_DEBUG("DEBUG: Received banner: '%s' %s", msg, "");
    free(msg);



    /* Sending HELO message */
    memset(snd_msg,'\0',128);
    if(mail->heloserver) {
      snprintf(snd_msg,127, "Helo %s\r\n", mail->heloserver);
    } else {
      snprintf(snd_msg,127, "Helo %s\r\n", "notify.ossec.net");
    }
    OS_SendTCP(socket,snd_msg);
    msg = OS_RecvTCP(socket, OS_SIZE_1024);
    if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
    {
        if(msg)
        {
            /* Ugly fix warning :) */
            /* In some cases (with virus scans in the middle)
             * we may get two banners. Check for that in here.
             */
            if(OS_Match(VALIDBANNER, msg))
            {
                free(msg);

                /* Try again */
                msg = OS_RecvTCP(socket, OS_SIZE_1024);
                if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
                {
                    merror("%s:%s",HELO_ERROR,msg!= NULL?msg:"null");
                    if(msg)
                        free(msg);
                    close(socket);
                    return(OS_INVALID);
                }
            }
            else
            {
                merror("%s:%s",HELO_ERROR,msg);
                free(msg);
                close(socket);
                return(OS_INVALID);
            }
        }
        else
        {
            merror("%s:%s",HELO_ERROR,"null");
            close(socket);
            return(OS_INVALID);
        }
    }

    MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
    free(msg);


    /* Building "Mail from" msg */
    memset(snd_msg,'\0',128);
    snprintf(snd_msg,127, MAILFROM, mail->from);
    OS_SendTCP(socket, snd_msg);
    msg = OS_RecvTCP(socket, OS_SIZE_1024);
    if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
    {
        merror(FROM_ERROR);
        if(msg)
            free(msg);
        close(socket);
        return(OS_INVALID);
    }
    MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
    free(msg);


    /* Additional RCPT to */
    final_to[0] = '\0';
    final_to_sz = sizeof(final_to) -2;

    if(mail->gran_to)
    {
        int i = 0;
        while(mail->gran_to[i] != NULL)
        {
            if(mail->gran_set[i] != SMS_FORMAT)
            {
                i++;
                continue;
            }

            memset(snd_msg,'\0',128);
            snprintf(snd_msg,127, RCPTTO, mail->gran_to[i]);
            OS_SendTCP(socket, snd_msg);
            msg = OS_RecvTCP(socket, OS_SIZE_1024);
            if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
            {
                merror(TO_ERROR, mail->gran_to[i]);
                if(msg)
                    free(msg);
                close(socket);
                return(OS_INVALID);
            }
            MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
            free(msg);


            /* Creating header for to */
            memset(snd_msg,'\0',128);
            snprintf(snd_msg,127, TO, mail->gran_to[i]);
            strncat(final_to, snd_msg, final_to_sz);
            final_to_sz -= strlen(snd_msg) +2;

            i++;
            continue;
        }
    }


    /* Sending the "DATA" msg */
    OS_SendTCP(socket,DATAMSG);
    msg = OS_RecvTCP(socket, OS_SIZE_1024);
    if((msg == NULL)||(!OS_Match(VALIDDATA, msg)))
    {
        merror(DATA_ERROR);
        if(msg)
            free(msg);
        close(socket);
        return(OS_INVALID);
    }
    MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", DATAMSG, msg);
    free(msg);


    /* Building "From" and "To" in the e-mail header */
    OS_SendTCP(socket, final_to);


    memset(snd_msg,'\0',128);
    snprintf(snd_msg,127, FROM, mail->from);
    OS_SendTCP(socket, snd_msg);


    /* Sending date */
    memset(snd_msg,'\0',128);


    /* Solaris doesn't have the "%z", so we set the timezone to 0. */
    #ifdef SOLARIS
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T -0000\r\n",p);
    #else
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T %z\r\n",p);
    #endif

    OS_SendTCP(socket,snd_msg);


    /* Sending subject */
    memset(snd_msg,'\0',128);
    snprintf(snd_msg, 127, SUBJECT, sms_msg->subject);
    OS_SendTCP(socket,snd_msg);

    OS_SendTCP(socket,ENDHEADER);


    /* Sending body */
    OS_SendTCP(socket, sms_msg->body);


    /* Sending end of data \r\n.\r\n */
    OS_SendTCP(socket,ENDDATA);
    msg = OS_RecvTCP(socket, OS_SIZE_1024);
    if(mail->strict_checking && ((msg == NULL)||(!OS_Match(VALIDMAIL, msg))))
    {
        merror(END_DATA_ERROR);
        if(msg)
            free(msg);
        close(socket);
        return(OS_INVALID);
    }
    /* Checking msg in here, since it may be null */
    if(msg)
        free(msg);


    /* quitting and closing socket */
    OS_SendTCP(socket,QUITMSG);
    msg = OS_RecvTCP(socket, OS_SIZE_1024);

    if(msg)
        free(msg);

    memset_secure(snd_msg,'\0',128);


    /* Returning 0 (success) */
    close(socket);

    return(0);
}



/* OS_Sendmail v0.1: 2005/03/18
 */
int OS_Sendmail(MailConfig *mail, struct tm *p)
{
    int socket,i=0;
    char *msg;
    char snd_msg[128];

    MailNode *mailmsg;

   /* If there is no sms message, we attempt to get from the
     * email list.
     */
    mailmsg = OS_PopLastMail();

    if(mailmsg == NULL)
    {
        merror("%s: No email to be sent. Inconsistent state.",ARGV0);
        return (OS_INVALID);
    }


    /* Connecting to the smtp server */
    socket = OS_ConnectTCP(SMTP_DEFAULT_PORT, mail->smtpserver, 0);
    if(socket < 0)
    {
        return(socket);
    }


    /* Receiving the banner */
    msg = OS_RecvTCP(socket, OS_SIZE_1024);
    if((msg == NULL)||(!OS_Match(VALIDBANNER, msg)))
    {
        merror(BANNER_ERROR);
        if(msg)
            free(msg);
        close(socket);
        return(OS_INVALID);
    }
    MAIL_DEBUG("DEBUG: Received banner: '%s' %s", msg, "");
    free(msg);



    /* Sending HELO message */
    memset(snd_msg,'\0',128);
    if(mail->heloserver) {
      snprintf(snd_msg,127, "Helo %s\r\n", mail->heloserver);
    } else {
      snprintf(snd_msg,127, "Helo %s\r\n", "notify.ossec.net");
    }
    OS_SendTCP(socket,snd_msg);
    msg = OS_RecvTCP(socket, OS_SIZE_1024);
    if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
    {
        if(msg)
        {
            /* Ugly fix warning :) */
            /* In some cases (with virus scans in the middle)
             * we may get two banners. Check for that in here.
             */
            if(OS_Match(VALIDBANNER, msg))
            {
                free(msg);

                /* Try again */
                msg = OS_RecvTCP(socket, OS_SIZE_1024);
                if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
                {
                    merror("%s:%s",HELO_ERROR,msg!= NULL?msg:"null");
                    if(msg)
                        free(msg);
                    close(socket);
                    return(OS_INVALID);
                }
            }
            else
            {
                merror("%s:%s",HELO_ERROR,msg);
                free(msg);
                close(socket);
                return(OS_INVALID);
            }
        }
        else
        {
            merror("%s:%s",HELO_ERROR,"null");
            close(socket);
            return(OS_INVALID);
        }
    }

    MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
    free(msg);


    /* Building "Mail from" msg */
    memset(snd_msg,'\0',128);
    snprintf(snd_msg,127, MAILFROM, mail->from);
    OS_SendTCP(socket, snd_msg);
    msg = OS_RecvTCP(socket, OS_SIZE_1024);
    if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
    {
        merror(FROM_ERROR);
        if(msg)
            free(msg);
        close(socket);
        return(OS_INVALID);
    }
    MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
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
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
        {
            merror(TO_ERROR, mail->to[i -1]);
            if(msg)
                free(msg);
            close(socket);
            return(OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
        free(msg);
    }


    /* Additional RCPT to */
    if(mail->gran_to)
    {
        i = 0;
        while(mail->gran_to[i] != NULL)
        {
            if(mail->gran_set[i] != FULL_FORMAT)
            {
                i++;
                continue;
            }

            memset(snd_msg,'\0',128);
            snprintf(snd_msg,127,RCPTTO, mail->gran_to[i]);
            OS_SendTCP(socket,snd_msg);
            msg = OS_RecvTCP(socket, OS_SIZE_1024);
            if((msg == NULL)||(!OS_Match(VALIDMAIL, msg)))
            {
                merror(TO_ERROR, mail->gran_to[i]);
                if(msg)
                    free(msg);

                i++;
                continue;
            }

            MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
            free(msg);
            i++;
            continue;
        }
    }


    /* Sending the "DATA" msg */
    OS_SendTCP(socket,DATAMSG);
    msg = OS_RecvTCP(socket, OS_SIZE_1024);
    if((msg == NULL)||(!OS_Match(VALIDDATA, msg)))
    {
        merror(DATA_ERROR);
        if(msg)
            free(msg);
        close(socket);
        return(OS_INVALID);
    }
    MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", DATAMSG, msg);
    free(msg);


    /* Building "From" and "To" in the e-mail header */
    memset(snd_msg,'\0',128);
    snprintf(snd_msg,127, TO, mail->to[0]);
    OS_SendTCP(socket, snd_msg);

    memset(snd_msg,'\0',128);
    snprintf(snd_msg,127, FROM, mail->from);
    OS_SendTCP(socket, snd_msg);


    /* Adding CCs */
    if(mail->to[1])
    {
        i = 1;
        while(1)
        {
            if(mail->to[i] == NULL)
            {
                break;
            }

            memset(snd_msg,'\0',128);
            snprintf(snd_msg,127, TO, mail->to[i]);
            OS_SendTCP(socket,snd_msg);

            i++;
        }
    }


    /* More CCs - from granular options */
    if(mail->gran_to)
    {
        i = 0;
        while(mail->gran_to[i] != NULL)
        {
            if(mail->gran_set[i] != FULL_FORMAT)
            {
                i++;
                continue;
            }

            memset(snd_msg,'\0',128);
            snprintf(snd_msg,127, TO, mail->gran_to[i]);
            OS_SendTCP(socket, snd_msg);
            i++;
            continue;
        }
    }


    /* Sending date */
    memset(snd_msg,'\0',128);


    /* Solaris doesn't have the "%z", so we set the timezone to 0. */
    #ifdef SOLARIS
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T -0000\r\n",p);
    #else
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T %z\r\n",p);
    #endif

    OS_SendTCP(socket,snd_msg);

    if(mail->idsname)
    {
        /* Sending server name header */
        memset(snd_msg,'\0',128);
        snprintf(snd_msg,127, XHEADER, mail->idsname);
        OS_SendTCP(socket, snd_msg);
    }

    /* Sending subject */
    memset(snd_msg,'\0',128);


    /* Checking if global subject is available */
    if((_g_subject_level != 0) && (_g_subject[0] != '\0'))
    {
        snprintf(snd_msg, 127, SUBJECT, _g_subject);

        /* Clearing global values */
        _g_subject[0] = '\0';
        _g_subject_level = 0;
    }
    else
    {
        snprintf(snd_msg, 127, SUBJECT, mailmsg->mail->subject);
    }
    OS_SendTCP(socket,snd_msg);

    OS_SendTCP(socket,ENDHEADER);


    /* Sending body */

    /* Sending multiple emails together if we have to */
    do
    {
        OS_SendTCP(socket, mailmsg->mail->body);
        mailmsg = OS_PopLastMail();
    }while(mailmsg);


    /* Sending end of data \r\n.\r\n */
    OS_SendTCP(socket,ENDDATA);
    msg = OS_RecvTCP(socket, OS_SIZE_1024);
    if(mail->strict_checking && ((msg == NULL)||(!OS_Match(VALIDMAIL, msg))))
    {
        merror(END_DATA_ERROR);
        if(msg)
            free(msg);
        close(socket);
        return(OS_INVALID);
    }
    /* Checking msg in here, since it may be null */
    if(msg)
        free(msg);


    /* quitting and closing socket */
    OS_SendTCP(socket,QUITMSG);
    msg = OS_RecvTCP(socket, OS_SIZE_1024);

    if(msg)
        free(msg);

    memset_secure(snd_msg,'\0',128);


    /* Returning 0 (success) */
    close(socket);

    return(0);
}
/* EOF */
