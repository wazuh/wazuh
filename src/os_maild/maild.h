/*   $OSSEC, maild.h, v0.2, 2005/08/24, Daniel B. Cid$   */

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

#ifndef _MAILD_H

#define _MAILD_H

#define MAILQUEUE	    "queue/alerts/mailq"
#define MAIL_LIST_SIZE      96   /* Max number of emails to be saved */
#define MAXCHILDPROCESS     6    /* Maximum simultaneos childs */
#define NEXTMAIL_TIMEOUT    5    /* Time to check for next msg */
#define DEFAULT_TIMEOUT     90   /* socket read timeout */ 
#define MAIL_MAXSIZE        2048 /* Maximum e-mail message size */

/* Mail msg structure */
typedef struct _MailMsg
{
	int type;
	int subject_size;
	int body_size;
	char *subject;
	char *body;
}MailMsg;

/* Mail config structure */
typedef struct _MailConfig
{
    char **to;
    char *from;
    char *smtpserver;
    int maxperhour;
}MailConfig;

/* Config function */    
int MailConf(char *cfgfile, MailConfig *Mail);


/* Send and receive the e-mail message on the unix queue */
MailMsg *OS_RecvMailQ(int socket);
int OS_SendMailQ(int socket, MailMsg *mail);

/* Sends an email */
int OS_Sendmail(MailConfig *mail);

/* Mail timeout used by select */
int mail_timeout;

#endif
