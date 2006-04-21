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

/* Each timeout is x * 5 */
#define NEXTMAIL_TIMEOUT    2    /* Time to check for next msg - 5 */
#define DEFAULT_TIMEOUT     18   /* socket read timeout - 18 (*5)*/ 
#define SUBJECT_SIZE        128  /* Maximum subject size */
#define BODY_SIZE           1256 /* Maximum body size */

#define MAIL_SUBJECT        "OSSEC Hids Notification - Alert level %d"
#define MAIL_BODY           "\r\nOSSEC HIDS Notification.\r\n" \
                            "%s\r\n\r\n" \
                            "Received From: %s\r\n" \
                            "Rule: %d fired (level %d) -> \"%s\"\r\n" \
                            "Portion of the log(s):\r\n\r\n%s\r\n" \
                            "\r\n\r\n --END OF NOTIFICATION\r\n\r\n\r\n"


/* Mail msg structure */
typedef struct _MailMsg
{
	char *subject;
	char *body;
}MailMsg;

#include "shared.h"
#include "config/mail-config.h"


/* Config function */    
int MailConf(char *cfgfile, MailConfig *Mail);


/* Receive the e-mail message */
MailMsg *OS_RecvMailQ(file_queue *fileq, struct tm *p);

/* Sends an email */
int OS_Sendmail(MailConfig *mail);

/* Mail timeout used by the file-queue */
int mail_timeout;

#endif
