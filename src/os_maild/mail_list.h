/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _MAILLIST__H
#define _MAILLIST__H

/* Events List structure */
typedef struct _MailNode {
    MailMsg *mail;
    struct _MailNode *next;
    struct _MailNode *prev;
} MailNode;

/* Add an email to the list */
void OS_AddMailtoList(MailMsg *ml) __attribute__((nonnull));

/* Return the last event from the Event list
 * removing it from there
 */
MailNode *OS_PopLastMail(void);

/* Return a pointer to the last email, not removing it */
MailNode *OS_CheckLastMail(void);

/* Create the mail list. Maxsize must be specified */
void OS_CreateMailList(int maxsize);

/* Free an email node */
void FreeMail(MailNode *ml);

/* Free email msg */
void FreeMailMsg(MailMsg *ml);

#endif /* _MAILLIST__H */

