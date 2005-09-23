#ifndef _MAILIST__H

#define _MAILIST__H


/* Events List structure */
typedef struct _MailNode
{
    MailMsg *mail;
    struct _MailNode *next;
    struct _MailNode *prev;
}MailNode;


/* Add an email to the list  */
void OS_AddMailtoList(MailMsg *ml);

/* Return the last event from the Event list 
 * removing it from there
 */
MailNode *OS_PopLastMail();

/* Returns a pointer to the last email, not removing it */
MailNode *OS_CheckLastMail();

/* Create the mail list. Maxsize must be specified */
void OS_CreateMailList(int maxsize);

/* Free an email node */
void FreeMail(MailNode *ml);

#endif
