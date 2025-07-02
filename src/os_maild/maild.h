/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef MAILD_H
#define MAILD_H

#define MAIL_LIST_SIZE      96   /* Max number of emails to be saved */
#define MAXCHILDPROCESS     6    /* Maximum simultaneous children */

/* Each timeout is x * 5 */
#define NEXTMAIL_TIMEOUT    2    /* Time to check for next msg - 5 */
#define DEFAULT_TIMEOUT     18   /* socket read timeout - 18 (*5)*/
#define SUBJECT_SIZE        128  /* Maximum subject size */

/* Maximum body size */
#define BODY_SIZE           OS_MAXSTR + OS_SIZE_1024

#define SMS_SUBJECT         "Wazuh %d - %d - %s"
#define MAIL_SUBJECT        "Wazuh notification - %s - Alert level %d"
#define MAIL_SUBJECT_FULL   "Wazuh alert - %s - Level %d - %s"

/* Full subject without ossec in the name */
#ifdef CLEANFULL
#define MAIL_SUBJECT_FULL2   "%d - %s - %s"
#endif

#define MAIL_BODY           "\r\n" __ossec_name " Notification.\r\n" \
                            "%s\r\n\r\n" \
                            "Received From: %s\r\n" \
                            "Rule: %d fired (level %d) -> \"%s\"\r\n" \
                            "%s" \
                            "Portion of the log(s):\r\n\r\n%s\r\n" \
                            "\r\n\r\n --END OF NOTIFICATION\r\n\r\n\r\n"

/* Mail msg structure */
typedef struct _MailMsg {
    char *subject;
    char *body;
} MailMsg;

#include "shared.h"
#include "../config/mail-config.h"

/* Config function */
int MailConf(int test_config, const char *cfgfile, MailConfig *Mail) __attribute__((nonnull));

// Read config
cJSON *getMailConfig(void);
cJSON *getMailAlertsConfig(void);
cJSON *getMailInternalOptions(void);

// Com request thread dispatcher
void * mailcom_main(__attribute__((unused)) void * arg);
size_t mailcom_dispatch(char * command, char ** output);
size_t mailcom_getconfig(const char * section, char ** output);

/* Receive the e-mail message */
MailMsg *OS_RecvMailQ(file_queue *fileq, struct tm *p, MailConfig *mail, MailMsg **msg_sms) __attribute__((nonnull));
MailMsg *OS_RecvMailQ_JSON(file_queue *fileq, MailConfig *mail, MailMsg **msg_sms) __attribute__((nonnull));

/**
 * @brief Read cJSON and save in printed with email format
 * @param item Pointer to the cJSON to read
 * @param printed Body email
 * @param body_size Remaining body message size
 * @param tab Determine the number of tabs on each line
 * @param counter Count the number of times that is tabulated in a line
 */
void PrintTable(cJSON *item, char *printed, size_t *body_size, char *tab, int counter);

/* Send an email */
int OS_Sendmail(MailConfig *mail, struct tm *p) __attribute__((nonnull));
int OS_Sendsms(MailConfig *mail, struct tm *p, MailMsg *sms_msg) __attribute__((nonnull));
int OS_SendCustomEmail(char **to, char *subject, char *smtpserver, char *from, char *replyto, char *idsname, FILE *fp, const struct tm *p);

/* Mail timeout used by the file-queue */
extern unsigned int mail_timeout;

/* Global var for highest level on mail subjects */
extern unsigned int   _g_subject_level;
extern char _g_subject[SUBJECT_SIZE + 2];
extern MailConfig mail;

#endif /* MAILD_H */
