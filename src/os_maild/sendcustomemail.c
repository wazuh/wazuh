/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Basic e-mailing operations */

#include "shared.h"
#include "os_net/os_net.h"

/* Return codes (from SMTP server) */
#define VALIDBANNER     "220"
#define VALIDMAIL       "250"
#define VALIDDATA       "354"

/* Default values used to connect */
#define SMTP_DEFAULT_PORT   25
#define HELOMSG             "Helo notify.ossec.net\r\n"
#define MAILFROM            "Mail From: <%s>\r\n"
#define RCPTTO              "Rcpt To: <%s>\r\n"
#define DATAMSG             "DATA\r\n"
#define FROM                "From: " __ossec_name " <%s>\r\n"
#define REPLYTO             "Reply-To: " __ossec_name " <%s>\r\n"
#define TO                  "To: <%s>"
#define TO_ADDITIONAL       ", <%s>"
#define TO_END              "\r\n"
#define CC                  "Cc: <%s>\r\n"
#define SUBJECT             "Subject: %s\r\n"
#define ENDHEADER           "\r\n"
#define ENDDATA             "\r\n.\r\n"
#define QUITMSG             "QUIT\r\n"
#define XHEADER             "X-IDS-OSSEC: %s\r\n"

/* Error messages - Can be translated */
#define INTERNAL_ERROR  "(1760): Memory/configuration error"
#define BANNER_ERROR    "(1762): Banner not received from server"
#define HELO_ERROR      "(1763): Hello not accepted by server"
#define FROM_ERROR      "(1764): Mail from not accepted by server"
#define TO_ERROR        "(1765): RCPT TO not accepted by server - '%s'."
#define DATA_ERROR      "(1766): DATA not accepted by server"
#define END_DATA_ERROR  "(1767): End of DATA not accepted by server"

#define MAIL_DEBUG_FLAG     0
#define MAIL_DEBUG(x,y,z) if(MAIL_DEBUG_FLAG) merror(x,y,z)


int OS_SendCustomEmail(char **to, char *subject, char *smtpserver, char *from, char *replyto, char *idsname, FILE *fp, const struct tm *p)
{
    wfd_t *sendmail = NULL;
    int socket = -1, i = 0;
    char *msg;
    char snd_msg[128];
    char buffer[2049];
    size_t final_to_sz;
    char final_to[512];

    buffer[2048] = '\0';

    if (smtpserver[0] == '/') {
        char *exec_cmd[2] = { smtpserver, NULL };
        sendmail = wpopenv(smtpserver, exec_cmd, W_BIND_STDIN);
        if (!sendmail) {
            return (OS_INVALID);
        }
    } else {
        /* Connect to the SMTP server */
        socket = OS_ConnectTCP(SMTP_DEFAULT_PORT, smtpserver, 0, 0);
        if (socket < 0) {
            return (socket);
        }

        /* Receive the banner */
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDBANNER, msg))) {
            merror(BANNER_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            return (OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Received banner: '%s' %s", msg, "");
        free(msg);

        /* Send HELO message */
        OS_SendTCP(socket, HELOMSG);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            if (msg) {
                /* In some cases (with virus scans in the middle)
                 * we may get two banners. Check for that in here.
                 */
                if (OS_Match(VALIDBANNER, msg)) {
                    free(msg);

                    /* Try again */
                    msg = OS_RecvTCP(socket, OS_SIZE_1024);
                    if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                        merror("%s:%s", HELO_ERROR, msg != NULL ? msg : "null");
                        if (msg) {
                            free(msg);
                        }
                        close(socket);
                        return (OS_INVALID);
                    }
                } else {
                    merror("%s:%s", HELO_ERROR, msg);
                    free(msg);
                    close(socket);
                    return (OS_INVALID);
                }
            } else {
                merror("%s:%s", HELO_ERROR, "null");
                close(socket);
                return (OS_INVALID);
            }
        }

        MAIL_DEBUG("Sent '%s', received: '%s'", HELOMSG, msg);
        free(msg);

        /* Build "Mail from" msg */
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, MAILFROM, from);
        OS_SendTCP(socket, snd_msg);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
            merror(FROM_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            return (OS_INVALID);
        }
        MAIL_DEBUG("Sent '%s', received: '%s'", snd_msg, msg);
        free(msg);

        /* Build "RCPT TO" msg */
        while (to[i]) {
            memset(snd_msg, '\0', 128);
            snprintf(snd_msg, 127, RCPTTO, to[i]);
            OS_SendTCP(socket, snd_msg);
            msg = OS_RecvTCP(socket, OS_SIZE_1024);
            if ((msg == NULL) || (!OS_Match(VALIDMAIL, msg))) {
                merror(TO_ERROR, to[i]);
                if (msg) {
                    free(msg);
                }
                close(socket);
                return (OS_INVALID);
            }
            MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", snd_msg, msg);
            free(msg);

            i++;
        }

        /* Send the "DATA" msg */
        OS_SendTCP(socket, DATAMSG);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);
        if ((msg == NULL) || (!OS_Match(VALIDDATA, msg))) {
            merror(DATA_ERROR);
            if (msg) {
                free(msg);
            }
            close(socket);
            return (OS_INVALID);
        }
        MAIL_DEBUG("DEBUG: Sent '%s', received: '%s'", DATAMSG, msg);
        free(msg);
    }

    /* Build "From" in the e-mail header */
    memset(snd_msg, '\0', 128);
    snprintf(snd_msg, 127, FROM, from);

    if (sendmail) {
        fprintf(sendmail->file_in, "%s", snd_msg);
    } else {
        OS_SendTCP(socket, snd_msg);
    }

    if (replyto) {
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, REPLYTO, replyto);

        if (sendmail) {
            fprintf(sendmail->file_in, "%s", snd_msg);
        } else {
            OS_SendTCP(socket, snd_msg);
        }
    }

    final_to[0] = '\0';
    final_to_sz = sizeof(final_to) - 1;

    /* Add TOs */
    if (to[0]) {
        i = 0;
        while (1) {
            if (to[i] == NULL) {
                break;
            }

            memset(snd_msg, '\0', 128);
            if (i == 0) {
                snprintf(snd_msg, 127, TO, to[i]);
            } else {
                snprintf(snd_msg, 127, TO_ADDITIONAL, to[i]);
            }
            strncat(final_to, snd_msg, final_to_sz);
            final_to_sz -= strlen(snd_msg) + 2;
            i++;
        }
        if (final_to[0] != '\0') {
            strncat(final_to, TO_END, final_to_sz);
        }
        if (sendmail) {
            fprintf(sendmail->file_in, "%s", final_to);
        } else {
            OS_SendTCP(socket, final_to);
        }
    }

    /* Send date */
    memset(snd_msg, '\0', 128);

    /* Solaris doesn't have the "%z", so we set the timezone to 0 */
#ifdef SOLARIS
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T -0000\r\n", p);
#else
    strftime(snd_msg, 127, "Date: %a, %d %b %Y %T %z\r\n", p);
#endif

    if (sendmail) {
        fprintf(sendmail->file_in, "%s", snd_msg);
    } else {
        OS_SendTCP(socket, snd_msg);
    }

    if (idsname) {
        /* Send server name header */
        memset(snd_msg, '\0', 128);
        snprintf(snd_msg, 127, XHEADER, idsname);

        if (sendmail) {
            fprintf(sendmail->file_in, "%s", snd_msg);
        } else {
            OS_SendTCP(socket, snd_msg);
        }
    }

    /* Send subject */
    memset(snd_msg, '\0', 128);
    snprintf(snd_msg, 127, SUBJECT, subject);

    if (sendmail) {
        fprintf(sendmail->file_in, "%s", snd_msg);
        fprintf(sendmail->file_in, ENDHEADER);
    } else {
        OS_SendTCP(socket, snd_msg);
        OS_SendTCP(socket, ENDHEADER);
    }

    /* Send body */
    fseek(fp, 0, SEEK_SET);
    while (fgets(buffer, 2048, fp) != NULL) {
        if (sendmail) {
            fprintf(sendmail->file_in, "%s", buffer);
        } else {
            OS_SendTCP(socket, buffer);
        }
    }

    if (sendmail) {
        fflush(sendmail->file_in);
        if (wpclose(sendmail) == -1) {
            merror(WAITPID_ERROR, errno, strerror(errno));
        }
    } else {
        /* Send end of data \r\n.\r\n */
        OS_SendTCP(socket, ENDDATA);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);

        /* Check msg, since it may be null */
        if (msg) {
            free(msg);
        }

        /* Quit and close socket */
        OS_SendTCP(socket, QUITMSG);
        msg = OS_RecvTCP(socket, OS_SIZE_1024);

        if (msg) {
            free(msg);
        }

        close(socket);
    }

    memset_secure(snd_msg, '\0', 128);
    return (0);
}
