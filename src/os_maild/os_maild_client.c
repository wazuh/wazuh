/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "maild.h"
#ifdef LIBGEOIP_ENABLED
#include "config/config.h"
#endif


/* Receive a Message on the Mail queue */
MailMsg *OS_RecvMailQ(file_queue *fileq, struct tm *p,
                      MailConfig *Mail, MailMsg **msg_sms)
{
    int i = 0, sms_set = 0, donotgroup = 0;
    size_t body_size = OS_MAXSTR - 3, log_size;
    char logs[OS_MAXSTR + 1];
    char extra_data[OS_MAXSTR + 1];
    char log_string[OS_MAXSTR / 4 + 1];
    char *subject_host;
#ifdef LIBGEOIP_ENABLED
    char geoip_msg_src[OS_SIZE_1024 + 1];
    char geoip_msg_dst[OS_SIZE_1024 + 1];
#endif

    MailMsg *mail;
    alert_data *al_data;

    Mail->priority = 0;

    /* Get message if available */
    al_data = Read_FileMon(fileq, p, mail_timeout);
    if (!al_data) {
        return (NULL);
    }

    /* If e-mail came correctly, generate the e-mail body/subject */
    os_calloc(1, sizeof(MailMsg), mail);
    os_calloc(BODY_SIZE, sizeof(char), mail->body);
    os_calloc(SUBJECT_SIZE, sizeof(char), mail->subject);

    /* Generate the logs */
    logs[0] = '\0';
    extra_data[0] = '\0';
    logs[OS_MAXSTR] = '\0';

    while (al_data->log[i]) {
        log_size = strlen(al_data->log[i]) + 4;

        /* If size left is small than the size of the log, stop it */
        if (body_size <= log_size) {
            break;
        }

        strncat(logs, al_data->log[i], body_size);
        strncat(logs, "\r\n", body_size);
        body_size -= log_size;
        i++;
    }

    if (al_data->old_md5) {
        log_size = strlen(al_data->old_md5) + 16 + 4;
        if (body_size > log_size) {
            strncat(logs, "Old md5sum was: ", 16);
            strncat(logs, al_data->old_md5, body_size);
            strncat(logs, "\r\n", 4);
            body_size -= log_size;
        }
    }
    if (al_data->new_md5) {
        log_size = strlen(al_data->new_md5) + 16 + 4;
        if (body_size > log_size) {
            strncat(logs, "New md5sum is : ", 16);
            strncat(logs, al_data->new_md5, body_size);
            strncat(logs, "\r\n", 4);
            body_size -= log_size;
        }
    }
    if (al_data->old_sha1) {
        log_size = strlen(al_data->old_sha1) + 17 + 4;
        if (body_size > log_size) {
            strncat(logs, "Old sha1sum was: ", 17);
            strncat(logs, al_data->old_sha1, body_size);
            strncat(logs, "\r\n", 4);
            body_size -= log_size;
        }
    }
    if (al_data->new_sha1) {
        log_size = strlen(al_data->new_sha1) + 17 + 4;
        if (body_size > log_size) {
            strncat(logs, "New sha1sum is : ", 17);
            strncat(logs, al_data->new_sha1, body_size);
            strncat(logs, "\r\n", 4);
            body_size -= log_size;
        }
    }

    /* EXTRA DATA */
    if (al_data->srcip) {
        log_size = snprintf(log_string, sizeof(log_string) - 1, "Src IP: %s\r\n", al_data->srcip );
        if (body_size > log_size) {
            if ( strncat(extra_data, log_string, log_size) != NULL ) {
                body_size -= log_size;
            }
        }
    }
    if (al_data->dstip) {
        log_size = snprintf(log_string, sizeof(log_string) - 1, "Dst IP: %s\r\n", al_data->dstip );
        if (body_size > log_size) {
            if ( strncat(extra_data, log_string, log_size) != NULL ) {
                body_size -= log_size;
            }
        }
    }
    if (al_data->user) {
        log_size = snprintf(log_string, sizeof(log_string) - 1, "User: %s\r\n", al_data->user );
        if (body_size > log_size) {
            if ( strncat(extra_data, log_string, log_size) != NULL ) {
                body_size -= log_size;
            }
        }
    }

    /* Subject */
    subject_host = strchr(al_data->location, '>');
    if (subject_host) {
        subject_host--;
        *subject_host = '\0';
    }

    /* We have two subject options - full and normal */
    if (Mail->subject_full) {
        /* Option for a clean full subject (without ossec in the name) */
#ifdef CLEANFULL
        snprintf(mail->subject, SUBJECT_SIZE - 1, MAIL_SUBJECT_FULL2,
                 al_data->level,
                 al_data->comment,
                 al_data->location);
#else
        snprintf(mail->subject, SUBJECT_SIZE - 1, MAIL_SUBJECT_FULL,
                 al_data->location,
                 al_data->level,
                 al_data->comment);
#endif
    } else {
        snprintf(mail->subject, SUBJECT_SIZE - 1, MAIL_SUBJECT,
                 al_data->location,
                 al_data->level);
    }


    /* Fix subject back */
    if (subject_host) {
        *subject_host = '-';
    }

#ifdef LIBGEOIP_ENABLED
    /* Get GeoIP information */
    if (Mail->geoip) {
        if (al_data->geoipdatasrc) {
            snprintf(geoip_msg_src, OS_SIZE_1024, "Src Location: %s\r\n", al_data->geoipdatasrc);
        } else {
            geoip_msg_src[0] = '\0';
        }
        if (al_data->geoipdatadst) {
            snprintf(geoip_msg_dst, OS_SIZE_1024, "Dst Location: %s\r\n", al_data->geoipdatadst);
        } else {
            geoip_msg_dst[0] = '\0';
        }
    } else {
        geoip_msg_src[0] = '\0';
        geoip_msg_dst[0] = '\0';
    }
#endif

    /* Body */
#ifdef LIBGEOIP_ENABLED
    snprintf(mail->body, BODY_SIZE - 1, MAIL_BODY,
             al_data->date,
             al_data->location,
             al_data->rule,
             al_data->level,
             al_data->comment,
             geoip_msg_src,
             geoip_msg_dst,
             extra_data,
             logs);
#else
    snprintf(mail->body, BODY_SIZE - 1, MAIL_BODY,
             al_data->date,
             al_data->location,
             al_data->rule,
             al_data->level,
             al_data->comment,
             extra_data,
             logs);
#endif
    debug2("OS_RecvMailQ: mail->body[%s]", mail->body);

    /* Check for granular email configs */
    if (Mail->gran_to) {
        i = 0;
        while (Mail->gran_to[i] != NULL) {
            int gr_set = 0;

            /* Look if location is set */
            if (Mail->gran_location[i]) {
                if (OSMatch_Execute(al_data->location,
                                    strlen(al_data->location),
                                    Mail->gran_location[i])) {
                    gr_set = 1;
                } else {
                    i++;
                    continue;
                }
            }

            /* Look for the level */
            if (Mail->gran_level[i]) {
                if (al_data->level >= Mail->gran_level[i]) {
                    gr_set = 1;
                } else {
                    i++;
                    continue;
                }
            }

            /* Look for rule id */
            if (Mail->gran_id[i]) {
                int id_i = 0;
                while (Mail->gran_id[i][id_i] != 0) {
                    if (Mail->gran_id[i][id_i] == al_data->rule) {
                        break;
                    }
                    id_i++;
                }

                /* If we found, id is going to be a valid rule */
                if (Mail->gran_id[i][id_i]) {
                    gr_set = 1;
                } else {
                    i++;
                    continue;
                }
            }

            /* Look for the group */
            if (Mail->gran_group[i]) {
                if (OSMatch_Execute(al_data->group,
                                    strlen(al_data->group),
                                    Mail->gran_group[i])) {
                    gr_set = 1;
                } else {
                    i++;
                    continue;
                }
            }

            /* If we got here, everything matched. Set this e-mail to be used. */
            if (gr_set) {
                if (Mail->gran_format[i] == SMS_FORMAT) {
                    Mail->gran_set[i] = SMS_FORMAT;

                    /* Set the SMS flag */
                    sms_set = 1;
                } else {
                    /* Options */
                    if (Mail->gran_format[i] == FORWARD_NOW) {
                        Mail->priority = 1;
                        Mail->gran_set[i] = FULL_FORMAT;
                    } else if (Mail->gran_format[i] == DONOTGROUP) {
                        Mail->priority = DONOTGROUP;
                        Mail->gran_set[i] = DONOTGROUP;
                        donotgroup = 1;
                    } else {
                        Mail->gran_set[i] = FULL_FORMAT;
                    }
                }
            }
            i++;
        }
    }


    /* If DONOTGROUP is set, we can't assign the new subject */
    if (!donotgroup) {
        /* Get highest level for alert */
        if (_g_subject[0] != '\0') {
            if (_g_subject_level < al_data->level) {
                strncpy(_g_subject, mail->subject, SUBJECT_SIZE);
                _g_subject_level = al_data->level;
            }
        } else {
            strncpy(_g_subject, mail->subject, SUBJECT_SIZE);
            _g_subject_level = al_data->level;
        }
    }

    /* If SMS is set, create the SMS output */
    if (sms_set) {
        MailMsg *msg_sms_tmp;

        /* Allocate memory for SMS */
        os_calloc(1, sizeof(MailMsg), msg_sms_tmp);
        os_calloc(BODY_SIZE, sizeof(char), msg_sms_tmp->body);
        os_calloc(SUBJECT_SIZE, sizeof(char), msg_sms_tmp->subject);

        snprintf(msg_sms_tmp->subject, SUBJECT_SIZE - 1, SMS_SUBJECT,
                 al_data->level,
                 al_data->rule,
                 al_data->comment);


        strncpy(msg_sms_tmp->body, logs, 128);
        msg_sms_tmp->body[127] = '\0';
        *msg_sms = msg_sms_tmp;
    }

    /* Clear the memory */
    FreeAlertData(al_data);

    return (mail);
}

