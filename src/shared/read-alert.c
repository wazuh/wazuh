/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* File monitoring functions */

#include "shared.h"
#include "read-alert.h"

/* ** Alert xyz: email active-response ** */

#define ALERT_BEGIN     "** Alert"
#define ALERT_BEGIN_SZ  8
#define RULE_BEGIN      "Rule: "
#define RULE_BEGIN_SZ   6
#define SRCIP_BEGIN     "Src IP: "
#define SRCIP_BEGIN_SZ  8
#define SRCPORT_BEGIN     "Src Port: "
#define SRCPORT_BEGIN_SZ  10
#define DSTIP_BEGIN     "Dst IP: "
#define DSTIP_BEGIN_SZ  8
#define DSTPORT_BEGIN     "Dst Port: "
#define DSTPORT_BEGIN_SZ  10
#define USER_BEGIN      "User: "
#define USER_BEGIN_SZ   6
#define ALERT_MAIL      "mail"
#define ALERT_MAIL_SZ   4
#define OLDMD5_BEGIN      "Old md5sum was: "
#define OLDMD5_BEGIN_SZ   16
#define NEWMD5_BEGIN      "New md5sum is : "
#define NEWMD5_BEGIN_SZ   16
#define OLDSHA1_BEGIN     "Old sha1sum was: "
#define OLDSHA1_BEGIN_SZ  17
#define NEWSHA1_BEGIN     "New sha1sum is : "
#define NEWSHA1_BEGIN_SZ  17
#define OLDSHA256_BEGIN     "Old sha256sum was: "
#define OLDSHA256_BEGIN_SZ  19
#define NEWSHA256_BEGIN     "New sha256sum is : "
#define NEWSHA256_BEGIN_SZ  19
/* "9/19/2016 - Sivakumar Nellurandi - parsing additions" */
#define SIZE_BEGIN        "Size changed from "
#define SIZE_BEGIN_SZ     18
#define OWNER_BEGIN        "Ownership was "
#define OWNER_BEGIN_SZ     14
#define GROUP_BEGIN        "Group ownership was "
#define GROUP_BEGIN_SZ     20
#define PERM_BEGIN        "Permissions changed from "
#define PERM_BEGIN_SZ     25

#define LOG_LIMIT      100
/* "9/19/2016 - Sivakumar Nellurandi - parsing additions" */


void FreeAlertData(alert_data *al_data) {
    char **p;
    os_free(al_data->alertid);
    os_free(al_data->date);
    os_free(al_data->location);
    os_free(al_data->comment);
    os_free(al_data->group);
    os_free(al_data->srcip);
    os_free(al_data->dstip);
    os_free(al_data->user);
    os_free(al_data->filename);
    os_free(al_data->old_md5);
    os_free(al_data->new_md5);
    os_free(al_data->old_sha1);
    os_free(al_data->new_sha1);
    os_free(al_data->old_sha256);
    os_free(al_data->new_sha256);
    os_free(al_data->file_size);
    os_free(al_data->owner_chg);
    os_free(al_data->group_chg);
    os_free(al_data->perm_chg);

/* "9/19/2016 - Sivakumar Nellurandi - parsing additions" */
    if (al_data->log) {
        p = al_data->log;

        while (*(p)) {
            os_free(*(p));
            p++;
        }
        os_free(al_data->log);
    }

    // al_data can't be NULL
    free(al_data);
    al_data = NULL;
}

/* Return alert data for the file specified */
alert_data *GetAlertData(int flag, FILE *fp) {

    alert_data *al_data;
    os_calloc(1, sizeof(alert_data), al_data);

    int _r = 0, issyscheck = 0;
    size_t log_size = 0;
    char *p;
    char str[OS_MAXSTR + 1];
    str[OS_MAXSTR] = '\0';

    while (fgets(str, OS_MAXSTR, fp) != NULL) {
        /* End of alert */
        if (strncmp(ALERT_BEGIN, str, ALERT_BEGIN_SZ) == 0) {
            char *m;
            size_t z = 0;
            /* End of the alert. */
            if (_r == 2) {
                if (fseek(fp, -strlen(str), SEEK_CUR) != -1) {
                    return (al_data);
                } else {
                    goto l_error;
                }
            }

            p = str + ALERT_BEGIN_SZ + 1;

            m = strstr(p, ":");
            if (!m) {
                continue;
            }

            z = strlen(p) - strlen(m);
            os_realloc(al_data->alertid, (z + 1) * sizeof(char), al_data->alertid);
            strncpy(al_data->alertid, p, z);
            al_data->alertid[z] = '\0';

            /* Search for email flag */
            p = strchr(p, ' ');
            if (!p) {
                continue;
            }

            p++;

            /* Check for the flags */
            if ((flag & CRALERT_MAIL_SET) &&
                    (strncmp(ALERT_MAIL, p, ALERT_MAIL_SZ) != 0)) {
                continue;
            }

            p = strchr(p, '-');
            if (p) {
                p++;
                /* Skip leading spaces */
                while (*p == ' ') {
                        p++;
                }
                os_free(al_data->group);
                os_strdup(p, al_data->group);

                /* Clean newline from group */
                os_clearnl(al_data->group, p);
                if (al_data->group != NULL && strstr(al_data->group, "syscheck") != NULL) {
                    issyscheck = 1;
                }
            }

            /* Search for active-response flag */
            _r = 1;
            continue;
        }

        if (_r < 1) {
            continue;
        }

        /*** Extract information from the event ***/

        /* r1 means: 2006 Apr 13 16:15:17 /var/log/auth.log */
        if (_r == 1) {
            /* Clear newline */
            os_clearnl(str, p);

            p = strchr(str, ':');
            if (p) {
                p = strchr(p, ' ');
                if (p) {
                    *p = '\0';
                    p++;
                } else {
                    /* If p is null it is because strchr failed */
                    merror("date or location not NULL");
                    goto l_error;
                }
            }

            /* If not, str is date and p is the location */
            if (al_data->date || al_data->location || !p) {
                merror("date or location not NULL or p is NULL");
                goto l_error;
            }

            os_strdup(str, al_data->date);
            os_strdup(p, al_data->location);
            _r = 2;
            log_size = 0;
            continue;
        } else if (_r == 2) {
            /* Rule begin */
            if (strncmp(RULE_BEGIN, str, RULE_BEGIN_SZ) == 0) {
                os_clearnl(str, p);

                p = str + RULE_BEGIN_SZ;
                al_data->rule = atoi(p);

                p = strchr(p, ' ');
                if (p) {
                    p++;
                    p = strchr(p, ' ');
                    if (p) {
                        p++;
                    }
                }

                if (!p) {
                    goto l_error;
                }

                al_data->level = atoi(p);

                /* Get the comment */
                p = strchr(p, '\'');
                if (!p) {
                    goto l_error;
                }

                p++;
                os_free(al_data->comment);
                os_strdup(p, al_data->comment);

                /* Must have the closing \' */
                p = strrchr(al_data->comment, '\'');
                if (p) {
                    *p = '\0';
                } else {
                    goto l_error;
                }
            }

            /* srcip */
            else if (strncmp(SRCIP_BEGIN, str, SRCIP_BEGIN_SZ) == 0) {
                os_clearnl(str, p);

                p = str + SRCIP_BEGIN_SZ;
                os_free(al_data->srcip);
                os_strdup(p,al_data->srcip);
            }
            /* srcport */
            else if (strncmp(SRCPORT_BEGIN, str, SRCPORT_BEGIN_SZ) == 0) {
                os_clearnl(str, p);

                p = str + SRCPORT_BEGIN_SZ;
                al_data->srcport = atoi(p);
            }
            /* dstip */
            else if (strncmp(DSTIP_BEGIN, str, DSTIP_BEGIN_SZ) == 0) {
                os_clearnl(str, p);

                p = str + DSTIP_BEGIN_SZ;
                os_free(al_data->dstip);
                os_strdup(p, al_data->dstip);
            }
            /* dstport */
            else if (strncmp(DSTPORT_BEGIN, str, DSTPORT_BEGIN_SZ) == 0) {
                os_clearnl(str, p);

                p = str + DSTPORT_BEGIN_SZ;
                al_data->dstport = atoi(p);
            }
            /* username */
            else if (strncmp(USER_BEGIN, str, USER_BEGIN_SZ) == 0) {
                os_clearnl(str, p);

                p = str + USER_BEGIN_SZ;
                os_free(al_data->user);
                os_strdup(p, al_data->user);
            }

         /* "9/19/2016 - Sivakumar Nellurandi - parsing additions" */
            /* It is a log message */
            else if (log_size < LOG_LIMIT) {
                os_clearnl(str, p);
                if (issyscheck == 1) {
                    if (strncmp(str, "Integrity checksum changed for: '", 33) == 0) {
                        al_data->filename = strdup(str + 33);
                        if (al_data->filename) {
                            al_data->filename[strlen(al_data->filename) - 1] = '\0';
                        }
                    }
                    issyscheck = 0;
                }

                os_realloc(al_data->log, (log_size + 2) * sizeof(char *), al_data->log);
                os_strdup(str, al_data->log[log_size]);
                log_size++;
                al_data->log[log_size] = NULL;
            }
        }
    }

    // We reached the end of the alert and the information is saved.
    if (feof(fp) && *str == '\0' && _r == 2) {
        return al_data;
    }

l_error:
    /* Free the memory */
    FreeAlertData(al_data);
    /* We need to clean end of file before returning */
    clearerr(fp);
    return (NULL);
}
