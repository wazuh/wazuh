/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "log.h"
#include "syscheck_op.h"
#include "alerts.h"
#include "getloglocation.h"
#include "rules.h"
#include "eventinfo.h"
#include "config.h"

/* Drop/allow patterns */
static OSMatch FWDROPpm;
static OSMatch FWALLOWpm;

/* Allow custom alert output tokens */
typedef enum e_custom_alert_tokens_id {
    CUSTOM_ALERT_TOKEN_TIMESTAMP = 0,
    CUSTOM_ALERT_TOKEN_FTELL,
    CUSTOM_ALERT_TOKEN_RULE_ALERT_OPTIONS,
    CUSTOM_ALERT_TOKEN_HOSTNAME,
    CUSTOM_ALERT_TOKEN_LOCATION,
    CUSTOM_ALERT_TOKEN_RULE_ID,
    CUSTOM_ALERT_TOKEN_RULE_LEVEL,
    CUSTOM_ALERT_TOKEN_RULE_COMMENT,
    CUSTOM_ALERT_TOKEN_SRC_IP,
    CUSTOM_ALERT_TOKEN_DST_USER,
    CUSTOM_ALERT_TOKEN_FULL_LOG,
    CUSTOM_ALERT_TOKEN_RULE_GROUP,
    CUSTOM_ALERT_TOKEN_LAST
} CustomAlertTokenID;

static const char CustomAlertTokenName[CUSTOM_ALERT_TOKEN_LAST][15] = {
    { "$TIMESTAMP" },
    { "$FTELL" },
    { "$RULEALERT" },
    { "$HOSTNAME" },
    { "$LOCATION" },
    { "$RULEID" },
    { "$RULELEVEL" },
    { "$RULECOMMENT" },
    { "$SRCIP" },
    { "$DSTUSER" },
    { "$FULLLOG" },
    { "$RULEGROUP" },
};

static void format_labels(char *buffer, size_t size, const Eventinfo *lf) {
    int i;
    size_t z = 0;

    for (i = 0; lf->labels[i].key != NULL; i++) {
        if (!lf->labels[i].flags.hidden || Config.show_hidden_labels) {
            z += (size_t)snprintf(buffer + z, size - z, "%s: %s\n",
                lf->labels[i].key,
                lf->labels[i].value);

            if (z >= size) {
                buffer[0] = '\0';
                return;
            }
        }
    }
}

/* Store the events in a file
 * The string must be null terminated and contain
 * any necessary new lines, tabs, etc.
 */
void OS_Store(const Eventinfo *lf)
{
    if (strcmp(lf->location, "ossec-keepalive") == 0) {
        return;
    }
    if (strstr(lf->location, "->ossec-keepalive") != NULL) {
        return;
    }

    fprintf(_eflog,
            "%d %s %02d %s %s%s%s %s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->location[0] != '(' ? lf->hostname : "",
            lf->location[0] != '(' ? "->" : "",
            lf->location,
            lf->full_log);

    return;
}

void OS_Store_Flush(){
    fflush(_eflog);
}

void OS_LogOutput(Eventinfo *lf)
{
    int i;
    char labels[OS_MAXSTR];

#ifdef LIBGEOIP_ENABLED
    if (Config.geoipdb_file) {
        if (lf->srcip && !lf->srcgeoip) {
            lf->srcgeoip = GetGeoInfobyIP(lf->srcip);
        }
        if (lf->dstip && !lf->dstgeoip) {
            lf->dstgeoip = GetGeoInfobyIP(lf->dstip);
        }
    }
#endif

    if (lf->labels && lf->labels[0].key) {
        format_labels(labels, OS_MAXSTR, lf);
    } else {
        labels[0] = '\0';
    }

    printf(
        "** Alert %ld.%ld:%s - %s\n"
        "%d %s %02d %s %s%s%s\n%sRule: %d (level %d) -> '%s'"
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
        (long int)lf->time.tv_sec,
        __crt_ftell,
        lf->generated_rule->alert_opts & DO_MAILALERT ? " mail " : "",
        lf->generated_rule->group,
        lf->year,
        lf->mon,
        lf->day,
        lf->hour,
        lf->location[0] != '(' ? lf->hostname : "",
        lf->location[0] != '(' ? "->" : "",
        lf->location,
        labels,
        lf->generated_rule->sigid,
        lf->generated_rule->level,
        lf->comment,

        lf->srcip == NULL ? "" : "\nSrc IP: ",
        lf->srcip == NULL ? "" : lf->srcip,

#ifdef LIBGEOIP_ENABLED
        lf->srcgeoip == NULL ? "" : "\nSrc Location: ",
        lf->srcgeoip == NULL ? "" : lf->srcgeoip,
#else
        "",
        "",
#endif



        lf->srcport == NULL ? "" : "\nSrc Port: ",
        lf->srcport == NULL ? "" : lf->srcport,

        lf->dstip == NULL ? "" : "\nDst IP: ",
        lf->dstip == NULL ? "" : lf->dstip,

#ifdef LIBGEOIP_ENABLED
        lf->dstgeoip == NULL ? "" : "\nDst Location: ",
        lf->dstgeoip == NULL ? "" : lf->dstgeoip,
#else
        "",
        "",
#endif



        lf->dstport == NULL ? "" : "\nDst Port: ",
        lf->dstport == NULL ? "" : lf->dstport,

        lf->dstuser == NULL ? "" : "\nUser: ",
        lf->dstuser == NULL ? "" : lf->dstuser,

        lf->generated_rule->alert_opts & NO_FULL_LOG ? "" : "\n",
        lf->generated_rule->alert_opts & NO_FULL_LOG ? "" : lf->full_log);

    /* FIM events */

    if (lf->filename && lf->event_type != FIM_DELETED) {
        printf("Attributes:\n");

        if (lf->size_after && *lf->size_after != '\0'){
            printf(" - Size: %s\n", lf->size_after);
        }

        if (lf->mtime_after) {
            printf(" - Date: %s", ctime(&lf->mtime_after));
        }

        if (lf->inode_after) {
            printf(" - Inode: %ld\n", lf->inode_after);
        }

        if (lf->owner_after && lf->uname_after) {
            if (strcmp(lf->uname_after, "") != 0) {
                printf(" - User: %s (%s)\n", lf->uname_after, lf->owner_after);
            }
        }

        if (lf->gowner_after && lf->gname_after) {
            if (strcmp(lf->gname_after, "") != 0) {
                printf(" - Group: %s (%s)\n", lf->gname_after, lf->gowner_after);
            }
        }

        if (lf->md5_after) {
            if (strcmp(lf->md5_after, "xxx") != 0 && strcmp(lf->md5_after, "") != 0) {
                printf(" - MD5: %s\n", lf->md5_after);
            }
        }

        if (lf->sha1_after) {
            if (strcmp(lf->sha1_after, "xxx") != 0 && strcmp(lf->sha1_after, "") != 0) {
                printf(" - SHA1: %s\n", lf->sha1_after);
            }
        }

        if (lf->sha256_after) {
            if (strcmp(lf->sha256_after, "xxx") != 0 && strcmp(lf->sha256_after, "") != 0) {
                printf(" - SHA256: %s\n", lf->sha256_after);
            }
        }

        if (lf->attrs_after != 0) {
            char *attributes_list;
            os_calloc(OS_SIZE_256 + 1, sizeof(char), attributes_list);
            decode_win_attributes(attributes_list, lf->attrs_after);
            printf(" - File attributes: %s\n", attributes_list);
            free(attributes_list);
        }

        if (lf->perm_after){
            printf(" - Permissions: %6o\n", lf->perm_after);
        } else if (lf->win_perm_after && *lf->win_perm_after != '\0') {
            char *permissions_list;
            int size;
            os_calloc(OS_SIZE_20480 + 1, sizeof(char), permissions_list);
            if (size = decode_win_permissions(permissions_list, OS_SIZE_20480, lf->win_perm_after, 0, NULL), size > 1) {
                os_realloc(permissions_list, size + 1, permissions_list);
                printf(" - Permissions: \n%s", permissions_list);
                free(permissions_list);
            }
        }
    }

    if (lf->filename && lf->sk_tag) {
        if (strcmp(lf->sk_tag, "") != 0) {
            printf("\nTags:\n");
            char * tag;
            tag = strtok(lf->sk_tag, ",");
            while (tag != NULL) {
                printf(" - %s\n", tag);
                tag = strtok(NULL, ",");
            }
        }
    }

    // Dynamic fields, except for syscheck events
    if (lf->fields && !lf->filename) {
        for (i = 0; i < lf->nfields; i++) {
            if (lf->fields[i].value && *lf->fields[i].value) {
                printf("%s: %s\n", lf->fields[i].key, lf->fields[i].value);
            }
        }
    }

    /* Print the last events if present */
    if (lf->last_events) {
        char **lasts = lf->last_events;
        while (*lasts) {
            printf("%s\n", *lasts);
            lasts++;
        }
    }

    printf("\n");


    fflush(stdout);
    return;
}

void OS_Log(Eventinfo *lf)
{
    int i;
    char labels[OS_MAXSTR];

#ifdef LIBGEOIP_ENABLED
    if (Config.geoipdb_file) {
        if (lf->srcip && !lf->srcgeoip) {
            lf->srcgeoip = GetGeoInfobyIP(lf->srcip);
        }
        if (lf->dstip && !lf->dstgeoip) {
            lf->dstgeoip = GetGeoInfobyIP(lf->dstip);
        }
    }
#endif

    if (lf->labels && lf->labels[0].key) {
        format_labels(labels, OS_MAXSTR, lf);
    } else {
        labels[0] = '\0';
    }

    /* Writing to the alert log file */
    fprintf(_aflog,
            "** Alert %ld.%ld:%s - %s\n"
            "%d %s %02d %s %s%s%s\n%sRule: %d (level %d) -> '%s'"
            "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
            (long int)lf->time.tv_sec,
            __crt_ftell,
            lf->generated_rule->alert_opts & DO_MAILALERT ? " mail " : "",
            lf->generated_rule->group,
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->location[0] != '(' ? lf->hostname : "",
            lf->location[0] != '(' ? "->" : "",
            lf->location,
            labels,
            lf->generated_rule->sigid,
            lf->generated_rule->level,
            lf->comment,

            lf->srcip == NULL ? "" : "\nSrc IP: ",
            lf->srcip == NULL ? "" : lf->srcip,

#ifdef LIBGEOIP_ENABLED
            lf->srcgeoip == NULL ? "" : "\nSrc Location: ",
            lf->srcgeoip == NULL ? "" : lf->srcgeoip,
#else
            "",
            "",
#endif


            lf->srcport == NULL ? "" : "\nSrc Port: ",
            lf->srcport == NULL ? "" : lf->srcport,

            lf->dstip == NULL ? "" : "\nDst IP: ",
            lf->dstip == NULL ? "" : lf->dstip,

#ifdef LIBGEOIP_ENABLED
            lf->dstgeoip == NULL ? "" : "\nDst Location: ",
            lf->dstgeoip == NULL ? "" : lf->dstgeoip,
#else
            "",
            "",
#endif



            lf->dstport == NULL ? "" : "\nDst Port: ",
            lf->dstport == NULL ? "" : lf->dstport,

            lf->dstuser == NULL ? "" : "\nUser: ",
            lf->dstuser == NULL ? "" : lf->dstuser,
            "\n",
            lf->full_log);

    /* FIM events */

    if (lf->filename && lf->event_type != FIM_DELETED) {
        fprintf(_aflog, "Attributes:\n");

        if (lf->size_after && *lf->size_after != '\0'){
            fprintf(_aflog, " - Size: %s\n", lf->size_after);
        }

        if (lf->mtime_after) {
            fprintf(_aflog, " - Date: %s", ctime(&lf->mtime_after));
        }
        if (lf->inode_after) {
            fprintf(_aflog, " - Inode: %ld\n", lf->inode_after);
        }
        if (lf->owner_after && lf->uname_after) {
            if (strcmp(lf->uname_after, "") != 0) {
                fprintf(_aflog, " - User: %s (%s)\n", lf->uname_after, lf->owner_after);
            }
        }
        if (lf->gowner_after && lf->gname_after) {
            if (strcmp(lf->gname_after, "") != 0) {
                fprintf(_aflog, " - Group: %s (%s)\n", lf->gname_after, lf->gowner_after);
            }
        }
        if (lf->md5_after) {
            if (strcmp(lf->md5_after, "xxx") != 0 && strcmp(lf->md5_after, "") != 0) {
                fprintf(_aflog, " - MD5: %s\n", lf->md5_after);
            }
        }

        if (lf->sha1_after) {
            if (strcmp(lf->sha1_after, "xxx") != 0 && strcmp(lf->sha1_after, "") != 0) {
                fprintf(_aflog, " - SHA1: %s\n", lf->sha1_after);
            }
        }

        if (lf->sha256_after) {
            if (strcmp(lf->sha256_after, "xxx") != 0 && strcmp(lf->sha256_after, "") != 0) {
                fprintf(_aflog, " - SHA256: %s\n", lf->sha256_after);
            }
        }

        if (lf->attrs_after != 0) {
            char *attributes_list;
            os_calloc(OS_SIZE_256 + 1, sizeof(char), attributes_list);
            decode_win_attributes(attributes_list, lf->attrs_after);
            fprintf(_aflog, " - File attributes: %s\n", attributes_list);
            free(attributes_list);
        }

        if (lf->perm_after) {
            fprintf(_aflog, " - Permissions: %6o\n", lf->perm_after);
        } else if (lf->win_perm_after && *lf->win_perm_after != '\0') {
            char *permissions_list;
            int size;
            os_calloc(OS_SIZE_20480 + 1, sizeof(char), permissions_list);
            if (size = decode_win_permissions(permissions_list, OS_SIZE_20480, lf->win_perm_after, 0, NULL), size > 1) {
                os_realloc(permissions_list, size + 1, permissions_list);
                fprintf(_aflog, " - Permissions: \n%s", permissions_list);
                free(permissions_list);
            }
        }
    }

    if (lf->filename && lf->sk_tag) {
        if (strcmp(lf->sk_tag, "") != 0) {
            char * tags;
            os_strdup(lf->sk_tag, tags);
            fprintf(_aflog, "\nTags:\n");
            char * tag;
            tag = strtok(tags, ",");
            while (tag != NULL) {
                fprintf(_aflog, " - %s\n", tag);
                tag = strtok(NULL, ",");
            }
            free(tags);
        }
    }

    // Dynamic fields, except for syscheck events
    if (lf->fields && !lf->filename) {
        for (i = 0; i < lf->nfields; i++) {
            if (lf->fields[i].value && *lf->fields[i].value) {
                fprintf(_aflog, "%s: %s\n", lf->fields[i].key, lf->fields[i].value);
            }
        }
    }

    /* Print the last events if present */
    if (lf->last_events) {
        char **lasts = lf->last_events;
        while (*lasts) {
            fprintf(_aflog, "%s\n", *lasts);
            lasts++;
        }
    }

    fprintf(_aflog, "\n");

    return;
}

void OS_Log_Flush(){
    fflush(_aflog);
}

void OS_CustomLog(const Eventinfo *lf, const char *format)
{
    char *log;
    char *tmp_log;
    char tmp_buffer[1024];

    /* Replace all the tokens */
    os_strdup(format, log);

    snprintf(tmp_buffer, 1024, "%ld", (long int)lf->time.tv_sec);
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_TIMESTAMP], tmp_buffer);
    free(log);

    snprintf(tmp_buffer, 1024, "%ld", __crt_ftell);
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_FTELL], tmp_buffer);
    free(tmp_log);

    snprintf(tmp_buffer, 1024, "%s", (lf->generated_rule->alert_opts & DO_MAILALERT) ? "mail " : "");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_ALERT_OPTIONS], tmp_buffer);
    free(log);

    snprintf(tmp_buffer, 1024, "%s", lf->hostname ? lf->hostname : "None");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_HOSTNAME], tmp_buffer);
    free(tmp_log);

    snprintf(tmp_buffer, 1024, "%s", lf->location ? lf->location : "None");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_LOCATION], tmp_buffer);
    free(log);

    snprintf(tmp_buffer, 1024, "%d", lf->generated_rule->sigid);
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_ID], tmp_buffer);
    free(tmp_log);

    snprintf(tmp_buffer, 1024, "%d", lf->generated_rule->level);
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_LEVEL], tmp_buffer);
    free(log);

    snprintf(tmp_buffer, 1024, "%s", lf->srcip ? lf->srcip : "None");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_SRC_IP], tmp_buffer);
    free(tmp_log);

    snprintf(tmp_buffer, 1024, "%s", lf->dstuser ? lf->dstuser : "None");

    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_DST_USER], tmp_buffer);
    free(log);

    char *escaped_log;
    escaped_log = escape_newlines(lf->full_log);

    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_FULL_LOG], escaped_log );
    free(tmp_log);
    free(escaped_log);

    snprintf(tmp_buffer, 1024, "%s", lf->comment ? lf->comment : "");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_COMMENT], tmp_buffer);
    free(log);

    snprintf(tmp_buffer, 1024, "%s", lf->generated_rule->group ? lf->generated_rule->group : "");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_GROUP], tmp_buffer);
    free(tmp_log);

    fprintf(_aflog, "%s", log);
    fprintf(_aflog, "\n");

    free(log);

    return;
}

void OS_CustomLog_Flush(){
    fflush(_aflog);
}

void OS_InitFwLog()
{
    /* Initialize fw log regexes */
    if (!OSMatch_Compile(FWDROP, &FWDROPpm, 0)) {
        merror_exit(REGEX_COMPILE, FWDROP,
                  FWDROPpm.error);
    }

    if (!OSMatch_Compile(FWALLOW, &FWALLOWpm, 0)) {
        merror_exit(REGEX_COMPILE, FWALLOW,
                  FWALLOWpm.error);
    }
}

int FW_Log(Eventinfo *lf)
{
    /* Set the actions */
    switch (*lf->action) {
        /* discard, drop, deny, */
        case 'd':
        case 'D':
        /* reject, */
        case 'r':
        case 'R':
        /* block */
        case 'b':
        case 'B':
            os_free(lf->action);
            os_strdup("DROP", lf->action);
            break;
        /* Closed */
        case 'c':
        case 'C':
        /* Teardown */
        case 't':
        case 'T':
            os_free(lf->action);
            os_strdup("CLOSED", lf->action);
            break;
        /* allow, accept, */
        case 'a':
        case 'A':
        /* pass/permitted */
        case 'p':
        case 'P':
        /* open */
        case 'o':
        case 'O':
            os_free(lf->action);
            os_strdup("ALLOW", lf->action);
            break;
        default:
            if (OSMatch_Execute(lf->action, strlen(lf->action), &FWDROPpm)) {
                os_free(lf->action);
                os_strdup("DROP", lf->action);
            }
            if (OSMatch_Execute(lf->action, strlen(lf->action), &FWALLOWpm)) {
                os_free(lf->action);
                os_strdup("ALLOW", lf->action);
            } else {
                os_free(lf->action);
                os_strdup("UNKNOWN", lf->action);
            }
            break;
    }

    /* Log to file */
    fprintf(_fflog,
            "%d %s %02d %s %s%s%s %s %s %s:%s->%s:%s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->location[0] != '(' ? lf->hostname : "",
            lf->location[0] != '(' ? "->" : "",
            lf->location,
            lf->action,
            lf->protocol,
            lf->srcip,
            lf->srcport,
            lf->dstip,
            lf->dstport);

    fflush(_fflog);

    return (1);
}
