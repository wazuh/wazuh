/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
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
        if (!lf->labels[i].flags.system && (!lf->labels[i].flags.hidden || Config.show_hidden_labels)) {
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

void OS_Log(Eventinfo *lf, FILE * fp)
{
    int i;
    char labels[OS_MAXSTR] = {0};
    char * saveptr;

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
    fprintf(fp,
            "** Alert %ld.%ld:%s - %s\n"
            "%d %s %02d %s %s%s%s\n%sRule: %d (level %d) -> '%s'"
            "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n",
            (long int)lf->time.tv_sec,
            get_global_alert_second_id(),
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

    if (lf->decoder_info->name != NULL && strncmp(lf->decoder_info->name, "syscheck_", 9) == 0) {
        fwrite("Attributes:\n", sizeof(char), 12, fp);

        if (lf->fields[FIM_SIZE].value && *lf->fields[FIM_SIZE].value != '\0') {
            fprintf(fp, " - Size: %s\n", lf->fields[FIM_SIZE].value);
        }

        if (lf->fields[FIM_PERM].value && *lf->fields[FIM_PERM].value != '\0') {
            fprintf(fp, " - Permissions: %s\n", lf->fields[FIM_PERM].value);
        }

        if (lf->fields[FIM_MTIME].value && *lf->fields[FIM_MTIME].value != '\0') {
            long aux_time = atol(lf->fields[FIM_MTIME].value);
            char buf_ptr[26];
            fprintf(fp, " - Date: %s", ctime_r(&aux_time, buf_ptr) != NULL ? buf_ptr : lf->fields[FIM_MTIME].value);
        }

        if (lf->fields[FIM_INODE].value && *lf->fields[FIM_INODE].value != '\0') {
            fprintf(fp, " - Inode: %s\n", lf->fields[FIM_INODE].value);
        }

        if (lf->fields[FIM_UID].value && lf->fields[FIM_UNAME].value && *lf->fields[FIM_UNAME].value != '\0') {
            fprintf(fp, " - User: %s (%s)\n", lf->fields[FIM_UNAME].value, lf->fields[FIM_UID].value);
        }

        if (lf->fields[FIM_GID].value && lf->fields[FIM_GNAME].value && *lf->fields[FIM_GNAME].value != '\0') {
            fprintf(fp, " - Group: %s (%s)\n", lf->fields[FIM_GNAME].value, lf->fields[FIM_GID].value);
        }

        if (lf->fields[FIM_MD5].value && strcmp(lf->fields[FIM_MD5].value, "xxx") && *lf->fields[FIM_MD5].value != '\0') {
            fprintf(fp, " - MD5: %s\n", lf->fields[FIM_MD5].value);
        }

        if (lf->fields[FIM_SHA1].value && strcmp(lf->fields[FIM_SHA1].value, "xxx") && *lf->fields[FIM_SHA1].value != '\0') {
            fprintf(fp, " - SHA1: %s\n", lf->fields[FIM_SHA1].value);
        }

        if (lf->fields[FIM_SHA256].value && strcmp(lf->fields[FIM_SHA256].value, "xxx") && *lf->fields[FIM_SHA256].value != '\0') {
            fprintf(fp, " - SHA256: %s\n", lf->fields[FIM_SHA256].value);
        }

        if (lf->fields[FIM_ATTRS].value && *lf->fields[FIM_ATTRS].value != '\0') {
            fprintf(fp, " - File attributes: %s\n", lf->fields[FIM_ATTRS].value);
        }

        if (lf->fields[FIM_USER_NAME].value && *lf->fields[FIM_USER_NAME].value != '\0') {
            fprintf(fp, " - (Audit) %s: %s\n", "User name", lf->fields[FIM_USER_NAME].value);
        }
        if (lf->fields[FIM_AUDIT_NAME].value && *lf->fields[FIM_AUDIT_NAME].value != '\0') {
            fprintf(fp, " - (Audit) %s: %s\n", "Audit name", lf->fields[FIM_AUDIT_NAME].value);
        }
        if (lf->fields[FIM_EFFECTIVE_NAME].value && *lf->fields[FIM_EFFECTIVE_NAME].value != '\0') {
            fprintf(fp, " - (Audit) %s: %s\n", "Effective name", lf->fields[FIM_EFFECTIVE_NAME].value);
        }
        if (lf->fields[FIM_GROUP_NAME].value && *lf->fields[FIM_GROUP_NAME].value != '\0') {
            fprintf(fp, " - (Audit) %s: %s\n", "Group name", lf->fields[FIM_GROUP_NAME].value);
        }
        if (lf->fields[FIM_PROC_ID].value && *lf->fields[FIM_PROC_ID].value != '\0') {
            fprintf(fp, " - (Audit) %s: %s\n", "Process id", lf->fields[FIM_PROC_ID].value);
        }
        if (lf->fields[FIM_PROC_NAME].value && *lf->fields[FIM_PROC_NAME].value != '\0') {
            fprintf(fp, " - (Audit) %s: %s\n", "Process name", lf->fields[FIM_PROC_NAME].value);
        }
        if (lf->fields[FIM_AUDIT_CWD].value && *lf->fields[FIM_AUDIT_CWD].value != '\0') {
            fprintf(fp, " - (Audit) %s: %s\n", "Process cwd", lf->fields[FIM_AUDIT_CWD].value);
        }
        if (lf->fields[FIM_PROC_PNAME].value && *lf->fields[FIM_PROC_PNAME].value != '\0') {
            fprintf(fp, " - (Audit) %s: %s\n", "Parent process name", lf->fields[FIM_PROC_PNAME].value);
        }
        if (lf->fields[FIM_PPID].value && *lf->fields[FIM_PPID].value != '\0') {
            fprintf(fp, " - (Audit) %s: %s\n", "Parent process id", lf->fields[FIM_PPID].value);
        }
        if (lf->fields[FIM_AUDIT_PCWD].value && *lf->fields[FIM_AUDIT_PCWD].value != '\0') {
            fprintf(fp, " - (Audit) %s: %s\n", "Parent process cwd", lf->fields[FIM_AUDIT_PCWD].value);
        }

        if (lf->fields[FIM_DIFF].value) {
            fprintf(fp, "\nWhat changed:\n%s\n", lf->fields[FIM_DIFF].value);
        }

        if (lf->fields[FIM_TAG].value && *lf->fields[FIM_TAG].value != '\0') {
            char * tags;
            os_strdup(lf->fields[FIM_TAG].value, tags);
            fwrite("\nTags:\n", sizeof(char), 7, fp);
            char * tag;
            tag = strtok_r(tags, ",", &saveptr);
            while (tag != NULL) {
                fprintf(fp, " - %s\n", tag);
                tag = strtok_r(NULL, ",", &saveptr);
            }
            free(tags);
        }
    }

    // Dynamic fields, except for syscheck events

    if (lf->decoder_info->name != NULL && strncmp(lf->decoder_info->name, "syscheck_", 9) != 0) {
        for (i = 0; i < lf->nfields; i++) {
            if (lf->fields[i].value != NULL && *lf->fields[i].value != '\0') {
                fprintf(fp, "%s: %s\n", lf->fields[i].key, lf->fields[i].value);
            }
        }
    }

    /* Print the last events if present */
    if (lf->last_events) {
        char **lasts = lf->last_events;
        while (*lasts) {
            fprintf(fp, "%s\n", *lasts);
            lasts++;
        }
    }

    fputc('\n', fp);

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

    snprintf(tmp_buffer, 1024, "%ld", get_global_alert_second_id());
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
