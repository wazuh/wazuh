/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "log.h"
#include "alerts.h"
#include "getloglocation.h"
#include "rules.h"
#include "eventinfo.h"
#include "config.h"

#ifdef LIBGEOIP_ENABLED
#include "GeoIP.h"
#include "GeoIPCity.h"

#define RFC1918_10     (167772160u  & 4278190080u)       /* 10/8        */
#define RFC1918_172    (2886729728u & 4293918720u)       /* 172.17/12   */
#define RFC1918_192    (3232235520u & 4294901760u)       /* 192.168/16  */
#define NETMASK_8      4278190080u                       /* 255.0.0.0   */
#define NETMASK_12     4293918720u                       /* 255.240.0.0 */
#define NETMASK_16     4294901760u                       /* 255.255.0.0 */

static const char *_mk_NA( const char *p )
{
    return (p ? p : "N/A");
}

/* Convert a dot-quad IP address into long format */
static unsigned long StrIP2Int(const char *ip)
{
    unsigned int c1, c2, c3, c4;
    /* IP address is not coming from user input -> We can trust it */
    /* Only minimal checking is performed */
    size_t len = strlen(ip);
    if ((len < 7) || (len > 15)) {
        return (0);
    }

    sscanf(ip, "%u.%u.%u.%u", &c1, &c2, &c3, &c4);
    return ((unsigned long)c4 + c3 * 256 + c2 * 256 * 256 + c1 * 256 * 256 * 256);
}

/* Use the GeoIP API to locate an IP address */
static void GeoIP_Lookup(const char *ip, char *buffer, const size_t length)
{
    GeoIP   *gi;
    GeoIPRecord *gir;

    /* Dumb way to detect an IPv6 address */
    if (strchr(ip, ':')) {
        /* Use the IPv6 DB */
        gi = GeoIP_open(Config.geoip_db_path, GEOIP_INDEX_CACHE);
        if (gi == NULL) {
            merror(INVALID_GEOIP_DB, ARGV0, Config.geoip6_db_path);
            snprintf(buffer, length, "Unknown (1)");
            return;
        }
        gir = GeoIP_record_by_name_v6(gi, ip);
    } else {
        /* Use the IPv4 DB */
        /* If we have a RFC1918 IP, do not perform a DB lookup (performance) */
        unsigned long longip = StrIP2Int(ip);
        if (longip == 0 ) {
            snprintf(buffer, length, "Unknown (2)");
            return;
        }
        if ((longip & NETMASK_8)  == RFC1918_10 ||
                (longip & NETMASK_12) == RFC1918_172 ||
                (longip & NETMASK_16) == RFC1918_192) {
            snprintf(buffer, length, "RFC1918 IP");
            return;
        }

        gi = GeoIP_open(Config.geoip_db_path, GEOIP_INDEX_CACHE);
        if (gi == NULL) {
            merror(INVALID_GEOIP_DB, ARGV0, Config.geoip_db_path);
            snprintf(buffer, length, "Unknown (3)");
            return;
        }
        gir = GeoIP_record_by_name(gi, ip);
    }
    if (gir != NULL) {
        snprintf(buffer, length, "%s,%s,%s",
                 _mk_NA(gir->country_code),
                 _mk_NA(GeoIP_region_name_by_code(gir->country_code, gir->region)),
                 _mk_NA(gir->city)
                );
        GeoIP_delete(gi);
        return;
    }
    GeoIP_delete(gi);
    snprintf(buffer, length, "Unknown (4)");
    return;
}
#endif /* LIBGEOIP_ENABLED */

/* Drop/allow patterns */
OSMatch FWDROPpm;
OSMatch FWALLOWpm;

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

char CustomAlertTokenName[CUSTOM_ALERT_TOKEN_LAST][15] = {
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

/* Store the events in a file
 * The string must be null terminated and contain
 * any necessary new lines, tabs, etc.
 */
void OS_Store(Eventinfo *lf)
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
            lf->hostname != lf->location ? lf->hostname : "",
            lf->hostname != lf->location ? "->" : "",
            lf->location,
            lf->full_log);

    fflush(_eflog);
    return;
}

void OS_LogOutput(Eventinfo *lf)
{
#ifdef LIBGEOIP_ENABLED
    char geoip_msg_src[OS_SIZE_1024 + 1];
    char geoip_msg_dst[OS_SIZE_1024 + 1];
    geoip_msg_src[0] = '\0';
    geoip_msg_dst[0] = '\0';
    if (Config.loggeoip) {
        if (lf->srcip) {
            GeoIP_Lookup(lf->srcip, geoip_msg_src, OS_SIZE_1024);
        }
        if (lf->dstip) {
            GeoIP_Lookup(lf->dstip, geoip_msg_dst, OS_SIZE_1024);
        }
    }
#endif
    printf(
        "** Alert %d.%ld:%s - %s\n"
        "%d %s %02d %s %s%s%s\nRule: %d (level %d) -> '%s'"
        "%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n%.1256s\n",
        lf->time,
        __crt_ftell,
        lf->generated_rule->alert_opts & DO_MAILALERT ? " mail " : "",
        lf->generated_rule->group,
        lf->year,
        lf->mon,
        lf->day,
        lf->hour,
        lf->hostname != lf->location ? lf->hostname : "",
        lf->hostname != lf->location ? "->" : "",
        lf->location,
        lf->generated_rule->sigid,
        lf->generated_rule->level,
        lf->generated_rule->comment,

        lf->srcip == NULL ? "" : "\nSrc IP: ",
        lf->srcip == NULL ? "" : lf->srcip,

#ifdef LIBGEOIP_ENABLED
        (strlen(geoip_msg_src) == 0) ? "" : "\nSrc Location: ",
        (strlen(geoip_msg_src) == 0) ? "" : geoip_msg_src,
#else
        "",
        "",
#endif

        lf->srcport == NULL ? "" : "\nSrc Port: ",
        lf->srcport == NULL ? "" : lf->srcport,

        lf->dstip == NULL ? "" : "\nDst IP: ",
        lf->dstip == NULL ? "" : lf->dstip,

#ifdef LIBGEOIP_ENABLED
        (strlen(geoip_msg_dst) == 0) ? "" : "\nDst Location: ",
        (strlen(geoip_msg_dst) == 0) ? "" : geoip_msg_dst,
#else
        "",
        "",
#endif

        lf->dstport == NULL ? "" : "\nDst Port: ",
        lf->dstport == NULL ? "" : lf->dstport,

        lf->dstuser == NULL ? "" : "\nUser: ",
        lf->dstuser == NULL ? "" : lf->dstuser,

        lf->full_log);

    /* Print the last events if present */
    if (lf->generated_rule->last_events) {
        char **lasts = lf->generated_rule->last_events;
        while (*lasts) {
            printf("%.1256s\n", *lasts);
            lasts++;
        }
        lf->generated_rule->last_events[0] = NULL;
    }

    printf("\n");

    fflush(stdout);
    return;
}

void OS_Log(Eventinfo *lf)
{
#ifdef LIBGEOIP_ENABLED
    char geoip_msg_src[OS_SIZE_1024 + 1];
    char geoip_msg_dst[OS_SIZE_1024 + 1];
    geoip_msg_src[0] = '\0';
    geoip_msg_dst[0] = '\0';
    if (Config.loggeoip) {
        if (lf->srcip) {
            GeoIP_Lookup(lf->srcip, geoip_msg_src, OS_SIZE_1024 );
        }
        if (lf->dstip) {
            GeoIP_Lookup(lf->dstip, geoip_msg_dst, OS_SIZE_1024 );
        }
    }
#endif
    /* Writing to the alert log file */
    fprintf(_aflog,
            "** Alert %d.%ld:%s - %s\n"
            "%d %s %02d %s %s%s%s\nRule: %d (level %d) -> '%s'"
            "%s%s%s%s%s%s%s%s%s%s%s%s%s%s\n%.1256s\n",
            lf->time,
            __crt_ftell,
            lf->generated_rule->alert_opts & DO_MAILALERT ? " mail " : "",
            lf->generated_rule->group,
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location ? lf->hostname : "",
            lf->hostname != lf->location ? "->" : "",
            lf->location,
            lf->generated_rule->sigid,
            lf->generated_rule->level,
            lf->generated_rule->comment,

            lf->srcip == NULL ? "" : "\nSrc IP: ",
            lf->srcip == NULL ? "" : lf->srcip,

#ifdef LIBGEOIP_ENABLED
            (strlen(geoip_msg_src) == 0) ? "" : "\nSrc Location: ",
            (strlen(geoip_msg_src) == 0) ? "" : geoip_msg_src,
#else
            "",
            "",
#endif

            lf->srcport == NULL ? "" : "\nSrc Port: ",
            lf->srcport == NULL ? "" : lf->srcport,

            lf->dstip == NULL ? "" : "\nDst IP: ",
            lf->dstip == NULL ? "" : lf->dstip,

#ifdef LIBGEOIP_ENABLED
            (strlen(geoip_msg_dst) == 0) ? "" : "\nDst Location: ",
            (strlen(geoip_msg_dst) == 0) ? "" : geoip_msg_dst,
#else
            "",
            "",
#endif

            lf->dstport == NULL ? "" : "\nDst Port: ",
            lf->dstport == NULL ? "" : lf->dstport,

            lf->dstuser == NULL ? "" : "\nUser: ",
            lf->dstuser == NULL ? "" : lf->dstuser,

            lf->full_log);

    /* Print the last events if present */
    if (lf->generated_rule->last_events) {
        char **lasts = lf->generated_rule->last_events;
        while (*lasts) {
            fprintf(_aflog, "%.1256s\n", *lasts);
            lasts++;
        }
        lf->generated_rule->last_events[0] = NULL;
    }

    fprintf(_aflog, "\n");
    fflush(_aflog);

    return;
}

void OS_CustomLog(Eventinfo *lf, char *format)
{
    char *log;
    char *tmp_log;
    char tmp_buffer[1024];

    /* Replace all the tokens */
    os_strdup(format, log);

    snprintf(tmp_buffer, 1024, "%d", lf->time);
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_TIMESTAMP], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }
    snprintf(tmp_buffer, 1024, "%ld", __crt_ftell);
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_FTELL], tmp_buffer);
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", (lf->generated_rule->alert_opts & DO_MAILALERT) ? "mail " : "");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_ALERT_OPTIONS], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->hostname ? lf->hostname : "None");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_HOSTNAME], tmp_buffer);
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->location ? lf->location : "None");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_LOCATION], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%d", lf->generated_rule->sigid);
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_ID], tmp_buffer);
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%d", lf->generated_rule->level);
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_LEVEL], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->srcip ? lf->srcip : "None");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_SRC_IP], tmp_buffer);
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->dstuser ? lf->dstuser : "None");

    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_DST_USER], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }
    char *escaped_log;
    escaped_log = escape_newlines(lf->full_log);

    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_FULL_LOG], escaped_log );
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    if (escaped_log) {
        os_free(escaped_log);
        escaped_log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->generated_rule->comment ? lf->generated_rule->comment : "");
    tmp_log = searchAndReplace(log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_COMMENT], tmp_buffer);
    if (log) {
        os_free(log);
        log = NULL;
    }

    snprintf(tmp_buffer, 1024, "%s", lf->generated_rule->group ? lf->generated_rule->group : "");
    log = searchAndReplace(tmp_log, CustomAlertTokenName[CUSTOM_ALERT_TOKEN_RULE_GROUP], tmp_buffer);
    if (tmp_log) {
        os_free(tmp_log);
        tmp_log = NULL;
    }

    fprintf(_aflog, "%s", log);
    fprintf(_aflog, "\n");
    fflush(_aflog);

    if (log) {
        os_free(log);
        log = NULL;
    }

    return;
}

void OS_InitFwLog()
{
    /* Initialize fw log regexes */
    if (!OSMatch_Compile(FWDROP, &FWDROPpm, 0)) {
        ErrorExit(REGEX_COMPILE, ARGV0, FWDROP,
                  FWDROPpm.error);
    }

    if (!OSMatch_Compile(FWALLOW, &FWALLOWpm, 0)) {
        ErrorExit(REGEX_COMPILE, ARGV0, FWALLOW,
                  FWALLOWpm.error);
    }
}

int FW_Log(Eventinfo *lf)
{
    /* If we don't have the srcip or the
     * action, there is no point in going
     * forward over here
     */
    if (!lf->action || !lf->srcip || !lf->dstip || !lf->srcport ||
            !lf->dstport || !lf->protocol) {
        return (0);
    }

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
            lf->hostname != lf->location ? lf->hostname : "",
            lf->hostname != lf->location ? "->" : "",
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

