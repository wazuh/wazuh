/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Hostinfo decoder */
#include "decoder.h"

#include "config.h"
#include "os_regex/os_regex.h"
#include "eventinfo.h"
#include "alerts/alerts.h"

#define HOSTINFO_FILE   "/queue/fts/hostinfo"
#define HOST_HOST       "Host: "
/*#define HOST_PORT       " open ports: "
#define HOST_CHANGED    "Host information changed."
#define HOST_NEW        "New host information added."*/
#define PREV_OPEN       "Previously"

/* Local variables */
static int hi_err = 0;
static int id_new = 0;
static int id_mod = 0;
static char _hi_buf[OS_MAXSTR + 1];
static FILE *_hi_fp = NULL;

/* Hostinfo decoder */
static OSDecoderInfo *hostinfo_dec = NULL;


/* Check if the string matches */
static char *__go_after(char *x, const char *y)
{
    size_t x_s;
    size_t y_s;

    /* X and Y must be not null */
    if (!x || !y) {
        return (NULL);
    }

    x_s = strlen(x);
    y_s = strlen(y);

    if (x_s <= y_s) {
        return (NULL);
    }

    /* String does not match */
    if (strncmp(x, y, y_s) != 0) {
        return (NULL);
    }

    x += y_s;

    return (x);
}

/* Initialize the necessary information to process the host information */
void HostinfoInit()
{
    hi_err = 0;

    /* Zero decoder */
    os_calloc(1, sizeof(OSDecoderInfo), hostinfo_dec);
    hostinfo_dec->id = getDecoderfromlist(HOSTINFO_MOD);
    hostinfo_dec->type = OSSEC_RL;
    hostinfo_dec->name = HOSTINFO_MOD;
    hostinfo_dec->fts = 0;
    id_new = getDecoderfromlist(HOSTINFO_NEW);
    id_mod = getDecoderfromlist(HOSTINFO_MOD);

    /* Open HOSTINFO_FILE */
    snprintf(_hi_buf, OS_SIZE_1024, "%s", HOSTINFO_FILE);

    /* r+ to read and write. Do not truncate */
    _hi_fp = fopen(_hi_buf, "r+");
    if (!_hi_fp) {
        /* Try opening with a w flag, file probably does not exist */
        _hi_fp = fopen(_hi_buf, "w");
        if (_hi_fp) {
            fclose(_hi_fp);
            _hi_fp = fopen(_hi_buf, "r+");
        }
    }
    if (!_hi_fp) {
        merror(FOPEN_ERROR, ARGV0, _hi_buf, errno, strerror(errno));
        return;
    }

    /* Clear the buffer */
    memset(_hi_buf, '\0', OS_MAXSTR + 1);

    return;
}

/* Return the file pointer to be used */
static FILE *HI_File(void)
{
    if (_hi_fp) {
        fseek(_hi_fp, 0, SEEK_SET);
        return (_hi_fp);
    }

    return (NULL);
}

/* Special decoder for Hostinformation
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive
 */
int DecodeHostinfo(Eventinfo *lf)
{
    int changed = 0;
    size_t bf_size;

    char *ip;
    char *portss;
    char *tmpstr;

    char buffer[OS_MAXSTR + 1];
    char opened[OS_MAXSTR + 1];
    FILE *fp;

    /* Check maximum number of errors */
    if (hi_err > 30) {
        merror("%s: Too many errors handling host information db. "
               "Ignoring it.", ARGV0);
        return (0);
    }

    /* Zero buffers */
    buffer[OS_MAXSTR] = '\0';
    opened[OS_MAXSTR] = '\0';
    fp = HI_File();
    if (!fp) {
        merror("%s: Error handling host information database.", ARGV0);
        hi_err++;
        return (0);
    }

    /* Copy log to buffer */
    strncpy(buffer, lf->log, OS_MAXSTR);

    /* Get IP */
    tmpstr = __go_after(buffer, HOST_HOST);
    if (!tmpstr) {
        merror("%s: Error handling host information database.", ARGV0);
        hi_err++;

        return (0);
    }

    /* Setting IP */
    ip = tmpstr;
    tmpstr = strchr(tmpstr, ',');
    if (!tmpstr) {
        merror("%s: Error handling host information database.", ARGV0);
        hi_err++;

        return (0);
    }
    *tmpstr = '\0';
    tmpstr++;
    portss = tmpstr;

    /* Get IP only information -- to store */
    tmpstr = strchr(ip, ' ');
    if (tmpstr) {
        *tmpstr = '\0';
    }
    bf_size = strlen(ip);

    /* Read the file and search for a possible entry */
    while (fgets(_hi_buf, OS_MAXSTR - 1, fp) != NULL) {
        /* Ignore blank lines and lines with a comment */
        if (_hi_buf[0] == '\n' || _hi_buf[0] == '#') {
            continue;
        }

        /* Remove newline */
        tmpstr = strchr(_hi_buf, '\n');
        if (tmpstr) {
            *tmpstr = '\0';
        }

        /* Check for IP */
        if (strncmp(ip, _hi_buf, bf_size) == 0) {
            /* Cannot use strncmp to avoid errors with crafted files */
            if (strcmp(portss, _hi_buf + bf_size) == 0) {
                return (0);
            } else {
                char *tmp_ports;

                tmp_ports = _hi_buf + (bf_size + 1);
                snprintf(opened, OS_MAXSTR, "%s %s", PREV_OPEN, tmp_ports);
                changed = 1;
            }
        }
    }

    /* Add the new entry at the end of the file */
    fseek(fp, 0, SEEK_END);
    fprintf(fp, "%s%s\n", ip, portss);

    /* Set decoder */
    lf->decoder_info = hostinfo_dec;

    /* Set comment */
    if (changed == 1) {
        hostinfo_dec->id = id_mod;
        /* lf->generated_rule->last_events[0] = opened; */
    } else {
        hostinfo_dec->id = id_new;
    }

    return (1);
}

