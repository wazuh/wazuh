/* Copyright (C) 2010 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dodiff.h"

#include "shared.h"

static int _add2last(const char *str, size_t strsize, const char *file)
{
    FILE *fp;

    fp = fopen(file, "w");
    if (!fp) {
        /* Try to create the directories */
        char *dirrule = NULL;
        char *diragent = NULL;

        dirrule = strrchr(file, '/');
        if (!dirrule) {
            merror("%s: ERROR: Invalid file name to diff: %s",
                   ARGV0, file);
            return (0);
        }
        *dirrule = '\0';

        diragent = strrchr(file, '/');
        if (!diragent) {
            merror("%s: ERROR: Invalid file name to diff (2): %s",
                   ARGV0, file);
            return (0);
        }
        *diragent = '\0';

        /* Check if the diragent exists */
        if (IsDir(file) != 0) {
            if (mkdir(file, 0770) == -1) {
                merror(MKDIR_ERROR, ARGV0, file, errno, strerror(errno));
                return (0);
            }
        }
        *diragent = '/';

        if (IsDir(file) != 0) {
            if (mkdir(file, 0770) == -1) {
                merror(MKDIR_ERROR, ARGV0, file, errno, strerror(errno));
                return (0);
            }
        }
        *dirrule = '/';

        fp = fopen(file, "w");
        if (!fp) {
            merror(FOPEN_ERROR, ARGV0, file, errno, strerror(errno));
            return (0);
        }
    }

    fwrite(str, strsize + 1, 1, fp);
    fclose(fp);
    return (1);
}

int doDiff(RuleInfo *rule, const Eventinfo *lf)
{
    time_t date_of_change;
    char *htpt = NULL;
    char flastfile[OS_SIZE_2048 + 1];
    char flastcontent[OS_SIZE_8192 + 1];

    /* Clean up global */
    flastcontent[0] = '\0';
    flastcontent[OS_SIZE_8192] = '\0';
    rule->last_events[0] = NULL;

    if (lf->hostname[0] == '(') {
        htpt = strchr(lf->hostname, ')');
        if (htpt) {
            *htpt = '\0';
        }
        snprintf(flastfile, OS_SIZE_2048, "%s/%s/%d/%s", DIFF_DIR, lf->hostname + 1,
                 rule->sigid, DIFF_LAST_FILE);

        if (htpt) {
            *htpt = ')';
        }
        htpt = NULL;
    } else {
        snprintf(flastfile, OS_SIZE_2048, "%s/%s/%d/%s", DIFF_DIR, lf->hostname,
                 rule->sigid, DIFF_LAST_FILE);
    }

    /* lf->size can't be too long */
    if (lf->size >= OS_SIZE_8192) {
        merror("%s: ERROR: event size (%ld) too long for diff.", ARGV0, lf->size);
        return (0);
    }

    /* Check if last diff exists */
    date_of_change = File_DateofChange(flastfile);
    if (date_of_change <= 0) {
        if (!_add2last(lf->log, lf->size, flastfile)) {
            merror("%s: ERROR: unable to create last file: %s", ARGV0, flastfile);
            return (0);
        }
        return (0);
    } else {
        FILE *fp;
        size_t n;
        fp = fopen(flastfile, "r");
        if (!fp) {
            merror(FOPEN_ERROR, ARGV0, flastfile, errno, strerror(errno));
            return (0);
        }

        n = fread(flastcontent, 1, OS_SIZE_8192, fp);
        if (n > 0) {
            flastcontent[n] = '\0';
        } else {
            merror("%s: ERROR: read error on %s", ARGV0, flastfile);
            fclose(fp);
            return (0);
        }
        fclose(fp);
    }

    /* Nothing changed */
    if (strcmp(flastcontent, lf->log) == 0) {
        return (0);
    }

    if (!_add2last(lf->log, lf->size, flastfile)) {
        merror("%s: ERROR: unable to create last file: %s", ARGV0, flastfile);
    }

    rule->last_events[0] = "Previous output:";
    rule->last_events[1] = flastcontent;
    return (1);
}

