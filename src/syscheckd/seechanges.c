/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_crypto/md5/md5_op.h"
#include "syscheck.h"

/* Prototypes */
static char *gen_diff_alert(const char *filename, time_t alert_diff_time) __attribute__((nonnull));
static int seechanges_dupfile(const char *old, const char *new) __attribute__((nonnull));
static int seechanges_createpath(const char *filename) __attribute__((nonnull));

#ifdef USE_MAGIC
#include <magic.h>

/* Global variables */
extern magic_t magic_cookie;


int is_text(magic_t cookie, const void *buf, size_t len)
{
    const char *magic = magic_buffer(cookie, buf, len);

    if (!magic) {
        const char *err = magic_error(cookie);
        merror("%s: ERROR: magic_buffer: %s", ARGV0, err ? err : "unknown");
        return (1); // TODO default to true?
    } else {
        if (strncmp(magic, "text/", 5) == 0) {
            return (1);
        }
    }

    return (0);
}
#endif

/* Generate diffs alerts */
static char *gen_diff_alert(const char *filename, time_t alert_diff_time)
{
    size_t n = 0;
    FILE *fp;
    char *tmp_str;
    char buf[OS_MAXSTR + 1];
    char diff_alert[OS_MAXSTR + 1];

    buf[OS_MAXSTR] = '\0';
    diff_alert[OS_MAXSTR] = '\0';

    snprintf(buf, OS_MAXSTR, "%s/local/%s/diff.%d",
             DIFF_DIR_PATH, filename,  (int)alert_diff_time);

    fp = fopen(buf, "r");
    if (!fp) {
        merror("%s: ERROR: Unable to generate diff alert.", ARGV0);
        return (NULL);
    }

    n = fread(buf, 1, 4096 - 1, fp);
    if (n <= 0) {
        merror("%s: ERROR: Unable to generate diff alert (fread).", ARGV0);
        fclose(fp);
        return (NULL);
    } else if (n >= 4000) {
        /* Clear the last newline */
        buf[n] = '\0';
        tmp_str = strrchr(buf, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
        } else {
            /* Weird diff with only one large line */
            buf[256] = '\0';
        }
    } else {
        buf[n] = '\0';
    }

    n = 0;

    /* Get up to 20 line changes */
    tmp_str = buf;

    while (tmp_str && (*tmp_str != '\0')) {
        tmp_str = strchr(tmp_str, '\n');
        if (!tmp_str) {
            break;
        } else if (n >= 19) {
            *tmp_str = '\0';
            break;
        }
        n++;
        tmp_str++;
    }

    /* Create alert */
    snprintf(diff_alert, 4096 - 1, "%s%s",
             buf, n >= 19 ?
             "\nMore changes.." :
             "");

    fclose(fp);
    return (strdup(diff_alert));
}

static int seechanges_dupfile(const char *old, const char *new)
{
    size_t n;
    FILE *fpr;
    FILE *fpw;
    unsigned char buf[2048 + 1];

    buf[2048] = '\0';

    fpr = fopen(old, "r");
    if (!fpr) {
        return (0);
    }

    fpw = fopen(new, "w");
    if (!fpw) {
        fclose(fpr);
        return (0);
    }

    n = fread(buf, 1, 2048, fpr);
#ifdef USE_MAGIC
    if (is_text(magic_cookie, buf, n) == 0) {
        goto cleanup;
    }
#endif

    do {
        buf[n] = '\0';
        fwrite(buf, n, 1, fpw);
    } while ((n = fread(buf, 1, 2048, fpr)) > 0);

#ifdef USE_MAGIC
cleanup:
#endif
    fclose(fpr);
    fclose(fpw);
    return (1);
}

static int seechanges_createpath(const char *filename)
{
    char *buffer = NULL;
    char *tmpstr = NULL;
    char *newdir = NULL;

    os_strdup(filename, buffer);
    newdir = buffer;
    tmpstr = strchr(buffer + 1, '/');
    if (!tmpstr) {
        merror("%s: ERROR: Invalid path name: '%s'", ARGV0, filename);
        free(buffer);
        return (0);
    }
    *tmpstr = '\0';
    tmpstr++;

    while (1) {
        if (IsDir(newdir) != 0) {
#ifndef WIN32
            if (mkdir(newdir, 0770) == -1)
#else
            if (mkdir(newdir) == -1)
#endif
            {
                merror(MKDIR_ERROR, ARGV0, newdir, errno, strerror(errno));
                free(buffer);
                return (0);
            }
        }

        if (*tmpstr == '\0') {
            break;
        }

        tmpstr[-1] = '/';
        tmpstr = strchr(tmpstr, '/');
        if (!tmpstr) {
            break;
        }
        *tmpstr = '\0';
        tmpstr++;
    }

    free(buffer);
    return (1);
}

/* Check if the file has changed */
char *seechanges_addfile(const char *filename)
{
    time_t date_of_change;
    char old_location[OS_MAXSTR + 1];
    char tmp_location[OS_MAXSTR + 1];
    char diff_cmd[OS_MAXSTR + 1];
    os_md5 md5sum_old;
    os_md5 md5sum_new;

    old_location[OS_MAXSTR] = '\0';
    tmp_location[OS_MAXSTR] = '\0';
    diff_cmd[OS_MAXSTR] = '\0';
    md5sum_new[0] = '\0';
    md5sum_old[0] = '\0';

    snprintf(old_location, OS_MAXSTR, "%s/local/%s/%s", DIFF_DIR_PATH, filename + 1,
             DIFF_LAST_FILE);

    /* If the file is not there, rename new location to last location */
    if (OS_MD5_File(old_location, md5sum_old) != 0) {
        seechanges_createpath(old_location);
        if (seechanges_dupfile(filename, old_location) != 1) {
            merror(RENAME_ERROR, ARGV0, filename, old_location, errno, strerror(errno));
        }
        return (NULL);
    }

    /* Get md5sum of the new file */
    if (OS_MD5_File(filename, md5sum_new) != 0) {
        return (NULL);
    }

    /* If they match, keep the old file and remove the new */
    if (strcmp(md5sum_new, md5sum_old) == 0) {
        return (NULL);
    }

    /* Save the old file at timestamp and rename new to last */
    date_of_change = File_DateofChange(old_location);
    snprintf(tmp_location, OS_MAXSTR, "%s/local/%s/state.%d", DIFF_DIR_PATH, filename + 1,
             (int)date_of_change);

    if (rename(old_location, tmp_location) == -1) {
        merror(RENAME_ERROR, ARGV0, old_location, tmp_location, errno, strerror(errno));
        return (NULL);
    }

    if (seechanges_dupfile(filename, old_location) != 1) {
        merror("%s: ERROR: Unable to create snapshot for %s", ARGV0, filename);
        return (NULL);
    }

    /* Run diff */
    date_of_change = File_DateofChange(old_location);
    snprintf(diff_cmd, 2048, "diff \"%s\" \"%s\" > \"%s/local/%s/diff.%d\" "
             "2>/dev/null",
             tmp_location, old_location,
             DIFF_DIR_PATH, filename + 1, (int)date_of_change);
    if (system(diff_cmd) != 256) {
        merror("%s: ERROR: Unable to run diff for %s",
               ARGV0,  filename);
        return (NULL);
    }

    /* Generate alert */
    return (gen_diff_alert(filename, date_of_change));
}

