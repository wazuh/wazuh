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
static int seechanges_dupfile(const char *old, const char *current) __attribute__((nonnull));
static int seechanges_createpath(const char *filename) __attribute__((nonnull));

static const char *STR_MORE_CHANGES = "More changes...";

#ifndef WIN32
#define PATH_OFFSET 1
#else
#define PATH_OFFSET 3
#endif

static char* filter(const char *string) {
#ifndef WIN32
    /* Unix version: we'll escape expansion symbols */
    char *out;
    const char *ptr;
    size_t clen;
    size_t len = strcspn(string, "\"\\$`");
    out = malloc(len + 1);
    ptr = string + len;
    strncpy(out, string, len);

    while (*ptr) {
        clen = strcspn(ptr + 1, "\"\\$`");
        out = realloc(out, len + clen + 3);
        out[len] = '\\';
        out[len + 1] = *ptr;
        strncpy(out + len + 2, ptr + 1, clen);
        len += clen + 2;
        ptr += clen + 1;
    }

    out[len] = '\0';
    return out;
#else
        /* Windows file names can't contain the following characters:
           \ / : * ? " < > |
           We'll ban strings that contain dangerous characters and convert / into \ */

        char *s;
        char *c;

        if (strchr(string, '%'))
            return NULL;

        s = strdup(string);
        c = s;

        while (c = strchr(c, '/'), c)
            *c = '\\';

        return s;
#endif
}

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

/* Return TRUE if the file name match one of the ``nodiff`` entries.
   Return FALSE otherwise */
int is_nodiff(const char *filename){
    if (syscheck.nodiff){
        int i;
        for (i = 0; syscheck.nodiff[i] != NULL; i++){
            if (strncasecmp(syscheck.nodiff[i], filename,
                            strlen(filename)) == 0) {
                return (TRUE);
            }
        }
    }
    if (syscheck.nodiff_regex) {
        int i;
        for (i = 0; syscheck.nodiff_regex[i] != NULL; i++) {
            if (OSMatch_Execute(filename, strlen(filename),
                                syscheck.nodiff_regex[i])) {
                 return (TRUE);
            }
        }
    }
    return (FALSE);
}

/* Generate diffs alerts */
static char *gen_diff_alert(const char *filename, time_t alert_diff_time)
{
    size_t n = 0;
    FILE *fp;
    char *diff_str;
    char buf[OS_MAXSTR + 1];

    buf[OS_MAXSTR] = '\0';

    snprintf(buf, OS_MAXSTR, "%s/local/%s/diff.%d",
             DIFF_DIR_PATH, filename + PATH_OFFSET, (int)alert_diff_time);

    fp = fopen(buf, "r");
    if (!fp) {
        merror("%s: ERROR: Unable to generate diff alert.", ARGV0);
        return (NULL);
    }

    n = fread(buf, 1, 4096 - 1, fp);
    fclose(fp);

    switch (n) {
    case 0:
        merror("%s: ERROR: Unable to generate diff alert (fread).", ARGV0);
        return (NULL);
    case 4095:
        n -= strlen(STR_MORE_CHANGES);

        while (n > 0 && buf[n - 1] != '\n')
            n--;

        strcpy(buf + n, STR_MORE_CHANGES);
        break;
    default:
        buf[n] = '\0';
    }

#ifdef WIN32
    diff_str = strchr(buf, '\n');

    if (!diff_str) {
        merror("%s: ERROR: Unable to find second line of alert string.", ARGV0);
        return NULL;
    }

    diff_str++;

#else
    diff_str = buf;
#endif

    return (strdup(diff_str));
}

static int seechanges_dupfile(const char *old, const char *current)
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

    fpw = fopen(current, "w");
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
    char *next = NULL;

    os_strdup(filename, buffer);
    newdir = buffer;
    tmpstr = strtok(buffer + PATH_OFFSET, "/\\");
    if (!tmpstr) {
        merror("%s: ERROR: Invalid path name: '%s'", ARGV0, filename);
        free(buffer);
        return (0);
    }

    while (next = strtok(NULL, "/\\"), next) {
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

        tmpstr = next;
        tmpstr[-1] = '/';
    }

    free(buffer);
    return (1);
}

/* Check if the file has changed */
char *seechanges_addfile(const char *filename)
{
    time_t old_date_of_change;
    time_t new_date_of_change;
    char old_location[OS_MAXSTR + 1];
    char tmp_location[OS_MAXSTR + 1];
    char diff_location[OS_MAXSTR + 1];
    char diff_cmd[OS_MAXSTR + 1];
    os_md5 md5sum_old;
    os_md5 md5sum_new;
    int status = -1;

    old_location[OS_MAXSTR] = '\0';
    tmp_location[OS_MAXSTR] = '\0';
    diff_location[OS_MAXSTR] = '\0';
    diff_cmd[OS_MAXSTR] = '\0';
    char *tmp_location_filtered = NULL;
    char *old_location_filtered = NULL;
    char *diff_location_filtered = NULL;
    md5sum_new[0] = '\0';
    md5sum_old[0] = '\0';

    snprintf(
        old_location,
        OS_MAXSTR,
        "%s/local/%s/%s",
        DIFF_DIR_PATH,
        filename + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    /* If the file is not there, rename new location to last location */
    if (OS_MD5_File(old_location, md5sum_old, OS_BINARY) != 0) {
        seechanges_createpath(old_location);
        if (seechanges_dupfile(filename, old_location) != 1) {
            merror(RENAME_ERROR, ARGV0, filename, old_location, errno, strerror(errno));
        }
        return (NULL);
    }

    /* Get md5sum of the new file */
    if (OS_MD5_File(filename, md5sum_new, OS_BINARY) != 0) {
        return (NULL);
    }

    /* If they match, keep the old file and remove the new */
    if (strcmp(md5sum_new, md5sum_old) == 0) {
        return (NULL);
    }

    /* Save the old file at timestamp and rename new to last */
    old_date_of_change = File_DateofChange(old_location);

    snprintf(
        tmp_location,
        OS_MAXSTR,
        "%s/local/%s/state.%d",
        DIFF_DIR_PATH,
        filename + PATH_OFFSET,
        (int)old_date_of_change
    );

    if (rename(old_location, tmp_location) == -1) {
        merror(RENAME_ERROR, ARGV0, old_location, tmp_location, errno, strerror(errno));
        return (NULL);
    }

    if (seechanges_dupfile(filename, old_location) != 1) {
        merror("%s: ERROR: Unable to create snapshot for %s", ARGV0, filename);
        return (NULL);
    }

    new_date_of_change = File_DateofChange(old_location);

    /* Create diff location */
    snprintf(
        diff_location,
        OS_MAXSTR,
        "%s/local/%s/diff.%d",
        DIFF_DIR_PATH,
        filename + PATH_OFFSET,
        (int)new_date_of_change
    );

    if (is_nodiff((filename))) {
        /* Dont leak sensible data with a diff hanging around */
        FILE *fdiff;
        char* nodiff_message = "<Diff truncated because nodiff option>";
        fdiff = fopen(diff_location, "w");
        if (!fdiff){
            merror("%s: ERROR: Unable to open file for writing `%s`", ARGV0, diff_location);
            goto cleanup;
        }
        fwrite(nodiff_message, strlen(nodiff_message) + 1, 1, fdiff);
        fclose(fdiff);
        /* Success */
        status = 0;
    } else {
        /* OK, run diff */

        tmp_location_filtered = filter(tmp_location);
        old_location_filtered = filter(old_location);
        diff_location_filtered = filter(diff_location);

        if (!(tmp_location_filtered && old_location_filtered && diff_location_filtered)) {
            debug1("%s: DEBUG: Diff execution skipped for containing insecure characters.", ARGV0);
            goto cleanup;
        }

        snprintf(
            diff_cmd,
            2048,
#ifndef WIN32
            "diff \"%s\" \"%s\" > \"%s\" 2> /dev/null",
#else
            "fc \"%s\" \"%s\" > \"%s\" 2> nul",
#endif
            tmp_location_filtered,
            old_location_filtered,
            diff_location_filtered
        );

#ifndef WIN32
        if (system(diff_cmd) != 256) {
#else
        int pstatus = system(diff_cmd);
        if (pstatus < 0 || pstatus > 1) {
#endif
            merror("%s: ERROR: Unable to run `%s`", ARGV0, diff_cmd);
            goto cleanup;
        }

        /* Success */
        status = 0;
    };

cleanup:

    free(tmp_location_filtered);
    free(old_location_filtered);
    free(diff_location_filtered);

    if (status == -1)
        return (NULL);

    /* Generate alert */
    return (gen_diff_alert(filename, new_date_of_change));
}
