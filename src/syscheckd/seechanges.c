/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_crypto/md5/md5_op.h"
#include "syscheck.h"

#ifdef WIN32
#define unlink(x) _unlink(x)
#endif

/* Prototypes */
static char *gen_diff_alert(const char *filename, time_t alert_diff_time) __attribute__((nonnull));
static int seechanges_dupfile(const char *old, const char *current) __attribute__((nonnull));
static int seechanges_createpath(const char *filename) __attribute__((nonnull));
#ifdef WIN32
static char *adapt_win_fc_output(char *command_output);
#endif

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
        if(!out){
            merror_exit(MEM_ERROR, errno, strerror(errno));
        }
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
        merror(FIM_ERROR_LIBMAGIC_BUFFER, err ? err : "unknown");
        return (1); // TODO default to true?
    } else {
        if (strncmp(magic, "text/", 5) == 0) {
            return (1);
        }
    }

    return (0);
}
#endif

#ifndef WIN32
/* Return TRUE if the filename is symlink to an directory */
int symlink_to_dir (const char *filename) {
    struct stat buf;
    int x;
    x = lstat (filename, &buf);

    if (x == 0 && S_ISLNK(buf.st_mode)) {
        x = stat (filename, &buf);
        return (x == 0 && S_ISDIR(buf.st_mode));
    } else {
        return (FALSE);
    }
}
#endif

/* Return TRUE if the file name match one of the ``nodiff`` entries.
   Return FALSE otherwise */
int is_nodiff(const char *filename){
    if (syscheck.nodiff){
        int i;
        for (i = 0; syscheck.nodiff[i] != NULL; i++){
            if ((strcmp(syscheck.nodiff[i], filename)) == 0) {
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
    char path[PATH_MAX + 1];
    char buf[OS_MAXSTR + 1];
    char compressed_file[PATH_MAX + 1];

    path[PATH_MAX] = '\0';

    snprintf(path, PATH_MAX, "%s/local/%s/diff.%d",
             DIFF_DIR_PATH, filename + PATH_OFFSET, (int)alert_diff_time);

    fp = fopen(path, "rb");
    if (!fp) {
        merror(FIM_ERROR_GENDIFF_OPEN);
        return (NULL);
    }

    n = fread(buf, 1, OS_MAXSTR - OS_SK_HEADER - 1, fp);
    fclose(fp);
    unlink(path);

    switch (n) {
    case 0:
        merror(FIM_ERROR_GENDIFF_READ);
        return (NULL);
    case OS_MAXSTR - OS_SK_HEADER - 1:
        buf[n] = '\0';
        n -= strlen(STR_MORE_CHANGES);

        while (n > 0 && buf[n - 1] != '\n')
            n--;

        strcpy(buf + n, STR_MORE_CHANGES);
        break;
    default:
        buf[n] = '\0';
    }

#ifdef WIN32
    if (diff_str = adapt_win_fc_output(buf), !diff_str) {
        return NULL;
    }

#else
    os_strdup(buf, diff_str);
#endif

    snprintf(
        compressed_file,
        PATH_MAX,
        "%s/local/%s/%s.gz",
        DIFF_DIR_PATH,
        filename + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    if (w_compress_gzfile(filename, compressed_file) != 0) {
        mwarn(FIM_WARN_GENDIFF_SNAPSHOT, filename);
    }

    return diff_str;
}

static int seechanges_dupfile(const char *old, const char *current)
{
    size_t n;
    FILE *fpr;
    FILE *fpw;
    unsigned char buf[2048 + 1];

    buf[2048] = '\0';

    fpr = fopen(old, "rb");
    if (!fpr) {
        return (0);
    }

    fpw = fopen(current, "wb");
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

        if (fwrite(buf, 1, n, fpw) != n) {
            merror(FIM_ERROR_GENDIFF_WRITING_DATA, current);
            break;
        }
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
    char *save_ptr = NULL;

    os_strdup(filename, buffer);
    newdir = buffer;
#ifdef WIN32
    tmpstr = strtok_r(buffer + PATH_OFFSET, "/\\", &save_ptr);
#else
    tmpstr = strtok_r(buffer + PATH_OFFSET, "/", &save_ptr);
#endif
    if (!tmpstr) {
        merror(FIM_ERROR_GENDIFF_INVALID_PATH, filename);
        free(buffer);
        return (0);
    }

#ifdef WIN32
    while (next = strtok_r(NULL, "/\\", &save_ptr), next) {
#else
    while (next = strtok_r(NULL, "/", &save_ptr), next) {
#endif
        if (IsDir(newdir) != 0) {
#ifndef WIN32
            if (mkdir(newdir, 0770) == -1)
#else
            if (mkdir(newdir) == -1)
#endif
            {
                merror(MKDIR_ERROR, newdir, errno, strerror(errno));
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
    char old_location[PATH_MAX + 1];
    char tmp_location[PATH_MAX + 1];
    char diff_location[PATH_MAX + 1];
    char diff_cmd[PATH_MAX + OS_SIZE_1024];
    char compressed_file[PATH_MAX + 1];
    os_md5 md5sum_old;
    os_md5 md5sum_new;
    int status = -1;

    old_location[PATH_MAX] = '\0';
    tmp_location[PATH_MAX] = '\0';
    diff_location[PATH_MAX] = '\0';
    diff_cmd[PATH_MAX] = '\0';
    compressed_file[PATH_MAX] = '\0';
    char *tmp_location_filtered = NULL;
    char *old_location_filtered = NULL;
    char *diff_location_filtered = NULL;
    md5sum_new[0] = '\0';
    md5sum_old[0] = '\0';

    snprintf(
        old_location,
        PATH_MAX,
        "%s/local/%s/%s",
        DIFF_DIR_PATH,
        filename + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    snprintf(
        compressed_file,
        PATH_MAX,
        "%s/local/%s/%s.gz",
        DIFF_DIR_PATH,
        filename + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    /* If the file is not there, create compressed file*/
    if (w_uncompress_gzfile(compressed_file, old_location) != 0) {
        seechanges_createpath(old_location);
        if (w_compress_gzfile(filename, compressed_file) != 0) {
            mwarn(FIM_WARN_GENDIFF_SNAPSHOT, filename);
        }
        return (NULL);
    }

    if (OS_MD5_File(old_location, md5sum_old, OS_BINARY) != 0) {
        unlink(old_location);
        return (NULL);
    }

    /* Get md5sum of the new file */
    if (OS_MD5_File(filename, md5sum_new, OS_BINARY) != 0) {
        unlink(old_location);
        return (NULL);
    }

    /* If they match, keep the old file and remove the new */
    if (strcmp(md5sum_new, md5sum_old) == 0) {
        unlink(old_location);
        return (NULL);
    }

    /* Save the old file at timestamp and rename new to last */
    old_date_of_change = File_DateofChange(old_location);

    snprintf(
        tmp_location,
        PATH_MAX,
        "%s/local/%s/state.%d",
        DIFF_DIR_PATH,
        filename + PATH_OFFSET,
        (int)old_date_of_change
    );

    if (rename(old_location, tmp_location) == -1) {
        merror(RENAME_ERROR, old_location, tmp_location, errno, strerror(errno));
        return (NULL);
    }

    if (seechanges_dupfile(filename, old_location) != 1) {
        merror(FIM_ERROR_GENDIFF_CREATE_SNAPSHOT, filename);
        return (NULL);
    }

    new_date_of_change = File_DateofChange(old_location);

    /* Create diff location */
    snprintf(
        diff_location,
        PATH_MAX,
        "%s/local/%s/diff.%d",
        DIFF_DIR_PATH,
        filename + PATH_OFFSET,
        (int)new_date_of_change
    );

#ifndef WIN32
    if (is_nodiff(filename) || symlink_to_dir(filename)) {
#else
    if (is_nodiff((filename))) {
#endif
        /* Dont leak sensible data with a diff hanging around */
        FILE *fdiff;
        char* nodiff_message = "<Diff truncated because nodiff option>";
        fdiff = fopen(diff_location, "wb");
        if (!fdiff){
            merror(FIM_ERROR_GENDIFF_OPEN_FILE, diff_location);
            goto cleanup;
        }

        if (fwrite(nodiff_message, strlen(nodiff_message) + 1, 1, fdiff) < 1) {
            merror(FIM_ERROR_GENDIFF_WRITING_DATA, diff_location);
        }
        fclose(fdiff);
        /* Success */
        status = 0;
    } else {
        /* OK, run diff */

        tmp_location_filtered = filter(tmp_location);
        old_location_filtered = filter(old_location);
        diff_location_filtered = filter(diff_location);

        if (!(tmp_location_filtered && old_location_filtered && diff_location_filtered)) {
            mdebug1(FIM_DIFF_SKIPPED);
            goto cleanup;
        }

        snprintf(
            diff_cmd,
            sizeof(diff_cmd),
#ifndef WIN32
            "diff \"%s\" \"%s\" > \"%s\" 2> /dev/null",
#else
            "fc /n \"%s\" \"%s\" > \"%s\" 2> nul",
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
            merror(FIM_ERROR_GENDIFF_COMMAND, diff_cmd);
            goto cleanup;
        }

        /* Success */
        status = 0;
    }

cleanup:

    unlink(tmp_location);
    unlink(old_location);
    free(tmp_location_filtered);
    free(old_location_filtered);
    free(diff_location_filtered);

    if (status == -1) {
        unlink(diff_location);
        return (NULL);
    }

    /* Generate alert */
    return (gen_diff_alert(filename, new_date_of_change));
}

#ifdef WIN32

char *adapt_win_fc_output(char *command_output) {
    char *adapted_output;
    char *line;
    char *next_line;
    const char *line_tag = ":  ";
    const char *split_tag = "---";
    char line_mode = 0; // 0: waiting for section, 1: remove, 2: add
    char first_line = 0;
    size_t line_tag_size = strlen(line_tag);
    size_t written = 0;

    if (line = strchr(command_output, '\n'), !line) {
        merror(FIM_ERROR_GENDIFF_SECONDLINE_MISSING);
        return NULL;
    }

    os_calloc(OS_MAXSTR + 1, sizeof(char), adapted_output);

    while (line) {
        next_line = strstr(++line, "\r\n");

        if (*line == '*') {
            if (next_line) {
                next_line++;
            }

            if (!line_mode) {
                if (first_line) {
                    written += snprintf(adapted_output + written, OS_MAXSTR - written, "%s\n", split_tag);
                }
                first_line = 1;
            } else if (line_mode == 1) {
                written += snprintf(adapted_output + written, OS_MAXSTR - written, "%s\n", split_tag);
            }

            line_mode = (line_mode + 1) % 3;
            goto next_it;
        }

        if (next_line) {
            *(next_line++) = '\0';
            *next_line = '\0';
        }

        if (line = strstr(line, line_tag), !line) {
            goto next_it;
        } else {
            line += line_tag_size;
        }

        written += snprintf(adapted_output + written, OS_MAXSTR - written, "%s%s%s", line_mode == 1 ? "< " : "> ", line, next_line ? "\n" : "");

next_it:
        line = next_line;
    }

    return adapted_output;
}

#endif