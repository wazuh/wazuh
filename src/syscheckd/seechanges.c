/* Copyright (C) 2015-2020, Wazuh Inc.
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

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier from tests
#define static
#endif

#ifdef WIN32
#define unlink(x) _unlink(x)
#endif

/* Prototypes */
/**
 * @brief Generate diffs alerts
 *
 * @param filename Path to file
 * @param alert_diff_time Time of diff alert
 * @param status Status of the output from the diff command
 * @return Diff string
 */
static char *gen_diff_alert(const char *filename, time_t alert_diff_time, __attribute__((unused)) int status)
                            __attribute__((nonnull));

/**
 * @brief Duplicate file
 *
 * @param old File to read from
 * @param current File to write to
 * @return 0 on error, 1 on success
 */
static int seechanges_dupfile(const char *old, const char *current) __attribute__((nonnull));

/**
 * @brief Create path for compressed file
 *
 * @param filename Path to the file that needs the new path
 * @return 0 on error, 1 on success
 */
static int seechanges_createpath(const char *filename) __attribute__((nonnull));

#ifdef WIN32
/**
 * @brief Adapt fc command output in Windows
 *
 * @param command_output fc command output
 * @return Adapted output
 */
static char *adapt_win_fc_output(char *command_output);
#endif

static const char *STR_MORE_CHANGES = "More changes...";

#ifndef WIN32
#define PATH_OFFSET 1
#else
#define PATH_OFFSET 0
#endif

static char* filter(const char *string) {
#ifndef WIN32
    /* Unix version: we'll escape expansion symbols */
    char *out;
    const char *ptr;
    size_t clen;
    size_t len = strcspn(string, "\"\\$`");
    os_malloc(len + 1, out);
    ptr = string + len;
    strncpy(out, string, len);

    while (*ptr) {
        clen = strcspn(ptr + 1, "\"\\$`");
        out = realloc(out, len + clen + 3);
        if(!out){
            merror_exit(MEM_ERROR, errno, strerror(errno)); // LCOV_EXCL_LINE
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
static char *gen_diff_alert(const char *filename, time_t alert_diff_time, __attribute__((unused)) int status) {
    size_t n = 0;
    FILE *fp;
    char *diff_str;
    char path[PATH_MAX + 1];
    char buf[OS_MAXSTR + 1];
    char tmp_location[PATH_MAX + 1];
    char compressed_file[PATH_MAX + 1];
    char containing_folder[PATH_MAX + 1];
    char compressed_tmp[PATH_MAX + 1];
    char localtmp_path[PATH_MAX + 1];
    char filename_abs[PATH_MAX];
    float tmp_diff_size = syscheck.diff_folder_size;

    path[PATH_MAX] = '\0';
    if (abspath(filename, filename_abs, sizeof(filename_abs)) == NULL) {
        merror("Cannot get absolute path of '%s': %s (%d)", filename, strerror(errno), errno);
        return NULL;
    }

#ifdef WIN32
    {
        char * filename_strip = os_strip_char(filename_abs, ':');

        if (filename_strip == NULL) {
            merror("Cannot remove heading colon from full path '%s'", filename_abs);
            return NULL;
        }

        strncpy(filename_abs, filename_strip, sizeof(filename_abs));
        filename_abs[sizeof(filename_abs) - 1] = '\0';
        free(filename_strip);
    }
#endif

    snprintf(
        tmp_location,
        PATH_MAX,
        "%s/localtmp/%s/%s",
        DIFF_DIR_PATH,
        filename_abs + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    snprintf(
        compressed_file,
        PATH_MAX,
        "%s/local/%s/%s.gz",
        DIFF_DIR_PATH,
        filename_abs + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    snprintf(
        containing_folder,
        PATH_MAX,
        "%s/local/%s",
        DIFF_DIR_PATH,
        filename_abs + PATH_OFFSET
    );

    snprintf(
        compressed_tmp,
        PATH_MAX,
        "%s/localtmp/%s/%s.gz",
        DIFF_DIR_PATH,
        filename_abs + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    snprintf(
        localtmp_path,
        PATH_MAX,
        "%s/localtmp",
        DIFF_DIR_PATH
    );

#ifdef WIN32
    tmp_diff_size -= (FileSizeWin(compressed_file) / 1024);
    if (syscheck.disk_quota_enabled && !seechanges_estimate_compression(FileSizeWin(filename_abs) / 1024)) {
#else
    tmp_diff_size -= (FileSize(compressed_file) / 1024);
    if (syscheck.disk_quota_enabled && !seechanges_estimate_compression(FileSize(filename_abs) / 1024)) {
#endif
        if (rmdir_ex(containing_folder) < 0) {
            if (errno != ENOENT) {
                mdebug2(RMDIR_ERROR, containing_folder, errno, strerror(errno));
            }
        }

        syscheck.diff_folder_size = tmp_diff_size;

        return NULL;
    }


    if (!seechanges_createpath(tmp_location)) {
        mdebug2("Could not create '%s' folder", tmp_location);
    }

    if (w_compress_gzfile(filename, compressed_tmp) != 0) {
        mwarn(FIM_WARN_GENDIFF_SNAPSHOT, filename);
    }
    else if (syscheck.disk_quota_enabled) {
#ifdef WIN32
        tmp_diff_size += (FileSizeWin(compressed_tmp) / 1024);
#else
        tmp_diff_size += (FileSize(compressed_tmp) / 1024);
#endif

        if (tmp_diff_size > syscheck.disk_quota_limit) {
            if (syscheck.disk_quota_full_msg) {
                syscheck.disk_quota_full_msg = false;
                mdebug2(FIM_DISK_QUOTA_LIMIT_REACHED, DIFF_DIR_PATH);
            }
#ifdef WIN32
            seechanges_modify_estimation_percentage(FileSizeWin(compressed_tmp) / 1024, FileSizeWin(filename) / 1024);
#else
            seechanges_modify_estimation_percentage(FileSize(compressed_tmp) / 1024, FileSize(filename) / 1024);
#endif

            seechanges_delete_compressed_file(filename_abs);

            if (rmdir_ex(localtmp_path) < 0) {
                mdebug2(RMDIR_ERROR, localtmp_path, errno, strerror(errno));
            }

            return NULL;
        }

        syscheck.diff_folder_size = tmp_diff_size;
    }

    snprintf(path, PATH_MAX, "%s/local/%s/diff.%d",
             DIFF_DIR_PATH, filename_abs + PATH_OFFSET, (int)alert_diff_time);

    fp = wfopen(path, "rb");
    if (!fp) {
        merror(FIM_ERROR_GENDIFF_OPEN, path);
        return (NULL);
    }

    n = fread(buf, 1, OS_MAXSTR - OS_SK_HEADER - 1, fp);
    fclose(fp);
    unlink(path);

    switch (n) {
    case 0:
        merror(FIM_ERROR_GENDIFF_READ);
        return (NULL);
    #ifndef WIN32
    case OS_MAXSTR - OS_SK_HEADER - 1:
        buf[n] = '\0';
        n -= strlen(STR_MORE_CHANGES);

        while (n > 0 && buf[n - 1] != '\n')
            n--;

        strcpy(buf + n, STR_MORE_CHANGES);
        break;
    #endif
    default:
        buf[n] = '\0';
    }

#ifdef WIN32
    if (diff_str = adapt_win_fc_output(buf), !diff_str) {
        return NULL;
    }

    // On Windows we handle long diffs after adapting the fc output.
    if(status) {
        char *p = strchr(buf, '\n');

        n = strlen(diff_str);

        if(p && p[1] != '*') {
            // If the second line does not start with '*', an error message was printed,
            // most likely stating that the files are "too different"
            if(n >= OS_MAXSTR - OS_SK_HEADER - 1 - strlen(STR_MORE_CHANGES)) {
                n -= strlen(STR_MORE_CHANGES);

                while (n > 0 && diff_str[n - 1] != '\n')
                    n--;
            }

            strcpy(diff_str + n, STR_MORE_CHANGES);
        }
    }
#else
    os_strdup(buf, diff_str);
#endif

    if (rename_ex(compressed_tmp, compressed_file) != 0) {
        mdebug2(RENAME_ERROR, compressed_tmp, compressed_file, errno, strerror(errno));
        os_free(diff_str);
        return NULL;
    }

    if (rmdir_ex(localtmp_path) < 0) {
        mdebug2(RMDIR_ERROR, localtmp_path, errno, strerror(errno));
    }

    return diff_str;
}

static int seechanges_dupfile(const char *old, const char *current) {
    size_t n;
    FILE *fpr;
    FILE *fpw;
    unsigned char buf[2048 + 1];

    buf[2048] = '\0';

    fpr = wfopen(old, "rb");
    if (!fpr) {
        return (0);
    }

    fpw = wfopen(current, "wb");
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

char *seechanges_get_diff_path(char *path) {
    char *full_path;
    os_malloc(sizeof(char) * (strlen(DIFF_DIR_PATH) + strlen(path) + 8), full_path);
    snprintf(full_path, PATH_MAX, "%s%clocal", DIFF_DIR_PATH, PATH_SEP);

#ifdef WIN32
    char drive[3];
    drive[0] = PATH_SEP;
    drive[1] = path[0];

    char *windows_path = strchr(path, ':');

    if (windows_path == NULL) {
        mdebug1("Incorrect path. This does not contain ':' ");
        os_free(full_path);
        return NULL;
    }

    strncat(full_path, drive, 2);
    strncat(full_path, (windows_path + 1), PATH_MAX - strlen(full_path) - 1);
#else
    strncat(full_path, path, PATH_MAX - strlen(full_path) - 1);
#endif

    return full_path;
}

void seechanges_delete_compressed_file(const char *path){
    char containing_folder[PATH_MAX + 1];
    char last_entry_file[PATH_MAX + 1];
    float file_size = 0.0;

    snprintf(
        containing_folder,
        PATH_MAX,
        "%s/local/%s",
        DIFF_DIR_PATH,
        path + PATH_OFFSET
    );

    snprintf(
        last_entry_file,
        strlen(containing_folder) + strlen(DIFF_LAST_FILE) + 5,
        "%s/%s.gz",
        containing_folder,
        DIFF_LAST_FILE
    );

#ifdef WIN32
    char abs_path[PATH_MAX + 1];

    abspath(containing_folder, abs_path, sizeof(abs_path));
    snprintf(containing_folder, PATH_MAX, "%s", abs_path);

    abspath(last_entry_file, abs_path, sizeof(abs_path));
    snprintf(last_entry_file, PATH_MAX, "%s", abs_path);
#endif

    if (IsDir(containing_folder) == -1) {
        return;     // The folder does not exist
    }

#ifdef WIN32
     file_size = (float)FileSizeWin(last_entry_file) / 1024;
#else
     file_size = (float)FileSize(last_entry_file) / 1024;
#endif

    if (rmdir_ex(containing_folder) < 0) {
        mdebug2(RMDIR_ERROR, containing_folder, errno, strerror(errno));
    }
    else {
        if (file_size != -1) {
            syscheck.diff_folder_size -= file_size;

            if (syscheck.diff_folder_size < 0) {
                syscheck.diff_folder_size = 0;
            }
        }

        mdebug2(FIM_DIFF_FOLDER_DELETED, containing_folder);
    }
}

int seechanges_estimate_compression(const float file_size) {
    float uncompressed_size = file_size;
    float compressed_estimation = 0.0;
    int result = -1;

    compressed_estimation = uncompressed_size - (syscheck.comp_estimation_perc * uncompressed_size);
    result = (syscheck.diff_folder_size + compressed_estimation) <= syscheck.disk_quota_limit;

    return result;
}

void seechanges_modify_estimation_percentage(const float compressed_size, const float uncompressed_size) {
    float compression_rate;

    if (uncompressed_size <= 0 || compressed_size <= 0) {
        return;
    }
    compression_rate = 1 - (compressed_size / uncompressed_size);

    if (compression_rate < 0.1) {
        return;     // Small compression rates won't update the estimation value
    }

    syscheck.comp_estimation_perc = (compression_rate + syscheck.comp_estimation_perc) / 2;

    if (syscheck.comp_estimation_perc < MIN_COMP_ESTIM) {
        syscheck.comp_estimation_perc = MIN_COMP_ESTIM;
    }
}

char *seechanges_addfile(const char *filename) {
    time_t old_date_of_change;
    time_t new_date_of_change;
    char old_location[PATH_MAX + 1];
    char tmp_location[PATH_MAX + 1];
    char diff_location[PATH_MAX + 1];
    char diff_cmd[PATH_MAX + OS_SIZE_1024];
    char compressed_file[PATH_MAX + 1];
    char containing_folder[PATH_MAX + 1];
    char containing_tmp_folder[PATH_MAX + 1];
    char compressed_tmp[PATH_MAX + 1];
    char localtmp_path[PATH_MAX + 1];
    char localtmp_location[PATH_MAX + 1];
#ifdef WIN32
    char abs_path[PATH_MAX + 1];
#endif
    os_md5 md5sum_old;
    os_md5 md5sum_new;
    int status = -1;
    float file_size = 0.0;
    float compressed_new_size = 0.0;
    int it = 0;

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

    char filename_abs[PATH_MAX];

    if (abspath(filename, filename_abs, sizeof(filename_abs)) == NULL) {
        merror("Cannot get absolute path of '%s': %s (%d)", filename, strerror(errno), errno);
        return NULL;
    }

#ifdef WIN32
    file_size = (float)FileSizeWin(filename_abs) / 1024;
#else
    file_size = (float)FileSize(filename_abs) / 1024;
#endif

    it = fim_configuration_directory(filename_abs, "file");

#ifdef WIN32
    {
        char * filename_strip = os_strip_char(filename_abs, ':');

        if (filename_strip == NULL) {
            merror("Cannot remove heading colon from full path '%s'", filename_abs);
            return NULL;
        }

        strncpy(filename_abs, filename_strip, sizeof(filename_abs));
        filename_abs[sizeof(filename_abs) - 1] = '\0';
        free(filename_strip);
    }
#endif

    if (syscheck.file_size_enabled) {
        if (file_size > syscheck.diff_size_limit[it]) {
            mdebug2(FIM_BIG_FILE_REPORT_CHANGES, filename_abs);
            seechanges_delete_compressed_file(filename_abs);
            return NULL;
        }
    }

    snprintf(
        old_location,
        PATH_MAX,
        "%s/local/%s/%s",
        DIFF_DIR_PATH,
        filename_abs + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    snprintf(
        localtmp_location,
        PATH_MAX,
        "%s/localtmp/%s/%s",
        DIFF_DIR_PATH,
        filename_abs + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    snprintf(
        containing_folder,
        PATH_MAX,
        "%s/local/%s",
        DIFF_DIR_PATH,
        filename_abs + PATH_OFFSET
    );

    snprintf(
        containing_tmp_folder,
        PATH_MAX,
        "%s/localtmp/%s",
        DIFF_DIR_PATH,
        filename_abs + PATH_OFFSET
    );

    snprintf(
        compressed_file,
        PATH_MAX,
        "%s/local/%s/%s.gz",
        DIFF_DIR_PATH,
        filename_abs + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    snprintf(
        compressed_tmp,
        PATH_MAX,
        "%s/localtmp/%s/%s.gz",
        DIFF_DIR_PATH,
        filename_abs + PATH_OFFSET,
        DIFF_LAST_FILE
    );

    snprintf(
        localtmp_path,
        PATH_MAX,
        "%s/localtmp",
        DIFF_DIR_PATH
    );

    // Estimate if the file could fit in the disk_quota limit. If it estimates it won't fit, delete compressed file.
    if (syscheck.disk_quota_enabled && !seechanges_estimate_compression(file_size)) {
        if (rmdir_ex(compressed_file) < 0) {
            if (errno != ENOENT) {
                mdebug2(RMDIR_ERROR, compressed_file, errno, strerror(errno));
            }
        }
        else {
#ifndef WIN32
            syscheck.diff_folder_size -= FileSize(compressed_file) / 1024;
#else
            syscheck.diff_folder_size -= FileSizeWin(compressed_file) / 1024;
#endif
        }

        return NULL;
    }

    // If the file is not there, create compressed file
    if (w_uncompress_gzfile(compressed_file, old_location) != 0) {
        seechanges_createpath(old_location);
        seechanges_createpath(localtmp_location);

        if (w_compress_gzfile(filename, compressed_tmp) != 0) {
            mwarn(FIM_WARN_GENDIFF_SNAPSHOT, filename);
        }
        else if (syscheck.disk_quota_enabled) {
#ifdef WIN32
            abspath(containing_tmp_folder, abs_path, sizeof(abs_path));
            snprintf(containing_tmp_folder, PATH_MAX, "%s", abs_path);
#endif
            compressed_new_size = DirSize(containing_tmp_folder) / 1024;
            /**
             * Check if adding the new file doesn't exceed the disk quota limit. Update the diff_folder_size
             * value if it's not exceeded and move the temporary file to the correct location.
             * It shouldn't perform any diff operation if the file causes the diff folder to exceed the disk
             * quota limit.
             */
            if (syscheck.diff_folder_size + compressed_new_size <= syscheck.disk_quota_limit) {
                syscheck.diff_folder_size += compressed_new_size;

                if (rename_ex(compressed_tmp, compressed_file) != 0) {
                    mdebug2(RENAME_ERROR, compressed_tmp, compressed_file, errno, strerror(errno));
                }

                return NULL;
            }
            else {
                if (syscheck.disk_quota_full_msg) {
                    syscheck.disk_quota_full_msg = false;
                    mdebug2(FIM_DISK_QUOTA_LIMIT_REACHED, DIFF_DIR_PATH);
                }

                seechanges_modify_estimation_percentage(compressed_new_size, file_size);

#ifdef WIN32
                abspath(containing_folder, abs_path, sizeof(abs_path));
                snprintf(containing_folder, PATH_MAX, "%s", abs_path);
#endif

                if (rmdir_ex(containing_folder) < 0) {
                    mdebug2(RMDIR_ERROR, containing_folder, errno, strerror(errno));
                }
            }
        }
        else {
            if (rename_ex(compressed_tmp, compressed_file) != 0) {
                mdebug2(RENAME_ERROR, compressed_tmp, compressed_file, errno, strerror(errno));
            }

            return NULL;
        }

#ifdef WIN32
        abspath(localtmp_path, abs_path, sizeof(abs_path));
        snprintf(localtmp_path, PATH_MAX, "%s", abs_path);
#endif

        if (rmdir_ex(localtmp_path) < 0) {
            mdebug2(RMDIR_ERROR, localtmp_path, errno, strerror(errno));
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
        filename_abs + PATH_OFFSET,
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
        filename_abs + PATH_OFFSET,
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
        fdiff = wfopen(diff_location, "wb");
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
            mdebug1(FIM_DIFF_SKIPPED); //LCOV_EXCL_LINE
            goto cleanup; //LCOV_EXCL_LINE
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
#ifndef WIN32
        status = 0;
#else
        status = pstatus;
#endif
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
    return (gen_diff_alert(filename, new_date_of_change, status));
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
        mdebug2("%s: %s", FIM_ERROR_GENDIFF_SECONDLINE_MISSING, command_output);
        return strdup(command_output);
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
