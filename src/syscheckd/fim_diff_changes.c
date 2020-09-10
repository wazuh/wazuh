/* Copyright (C) 2015-2020, Wazuh Inc.
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


// Remove static qualifier from tests
#ifdef WAZUH_UNIT_TESTING
#define static
#endif

#ifdef WIN32
#define unlink(x) _unlink(x)
#define FileSize(x) FileSizeWin(x)
#define PATH_OFFSET 0
#else
#define PATH_OFFSET 1
#endif

static const char *STR_MORE_CHANGES = "More changes...";

typedef struct diff_paths {

    char *compress_folder;
    char *compress_file;

    char *tmp_folder;
    char *file_origin;
    char *uncompress_file;
    char *compress_tmp_file;
    char *diff_file;

    int size_limit;

} diff_paths;

/* Prototypes */
//TODO description
/**
 * @brief
 *
 * @param encode_key
 * @param encode_value
 * @param configuration
 *
 * @return diff_paths structure
 */
diff_paths *initialize_registry_diff_paths(
        char *encode_key,
        char *encode_value,
        registry *configuration);

//TODO description
/**
 * @brief
 *
 * @param filename
 *
 * @return diff_paths structure
 */
diff_paths *initialize_file_diff_paths(char *filename);

//TODO description
/**
 * @brief
 *
 * @param diff
 *
 * @return diff_paths structure
 */
void free_diff_paths(diff_paths *diff);

//TODO description
/**
 * @brief
 *
 * @param diff
 *
 * @return
 */
char *fim_diff_check_file(diff_paths *diff);

//TODO description
/**
 * @brief
 *
 * @param folder
 *
 * @return
 */
void fim_diff_delete_compress_folder(char *folder);

//TODO description
/**
 * @brief
 *
 * @param file_size
 *
 * @return
 */
int fim_diff_estimate_compression(const float file_size);

//TODO description
/**
 * @brief
 *
 * @param diff
 * @param file_size
 *
 * @return
 */
int fim_diff_create_compress(diff_paths *diff, float file_size);

//TODO description
/**
 * @brief
 *
 * @param filename
 *
 * @return
 */
int is_nodiff(const char *filename);

//TODO description
/**
 * @brief
 *
 * @param diff
 * @param status
 *
 * @return
 */
char *gen_diff_str(diff_paths *diff, __attribute__((unused)) int status);

//TODO description
/**
 * @brief
 *
 * @param string
 *
 * @return
 */
char* filter(const char *string);

#ifdef WIN32
char * fim_registry_value_diff(
            char *key_name,
            char *value_name,
            char *value_data,
            DWORD data_type,
            registry registry) {

    char buffer[PATH_MAX + 1];
    char *diff_changes = NULL;
    char *aux_data = NULL;
    char *key_path = NULL;
    char *value_path = NULL;
    os_sha1 encoded_key;
    os_sha1 encoded_value;
    FILE *fp;

    // Invalid types for report_changes
    if (data_type == REG_NONE || data_type == REG_BINARY || data_type == REG_LINK || data_type == REG_RESOURCE_LIST
        || data_type == REG_FULL_RESOURCE_DESCRIPTOR || data_type == REG_RESOURCE_REQUIREMENTS_LIST){
            return NULL;
    }

    OS_SHA1_Str(key_name, strlen(key_name), encoded_key);
    OS_SHA1_Str(value_name, strlen(value_name), encoded_value);

    snprintf(buffer, MAX_PATH, "%s\\tmp\\%s", DIFF_DIR_PATH, encoded_key);
    os_strdup(key_path, buffer);

    mkdir(key_path);
    snprintf(buffer, MAX_PATH, "%s\\%s", encoded_key, encoded_value);
    os_strdup(value_path, buffer);

    //TODO: Ensure that the content generation is correct
    if (fp = fopen(value_path, "w"), fp) {
        switch (data_type) {
            case REG_SZ:
            case REG_EXPAND_SZ:
                fprintf(fp, "%s", value_data);
                break;

            case REG_MULTI_SZ:
                aux_data = value_data;

                while (*aux_data) {
                    fprintf(fp, "%s\n", aux_data);
                    aux_data += strlen(aux_data) + 1;
                }
                break;
            case REG_DWORD:
                fprintf(fp, "%04x", *((unsigned int*)value_data));
                break;

            case REG_DWORD_BIG_ENDIAN:
                aux_data = value_data;

                fprintf(fp, "%04x", *((unsigned int*)value_data));
                break;

            case REG_QWORD:
                fprintf(fp, "%05x", *((unsigned int*)value_data));
                break;

            default:
                // Wrong type
                mwarn(FIM_REG_VAL_WRONG_TYPE, data_type);
                break;
        }
    } else {
        merror(FOPEN_ERROR, value_path, errno, strerror(errno));
        os_free(key_path);
        os_free(value_path);
        return NULL;
    }

    fclose(fp);

    diff_paths diff = initialize_registry_diff_paths(key_path, value_path);

    // We send the file with the value data to "seechanges" as if it were a monitored file
    if (diff_changes = fim_diff_check_file(diff), !diff_changes) {
        // error, comprobar
        return NULL;
    }

    // Remove file with value data, no longer needed
    _unlink(value_path);
    // Remove dir if empty
    rmdir(key_path);

    return diff_changes;
}


diff_paths *initialize_registry_diff_paths(
            char *encode_key,
            char *encode_value,
            registry *configuration){

    diff_paths *diff;
    char buffer[PATH_MAX + 1];

    os_calloc(1, sizeof(diff_paths), diff);

    //TODO: remove encode_KEY folder, if no more value files are inside
    snprintf(
        buffer,
        PATH_MAX,
        "%s/registry/%s/%s",
        DIFF_DIR_PATH,
        encode_key,
        encode_value
    );
    os_strdup(buffer, diff->compress_folder);

    snprintf(
        buffer,
        PATH_MAX,
        "%s/last-entry.gz",
        diff->compress_folder
    );
    os_strdup(buffer, diff->compress_file);

    snprintf(
        buffer,
        PATH_MAX,
        "%s/tmp",
        DIFF_DIR_PATH
    );
    os_strdup(buffer, diff->tmp_folder);

    snprintf(
        buffer,
        PATH_MAX,
        "%s/%s/%s",
        diff->tmp_folder,
        encode_key,
        encode_value
    );
    os_strdup(buffer, diff->file_origin);

    snprintf(
        buffer,
        PATH_MAX,
        "%s/tmp-entry",
        diff->tmp_folder
    );
    os_strdup(buffer, diff->uncompress_file);

    snprintf(
        buffer,
        PATH_MAX,
        "%s/tmp-entry.gz",
        diff->tmp_folder
    );
    os_strdup(buffer, diff->compress_tmp_file);

    snprintf(
        buffer,
        PATH_MAX,
        "%s/diff-file",
        diff->tmp_folder
    );
    os_strdup(buffer, diff->diff_file);

    diff->size_limit = configuration->diff_size_limit;
}

#endif

diff_paths *initialize_file_diff_paths(char *filename) {
    diff_paths *diff;
    char buffer[PATH_MAX + 1];

    os_calloc(1, sizeof(diff_paths), diff);

    os_strdup(diff->file_origin, filename);


    snprintf(
        buffer,
        PATH_MAX,
        "%s/local/%s",
        DIFF_DIR_PATH,
        filename + PATH_OFFSET
    );


}

//TODO free diff_paths structure
void free_diff_paths(diff_paths *diff) {
    return;
}


char *fim_diff_check_file(diff_paths *diff) {
    float file_size = 0;
    os_md5 md5sum_old;
    os_md5 md5sum_new;
    int status = -1;
    char diff_cmd[PATH_MAX * 3 + OS_SIZE_1024];
    char *diff_str = NULL;
    char *uncompress_file_filtered = NULL;
    char *file_origin_filtered = NULL;
    char *diff_file_filtered = NULL;

    file_size = (float)FileSize(diff->file_origin) / 1024;

    if (syscheck.file_size_enabled) {
        if (file_size > diff->size_limit) {
            // TODO: get real name for registry key and value
            mdebug2(FIM_BIG_FILE_REPORT_CHANGES, diff->file_origin);
            fim_diff_delete_compress_folder(diff->compress_folder);
            return NULL;
        }
    }

    // Estimate if the file could fit in the disk_quota limit. If not, return.
    if (syscheck.disk_quota_enabled && !fim_diff_estimate_compression(file_size)) {
        // TODO: check that, when the quota is exceeded, the last backup of the file that could be stored is kept
        return NULL;
    }

    fim_diff_createpath(diff->tmp_folder);

    // If the file is not there, create compressed file and return.
    if (w_uncompress_gzfile(diff->compress_file, diff->uncompress_file) != 0) {
        fim_diff_create_compress(diff, file_size);
        if (rmdir_ex(diff->tmp_folder) < 0) {
            mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
        }
        return NULL;
    }

    /**~~~~~~~~~~~~~~~~Start the comparison~~~~~~~~~~~~~~~~*/
    md5sum_new[0] = '\0';
    md5sum_old[0] = '\0';

    /* Get md5sum of the old file */
    if (OS_MD5_File(diff->uncompress_file, md5sum_old, OS_BINARY) != 0) {
        if (rmdir_ex(diff->tmp_folder) < 0) {
            mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
        }
        return (NULL);
    }

    /* Get md5sum of the new file */
    if (OS_MD5_File(diff->file_origin, md5sum_new, OS_BINARY) != 0) {
        if (rmdir_ex(diff->tmp_folder) < 0) {
            mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
        }
        return (NULL);
    }

    /* If they match (not changes), keep the compress file and remove the uncompress, wait for changes */
    if (strcmp(md5sum_new, md5sum_old) == 0) {
        if (rmdir_ex(diff->tmp_folder) < 0) {
            mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
        }
        return (NULL);
    }

#ifndef WIN32
    if (is_nodiff(diff->file_origin) || symlink_to_dir(diff->file_origin)) {
#else
    if (is_nodiff(diff->file_origin)) {
#endif
        /* Dont leak sensible data with a diff hanging around */
        FILE *fdiff;
        char* nodiff_message = "<Diff truncated because nodiff option>";
        fdiff = wfopen(diff->diff_file, "wb");
        if (!fdiff){
            merror(FIM_ERROR_GENDIFF_OPEN_FILE, diff->diff_file);
            goto cleanup;
        }

        if (fwrite(nodiff_message, strlen(nodiff_message) + 1, 1, fdiff) < 1) {
            merror(FIM_ERROR_GENDIFF_WRITING_DATA, diff->diff_file);
        }
        fclose(fdiff);
        /* Success nodiff */
        status = 1;
    } else {
        /* OK, run diff */
        uncompress_file_filtered = filter(diff->uncompress_file);
        file_origin_filtered = filter(diff->file_origin);
        diff_file_filtered = filter(diff->diff_file);

        if (!(uncompress_file_filtered && file_origin_filtered && diff_file_filtered)) {
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
            uncompress_file_filtered,
            file_origin_filtered,
            diff_file_filtered
        );

        status = system(diff_cmd);
    }

    if (status == 1){
        diff_str = gen_diff_str(diff, status);
    } else if (status != 0){
        //TODO
        merror("Diff command error");
    }

cleanup:

    free(uncompress_file_filtered);
    free(file_origin_filtered);
    free(diff_file_filtered);
    free_diff_paths(diff);
    if (rmdir_ex(diff->tmp_folder) < 0) {
        mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
    }

    return diff_str;
}

char *gen_diff_str(diff_paths *diff, int status){
    float tmp_diff_size = syscheck.diff_folder_size;
    FILE *fp;
    char buf[OS_MAXSTR + 1];
    size_t n = 0;
    char *diff_str;

    tmp_diff_size -= (FileSize(diff->compress_file) / 1024);
/* COMPROBACION NECESARIA?
    if (syscheck.disk_quota_enabled && !seechanges_estimate_compression(FileSize(diff->file_origin) / 1024)) {
        if (rmdir_ex(diff->tmp_folder) < 0) {
            mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
        }
        return NULL;
    }
*/

    if (w_compress_gzfile(diff->file_origin, diff->compress_tmp_file) != 0) {
            mwarn(FIM_WARN_GENDIFF_SNAPSHOT, diff->file_origin);
    } else if (syscheck.disk_quota_enabled) {
        tmp_diff_size += (FileSize(diff->compress_tmp_file) / 1024);

        if (tmp_diff_size > syscheck.disk_quota_limit) {
            if (syscheck.disk_quota_full_msg) {
                syscheck.disk_quota_full_msg = false;
                mdebug2(FIM_DISK_QUOTA_LIMIT_REACHED, DIFF_DIR_PATH);
            }
            fim_diff_modify_compress_estimation(FileSize(diff->compress_tmp_file) / 1024, FileSize(diff->file_origin) / 1024);
            fim_diff_delete_compress_folder(diff->compress_folder);

            if (rmdir_ex(diff->tmp_folder) < 0) {
                mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
            }
            return NULL;
        }

        syscheck.diff_folder_size = tmp_diff_size;
    }

    fp = wfopen(diff->diff_file, "rb");
    if (!fp) {
        merror(FIM_ERROR_GENDIFF_OPEN, diff->diff_file);
        if (rmdir_ex(diff->tmp_folder) < 0) {
            mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
        }
        return NULL;
    }

    n = fread(buf, 1, OS_MAXSTR - OS_SK_HEADER - 1, fp);
    fclose(fp);
    unlink(diff->diff_file);

    switch (n) {
    case 0:
        merror(FIM_ERROR_GENDIFF_READ);
        if (rmdir_ex(diff->tmp_folder) < 0) {
            mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
        }
        return NULL;
// TODO: unify MORE_CHANGES utility, windows and linux
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
        if (rmdir_ex(diff->tmp_folder) < 0) {
            mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
        }
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

    if (rename_ex(diff->compress_tmp_file, diff->compress_file) != 0) {
        mdebug2(RENAME_ERROR, diff->compress_tmp_file, diff->compress_file, errno, strerror(errno));
        os_free(diff_str);
        if (rmdir_ex(diff->tmp_folder) < 0) {
            mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
        }
        return NULL;
    }

    if (rmdir_ex(diff->tmp_folder) < 0) {
        mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
    }
    return diff_str;
}

void fim_diff_delete_compress_folder(char *folder) {
    float file_size = 0.0;

    if (IsDir(folder) == -1) {
        return;     // The folder does not exist
    }

    file_size = (float)FileSize(folder) / 1024;

    if (rmdir_ex(folder) < 0) {
        mdebug2(RMDIR_ERROR, folder, errno, strerror(errno));
    } else {
        if (file_size != -1) {
            syscheck.diff_folder_size -= file_size;

            if (syscheck.diff_folder_size < 0) {
                syscheck.diff_folder_size = 0;
            }
        }
    }
}

void fim_diff_modify_compress_estimation(const float compressed_size, const float uncompressed_size) {
    float compression_rate = 1 - (compressed_size / uncompressed_size);

    if (compression_rate < 0.1) {
        return;     // Small compression rates won't update the estimation value
    }

    syscheck.comp_estimation_perc = (compression_rate + syscheck.comp_estimation_perc) / 2;

    if (syscheck.comp_estimation_perc < MIN_COMP_ESTIM) {
        syscheck.comp_estimation_perc = MIN_COMP_ESTIM;
    }
}

int fim_diff_estimate_compression(const float file_size) {
    float compressed_estimation = 0.0;
    int result = -1;

    compressed_estimation = file_size - (syscheck.comp_estimation_perc * file_size);
    result = (syscheck.diff_folder_size + compressed_estimation) <= syscheck.disk_quota_limit;

    return result;
}

int fim_diff_createpath(const char *filename){
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
            if (mkdir(newdir, 0770) == -1){
#else
            if (mkdir(newdir) == -1){
#endif
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

int fim_diff_create_compress(diff_paths *diff, float file_size) {
    unsigned int compressed_new_size = 0;

    fim_diff_createpath(diff->compress_folder);

    if (w_compress_gzfile(diff->file_origin, diff->compress_tmp_file) != 0) {
        mwarn(FIM_WARN_GENDIFF_SNAPSHOT, diff->file_origin);
    } else if (syscheck.disk_quota_enabled) {
        compressed_new_size = FileSize(diff->compress_tmp_file) / 1024;
        /**
         * Check if adding the new file doesn't exceed the disk quota limit.
         * Update the diff_folder_size value if it's not exceeded and move
         * the temporary file to the correct location.
         * It shouldn't perform any diff operation if the file causes the
         * diff folder to exceed the disk quota limit.
         */
        if (syscheck.diff_folder_size + compressed_new_size <= syscheck.disk_quota_limit) {
            syscheck.diff_folder_size += compressed_new_size;

            if (rename_ex(diff->compress_tmp_file, diff->compress_file) != 0) {
                mdebug2(RENAME_ERROR, diff->compress_tmp_file, diff->compress_file, errno, strerror(errno));
            }

            return NULL;
        } else {
            if (syscheck.disk_quota_full_msg) {
                syscheck.disk_quota_full_msg = false;
                mdebug2(FIM_DISK_QUOTA_LIMIT_REACHED, DIFF_DIR_PATH);
            }

            fim_diff_modify_compress_estimation(compressed_new_size, file_size);

            if (rmdir_ex(diff->compress_folder) < 0) {
                mdebug2(RMDIR_ERROR, diff->compress_folder, errno, strerror(errno));
            }
        }
    } else {
        if (rename_ex(diff->compress_tmp_file, diff->compress_file) != 0) {
            mdebug2(RENAME_ERROR, diff->compress_tmp_file, diff->compress_file, errno, strerror(errno));
        }

        return NULL;
    }

    return (NULL);
}

//TODO: Registry nodiff functionality
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

char* filter(const char *string) {
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
