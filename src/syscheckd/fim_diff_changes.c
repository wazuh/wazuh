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
#define PATH_OFFSET 0
#else
#define PATH_OFFSET 1
#endif

static const char *STR_MORE_CHANGES = "More changes...";

typedef struct diff_paths {

    char *file_origin;
    char *compress_file;
    char *compress_folder;
    char *tmp_folder;
    char *compress_tmp_file;

    int size_limit;

    // char *containing_folder;
    // char *old_location;
    // char *tmp_path;
    // char *containing_tmp_folder;
    // char *tmp_location;
    // char *compressed_tmp;
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
char *fim_diff_addfile(diff_paths *diff);

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
 *
 * @return
 */
int fim_diff_create_compress(diff_paths *diff);



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
    if (diff_changes = fim_diff_addfile(diff), !diff_changes) {
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

    snprintf(
        buffer,
        PATH_MAX,
        "%s/tmp/%s/%s",
        DIFF_DIR_PATH,
        encode_key,
        encode_value
    );
    os_strdup(buffer, diff->file_origin);

    snprintf(
        buffer,
        PATH_MAX,
        "%s/registry/%s/%s/last-entry.gz",
        DIFF_DIR_PATH,
        encode_key,
        encode_value
    );
    os_strdup(buffer, diff->compress_file);

    snprintf(
        buffer,
        PATH_MAX,
        "%s/registry/%s/%s",
        DIFF_DIR_PATH,
        encode_key,
        encode_value
    );
    os_strdup(buffer, diff->compress_folder);

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


char *fim_diff_addfile(diff_paths *diff) {
    int file_size = 0;

#ifdef WIN32
    file_size = (float)FileSizeWin(diff->file_origin) / 1024;
#else
    file_size = (float)FileSize(diff->file_origin) / 1024;
#endif

    if (syscheck.file_size_enabled) {
        if (file_size > diff->size_limit) {
            // TODO: get real name for registry value
            mdebug2(FIM_BIG_FILE_REPORT_CHANGES, diff->file_origin);
            fim_diff_delete_compress_folder(diff->compress_folder);
            return NULL;
        }
    }

    // Estimate if the file could fit in the disk_quota limit. If it estimates it won't fit, delete compressed file.
    if (syscheck.disk_quota_enabled && !fim_diff_estimate_compression(file_size)) {
        // TODO: check that, when the quota is exceeded, the last backup of the file that could be stored is kept
        return NULL;
    }

    // If the file is not there, create compressed file
    if (w_uncompress_gzfile(diff->compress_file, diff->file_origin) != 0) {
        fim_diff_create_compress(diff);
        return NULL;
    }


}


void fim_diff_delete_compress_folder(char *folder) {
    float file_size = 0.0;

    if (IsDir(folder) == -1) {
        return;     // The folder does not exist
    }

#ifdef WIN32
     file_size = (float)FileSizeWin(folder) / 1024;
#else
     file_size = (float)FileSize(folder) / 1024;
#endif

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


int fim_diff_estimate_compression(const float file_size) {
    float compressed_estimation = 0.0;
    int result = -1;

    compressed_estimation = file_size - (syscheck.comp_estimation_perc * file_size);
    result = (syscheck.diff_folder_size + compressed_estimation) <= syscheck.disk_quota_limit;

    return result;
}


int fim_diff_create_compress(diff_paths *diff) {
    unsigned int compressed_new_size = 0;

    seechanges_createpath(diff->compress_folder);
    seechanges_createpath(diff->tmp_folder);

    if (w_compress_gzfile(diff->file_origin, diff->compress_tmp_file) != 0) {
        mwarn(FIM_WARN_GENDIFF_SNAPSHOT, diff->file_origin);
    }
    else if (syscheck.disk_quota_enabled) {
        compressed_new_size = DirSize(diff->tmp_folder) / 1024;
        /**
         * Check if adding the new file doesn't exceed the disk quota limit.
         * Update the diff_folder_size value if it's not exceeded and move
         * the temporary file to the correct location.
         * It shouldn't perform any diff operation if the file causes the
         * diff folder to exceed the disk quota limit.
         */
        if (syscheck.diff_folder_size + compressed_new_size <= syscheck.disk_quota_limit) {
            syscheck.diff_folder_size += compressed_new_size;

            if (rename_ex(diff->compressed_tmp, paths->compress_file) != 0) {
                mdebug2(RENAME_ERROR, paths->compressed_tmp, paths->compressed_file, errno, strerror(errno));
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
            abspath(paths->containing_folder, abs_path, sizeof(abs_path));
            snprintf(paths->containing_folder, PATH_MAX, "%s", abs_path);
#endif

            if (rmdir_ex(paths->containing_folder) < 0) {
                mdebug2(RMDIR_ERROR, paths->containing_folder, errno, strerror(errno));
            }
        }
    }
    else {
        if (rename_ex(paths->compressed_tmp, paths->compressed_file) != 0) {
            mdebug2(RENAME_ERROR, paths->compressed_tmp, paths->compressed_file, errno, strerror(errno));
        }

        return NULL;
    }

#ifdef WIN32
    abspath(paths->tmp_path, abs_path, sizeof(abs_path));
    snprintf(paths->tmp_path, PATH_MAX, "%s", abs_path);
#endif

    if (rmdir_ex(paths->tmp_path) < 0) {
        mdebug2(RMDIR_ERROR, paths->tmp_path, errno, strerror(errno));
    }

    return (NULL);
}
