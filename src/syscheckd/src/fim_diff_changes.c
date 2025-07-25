/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "../os_crypto/md5/md5_op.h"
#include "syscheck.h"


// Remove static qualifier from tests
#ifdef WAZUH_UNIT_TESTING

#ifdef WIN32
#include "../unit_tests/wrappers/windows/libc/stdio_wrappers.h"
#endif

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

#ifdef WIN32

/* Prototypes */

/**
 * @brief Initializes the structure with the data needed for diff
 *
 * @param key_name Name of the key
 * @param value_name Name of the value
 * @param configuration Syscheck configuration related to the key
 *
 * @return Structure with all the data necessary to compute differences
 */
diff_data *initialize_registry_diff_data(const char *key_name, const char *value_name, const registry_t *configuration);

/**
 * @brief Creates file with the value, writing the data according to its type
 *
 * @param value_data Content of the value to be checked
 * @param data_type The type of value we are checking
 * @param diff Structure with all the data necessary to compute differences
 *
 * @return -1 on error 0 on success
 */
int fim_diff_registry_tmp(const char *value_data,
                          DWORD data_type,
                          const diff_data *diff);

#endif

/**
 * @brief Initializes the structure with the data needed for diff
 *
 * @param filename Path of file monitored
 * @param configuration Configuration associated with the file
 *
 * @return Structure with all the data necessary to compute differences
 */
diff_data *initialize_file_diff_data(const char *filename, const directory_t *configuration);

/**
 * @brief Free the structure with the data needed for diff
 *
 * @param diff Structure with all the data necessary to compute differences
 */
void free_diff_data(diff_data *diff);

/**
 * @brief Checks that the file being processed does not exceed the configuration limit
 *
 * @param diff Structure with all the data necessary to compute differences
 *
 * @return 0 if success, 1 if file_size too much large, 2 if quota is exceeded
 */
int fim_diff_check_limits(diff_data *diff);

/**
 * @brief Deletes the folder with the compressed file last-entry.gz
 *
 * @param folder Path of the folder to be removed
 *
 * @return -1 if some error occurs, 0 on success
 */
int fim_diff_delete_compress_folder(const char *folder);

/**
 * @brief Checks if diff_quota is reached with a estimation of the compressed file size
 *
 * @param file_size Size of the uncompressed file
 *
 * @return False if the compressed file doesn't fit into the quota
 */
int fim_diff_estimate_compression(float file_size);

/**
 * @brief Compresses the file in a temporal folder and checks that it fits into the quota
 *
 * @param diff Structure with all the data necessary to compute differences
 *
 * @return -1 if file can't be compressed, or if it doesn't fit into the quota
 */
int fim_diff_create_compress_file(const diff_data *diff);

/**
 * @brief Modifies the compression ratio to be used in the following estimates
 *
 * @param compressed_size Size of the compressed file
 * @param uncompressed_size Size of the uncompressed file
 */
void fim_diff_modify_compress_estimation(float compressed_size, float uncompressed_size);

/**
 * @brief Compares MD5 hashes of the old and new files to see if they are the same
 *
 * @param diff Structure with all the data necessary to compute differences
 *
 * @return -1 if old and new files are the same, 0 if they are different
 */
int fim_diff_compare(const diff_data *diff);

/**
 * @brief Generates the diff file with the result of the diff/fc command (only if nodiff is not configured)
 *
 * @param diff Structure with all the data necessary to compute differences
 * @param is_file True if the diff is for a file
 *
 * @return String with the changes to add to the alert
 */
char *fim_diff_generate(const diff_data *diff, bool is_file);

/**
 * @brief Reads the diff file and generates the string with the differences
 *
 * @param diff Structure with all the data necessary to compute differences
 *
 * @return String with the changes to add to the alert
 */
char *gen_diff_str(const diff_data *diff);

/**
 * @brief Checks if a specific file has been configured with the ``nodiff`` option
 *
 * @param filename The name of the file to check
 * @return 1 if the file has been configured with the ``nodiff`` option, 0 if not
 */
int is_file_nodiff(const char *filename);

/**
 * @brief Checks if a specific registry value has been configured with the ``nodiff`` option
 *
 * @param key_name The name of the key to check
 * @param value_name The name of the value to check
 * @param arch Architecture type of the value to check
 * @return 1 if the value has been configured with the ``nodiff`` option, 0 if not
 */
int is_registry_nodiff(const char *key_name, const char *value_name, int arch);

/**
 * @brief Filter a path so that it cannot contain strange symbols. In the case of Windows, change the '/' to '\'.
 *
 * @param string String with the path to be filtered
 *
 * @return A pointer to the filtered path
 */
char* filter(const char *string);

/**
 * @brief Saves the temporal compress file into the compress folder
 *
 * @param diff Structure with all the data necessary to compute differences
 */
void save_compress_file(const diff_data *diff);

#ifdef WIN32

/**
 * @brief Adapts the fc output to be the same as the diff
 *
 * @param command_output Output of the fc command
 *
 * @return Adapted output
 */
char *adapt_win_fc_output(char *command_output);

/* Definitions */

char *fim_registry_value_diff(const char *key_name,
                              const char *value_name,
                              const char *value_data,
                              DWORD data_type,
                              const registry_t *configuration) {

    char *diff_changes = NULL;
    int ret;

    // Invalid types for report_changes
    if (!(data_type == REG_SZ ||
          data_type == REG_EXPAND_SZ ||
          data_type == REG_MULTI_SZ ||
          data_type == REG_DWORD ||
          data_type == REG_DWORD_BIG_ENDIAN ||
          data_type == REG_QWORD)) {
            mdebug2(FIM_REG_VAL_INVALID_TYPE, key_name, value_name);
            return NULL;
    }

    // Generate diff structure
    diff_data *diff = initialize_registry_diff_data(key_name, value_name, configuration);
    if (!diff){
        goto cleanup;
    }

    // Create tmp directory and file with de content of the registry
    if (fim_diff_registry_tmp(value_data, data_type, diff) == -1){
        goto cleanup;
    }

    char full_value_name[PATH_MAX];
    snprintf(full_value_name, PATH_MAX, "%s\\%s", key_name, value_name);

    // Check for file limit and disk quota
    if (ret = fim_diff_check_limits(diff), ret == 1) {
        mdebug2(FIM_BIG_FILE_REPORT_CHANGES, full_value_name);
        os_strdup("Unable to calculate diff due to 'file_size' limit has been reached.", diff_changes);
        goto cleanup;
    } else if (ret == 2){
        mdebug2(FIM_DISK_QUOTA_LIMIT_REACHED, "estimation", full_value_name);
        os_strdup("Unable to calculate diff due to 'disk_quota' limit has been reached.", diff_changes);
        goto cleanup;
    }

    // If the file is not there, create compressed file and return.
    if (w_uncompress_gzfile(diff->compress_file, diff->uncompress_file) != 0) {
        if (ret = fim_diff_create_compress_file(diff), ret == 0){
            mkdir_ex(diff->compress_folder);
            save_compress_file(diff);
            os_strdup("Unable to calculate diff due to no previous data stored for this registry value.", diff_changes);
        } else if (ret == -2){
            os_strdup("Unable to calculate diff due to 'disk_quota' limit has been reached.", diff_changes);
        }
        goto cleanup;
    }

    // If it exists, estimate the new compressed file
    float backup_file_size = (FileSize(diff->compress_file) / 1024.0f);
    syscheck.diff_folder_size -= backup_file_size;
    if (ret = fim_diff_create_compress_file(diff), ret != 0) {
        syscheck.diff_folder_size += backup_file_size;
        if (ret == -2){
            os_strdup("Unable to calculate diff due to 'disk_quota' limit has been reached.", diff_changes);
        }
        goto cleanup;
    }

    if (fim_diff_compare(diff) == -1) {
        mdebug2(FIM_DIFF_IDENTICAL_MD5_FILES);
        syscheck.diff_folder_size += backup_file_size;
        os_strdup("No content changes were found for this registry value.", diff_changes);
        goto cleanup;
    }

    if (is_registry_nodiff(key_name, value_name, configuration->arch)) {
        os_strdup("Diff truncated due to 'nodiff' configuration detected for this registry value.", diff_changes);
        syscheck.diff_folder_size += backup_file_size;
        goto cleanup;
    }

    if (diff_changes = fim_diff_generate(diff, false), !diff_changes){
        syscheck.diff_folder_size += backup_file_size;
        goto cleanup;
    }

    save_compress_file(diff);

cleanup:

    if (rmdir_ex(diff->tmp_folder) < 0) {
        mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
    }

    free_diff_data(diff);

    return diff_changes;
}


diff_data *initialize_registry_diff_data(const char *key_name, const char *value_name, const registry_t *configuration) {
    diff_data *diff;
    char buffer[PATH_MAX];

    os_calloc(1, sizeof(diff_data), diff);

    diff->file_size = 0;
    diff->size_limit = configuration->diff_size_limit;

    os_sha1 encoded_key;
    os_sha1 encoded_value;
    OS_SHA1_Str(key_name, -1, encoded_key);
    OS_SHA1_Str(value_name, -1, encoded_value);

    if (configuration->arch){
        snprintf(buffer, PATH_MAX, "%s/registry/[x64] %s/%s", DIFF_DIR, encoded_key, encoded_value);
    } else {
        snprintf(buffer, PATH_MAX, "%s/registry/[x32] %s/%s", DIFF_DIR, encoded_key, encoded_value);
    }
    os_strdup(buffer, diff->compress_folder);

    snprintf(buffer, PATH_MAX, "%s/last-entry.gz", diff->compress_folder);
    os_strdup(buffer, diff->compress_file);

    snprintf(buffer, PATH_MAX, "%s/tmp", DIFF_DIR);
    os_strdup(buffer, diff->tmp_folder);

    if (configuration->arch){
        snprintf(buffer, PATH_MAX, "%s/[x64] %s%s", diff->tmp_folder, encoded_key, encoded_value);
    } else {
        snprintf(buffer, PATH_MAX, "%s/[x32] %s%s", diff->tmp_folder, encoded_key, encoded_value);
    }
    os_strdup(buffer, diff->file_origin);

    snprintf(buffer, PATH_MAX, "%s/tmp-entry", diff->tmp_folder);
    os_strdup(buffer, diff->uncompress_file);

    snprintf(buffer, PATH_MAX, "%s/tmp-entry.gz", diff->tmp_folder);
    os_strdup(buffer, diff->compress_tmp_file);

    snprintf(buffer, PATH_MAX, "%s/diff-file", diff->tmp_folder);
    os_strdup(buffer, diff->diff_file);

    return diff;
}

int fim_diff_registry_tmp(const char *value_data,
                          DWORD data_type,
                          const diff_data *diff) {

    char *aux_data = NULL;
    int ret = 0;

    mkdir_ex(diff->tmp_folder);
    FILE *fp = wfopen(diff->file_origin, "w");
    if (NULL != fp) {
        switch (data_type) {
            case REG_SZ:
            case REG_EXPAND_SZ:
                fprintf(fp, "%s", value_data);
                break;

            case REG_MULTI_SZ:
                while (*value_data) {
                    fprintf(fp, "%s\n", value_data);
                    value_data += strlen(value_data) + 1;
                }
                break;

            case REG_DWORD:
                fprintf(fp, "%04x", *((unsigned int*)value_data));
                break;

            case REG_DWORD_BIG_ENDIAN:
                os_calloc(1, 4, aux_data);

                for (int i = 0; i < 4; i++){
                    aux_data[i] = value_data[4 - i - 1];
                }
                fprintf(fp, "%04x", *((unsigned int*)aux_data));

                os_free(aux_data);
                break;

            case REG_QWORD:
                fprintf(fp, "%llx", *((unsigned long long*)value_data));
                break;

            default:
                // Wrong type
                mwarn(FIM_REG_VAL_WRONG_TYPE);
                ret = -1;
                break;
        }
        fclose(fp);
    } else {
        merror(FOPEN_ERROR, diff->file_origin, errno, strerror(errno));
        return -1;
    }

    return ret;
}

#endif

char *fim_file_diff(const char *filename, const directory_t *configuration) {

    char *diff_changes = NULL;
    int ret;

    // Generate diff structure
    diff_data *diff = initialize_file_diff_data(filename, configuration);
    if (!diff){
        return NULL;
    }

    mkdir_ex(diff->tmp_folder);

    // Check for file limit and disk quota
    if (ret = fim_diff_check_limits(diff), ret == 1) {
        mdebug2(FIM_BIG_FILE_REPORT_CHANGES, filename);
        os_strdup("Unable to calculate diff due to 'file_size' limit has been reached.", diff_changes);
        goto cleanup;
    } else if (ret == 2){
        mdebug2(FIM_DISK_QUOTA_LIMIT_REACHED, "estimation", filename);
        os_strdup("Unable to calculate diff due to 'disk_quota' limit has been reached.", diff_changes);
        goto cleanup;
    }

    // If the file is not there, create compressed file and return.
    if (w_uncompress_gzfile(diff->compress_file, diff->uncompress_file) != 0) {
        if (ret = fim_diff_create_compress_file(diff), ret == 0){
            mkdir_ex(diff->compress_folder);
            save_compress_file(diff);
            os_strdup("Unable to calculate diff due to no previous data stored for this file.", diff_changes);
        } else if (ret == -2){
            os_strdup("Unable to calculate diff due to 'disk_quota' limit has been reached.", diff_changes);
        }
        goto cleanup;
    }

    // If it exists, estimate the new compressed file
    float backup_file_size = (FileSize(diff->compress_file) / 1024.0f);
    syscheck.diff_folder_size -= backup_file_size;
    if (ret = fim_diff_create_compress_file(diff), ret != 0) {
        syscheck.diff_folder_size += backup_file_size;
        if (ret == -2){
            os_strdup("Unable to calculate diff due to 'disk_quota' limit has been reached.", diff_changes);
        }
        goto cleanup;
    }

    if (fim_diff_compare(diff) == -1) {
        mdebug2(FIM_DIFF_IDENTICAL_MD5_FILES);
        syscheck.diff_folder_size += backup_file_size;
        os_strdup("No content changes were found for this file.", diff_changes);
        goto cleanup;
    }

    if (is_file_nodiff(diff->file_origin)) {
        os_strdup("Diff truncated due to 'nodiff' configuration detected for this file.", diff_changes);
        syscheck.diff_folder_size += backup_file_size;
        goto cleanup;
    }

    if (diff_changes = fim_diff_generate(diff, true), !diff_changes){
        syscheck.diff_folder_size += backup_file_size;
        goto cleanup;
    }

    save_compress_file(diff);

cleanup:

    if (rmdir_ex(diff->tmp_folder) < 0) {
        mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
    }

    free_diff_data(diff);

    return diff_changes;
}


diff_data *initialize_file_diff_data(const char *filename, const directory_t *configuration){
    diff_data *diff;
    char buffer[PATH_MAX];
    char abs_diff_dir_path[PATH_MAX];
    os_sha1 encoded_path;
    char *path = NULL;

#ifdef WIN32
    path = auto_to_ansi(filename);
    if (!path) {
        return NULL;
    }
#else
    os_strdup(filename, path);
#endif

    os_calloc(1, sizeof(diff_data), diff);

    // Get diff_size_limit of filename
    diff->file_size = 0;

    if (syscheck.file_size_enabled) {
        diff->size_limit = configuration->diff_size_limit;
    }

    // Get absolute path of filename:
    if (abspath(path, buffer, sizeof(buffer)) == NULL) {
        merror(FIM_ERROR_GET_ABSOLUTE_PATH, filename, strerror(errno), errno);
        os_free(path);
        goto error;
    }
    os_free(path);

    os_strdup(buffer, diff->file_origin);

#ifdef WIN32
    // Get cwd for Windows
    if (abspath(DIFF_DIR, abs_diff_dir_path, sizeof(abs_diff_dir_path)) == NULL) {
        merror(FIM_ERROR_GET_ABSOLUTE_PATH, abs_diff_dir_path, strerror(errno), errno);
        goto error;
    }
#else
    strcpy(abs_diff_dir_path, DIFF_DIR);
#endif

    OS_SHA1_Str(buffer, -1, encoded_path);

    os_snprintf(buffer, PATH_MAX, "%s/file/%s", abs_diff_dir_path, encoded_path);
    os_strdup(buffer, diff->compress_folder);

    snprintf(buffer, PATH_MAX, "%s/last-entry.gz", diff->compress_folder);
    os_strdup(buffer, diff->compress_file);

    os_snprintf(buffer, PATH_MAX, "%s/tmp", abs_diff_dir_path);
    os_strdup(buffer, diff->tmp_folder);

    snprintf(buffer, PATH_MAX, "%s/tmp-entry", diff->tmp_folder);
    os_strdup(buffer, diff->uncompress_file);

    snprintf(buffer, PATH_MAX, "%s/tmp-entry.gz", diff->tmp_folder);
    os_strdup(buffer, diff->compress_tmp_file);

    snprintf(buffer, PATH_MAX, "%s/diff-file", diff->tmp_folder);
    os_strdup(buffer, diff->diff_file);

    return diff;

error:
    free_diff_data(diff);
    return NULL;
}

void free_diff_data(diff_data *diff) {
    if (!diff){
        return;
    }

    os_free(diff->compress_folder);
    os_free(diff->compress_file);
    os_free(diff->tmp_folder);
    os_free(diff->file_origin);
    os_free(diff->uncompress_file);
    os_free(diff->compress_tmp_file);
    os_free(diff->diff_file);

    free(diff);
}

int fim_diff_check_limits(diff_data *diff) {
    diff->file_size = (float)FileSize(diff->file_origin) / 1024;

    if (syscheck.file_size_enabled) {
        if (diff->file_size > diff->size_limit) {
            fim_diff_delete_compress_folder(diff->compress_folder);
            return 1;
        }
    }
    // Estimate if the file could fit in the disk_quota limit. If not, return.
    if (syscheck.disk_quota_enabled && !fim_diff_estimate_compression(diff->file_size)) {
        return 2;
    }

    return 0;
}

int fim_diff_delete_compress_folder(const char *folder) {
    float dir_size = 0.0;

    if (IsDir(folder) == -1) {
        return -2;     // The folder does not exist
    }

    dir_size = (float)DirSize(folder) / 1024;

    if (rmdir_ex(folder) < 0) {
        mdebug2(RMDIR_ERROR, folder, errno, strerror(errno));
        return -1;
    } else if (dir_size != -1) {
        syscheck.diff_folder_size -= dir_size;
        if (!syscheck.disk_quota_full_msg) {
            syscheck.disk_quota_full_msg = true;
        }
        if (syscheck.diff_folder_size < 0) {
            syscheck.diff_folder_size = 0;
        }
    }

    if (remove_empty_folders(folder) == -1) {
        return -1;
    }

    mdebug2(FIM_DIFF_FOLDER_DELETED, folder);
    return 0;
}

int fim_diff_estimate_compression(float file_size) {
    float compressed_estimation = file_size - (syscheck.comp_estimation_perc * file_size);
    return ((syscheck.diff_folder_size + compressed_estimation) <= syscheck.disk_quota_limit);
}

int fim_diff_create_compress_file(const diff_data *diff) {
    if (w_compress_gzfile(diff->file_origin, diff->compress_tmp_file) != 0) {
        mwarn(FIM_WARN_GENDIFF_SNAPSHOT, diff->file_origin);
        return -1;
    } else if (syscheck.disk_quota_enabled) {
        unsigned int zip_size = FileSize(diff->compress_tmp_file) / 1024;

        if (syscheck.diff_folder_size + zip_size > syscheck.disk_quota_limit) {
            if (syscheck.disk_quota_full_msg) {
                syscheck.disk_quota_full_msg = false;
                mdebug2(FIM_DISK_QUOTA_LIMIT_REACHED, "calculate", diff->file_origin);
            }
            fim_diff_modify_compress_estimation(zip_size, diff->file_size);
            return -2;
        }
    }

    return 0;
}

void fim_diff_modify_compress_estimation(float compressed_size, float uncompressed_size) {
    float compression_rate = 1 - (compressed_size / uncompressed_size);

    if (compression_rate < 0.1) {
        return;     // Small compression rates won't update the estimation value
    }

    syscheck.comp_estimation_perc = (compression_rate + syscheck.comp_estimation_perc) / 2;

    if (syscheck.comp_estimation_perc < MIN_COMP_ESTIM) {
        syscheck.comp_estimation_perc = MIN_COMP_ESTIM;
    }
}

int fim_diff_compare(const diff_data *diff) {
    os_md5 md5sum_old;
    os_md5 md5sum_new;

    md5sum_new[0] = '\0';
    md5sum_old[0] = '\0';

    /* Get md5sum of the old file */
    if (OS_MD5_File(diff->uncompress_file, md5sum_old, OS_BINARY) != 0) {
        return -1;
    }

    /* Get md5sum of the new file */
    if (OS_MD5_File(diff->file_origin, md5sum_new, OS_BINARY) != 0) {
        return -1;
    }

    /* If they match (not changes), keep the compress file and remove the uncompress, wait for changes */
    if (strcmp(md5sum_new, md5sum_old) == 0) {
        return -1;
    }

    return 0;
}

char *fim_diff_generate(const diff_data *diff, bool is_file) {
    char diff_cmd[PATH_MAX * 3 + OS_SIZE_1024];
    char *diff_str = NULL;
    char *uncompress_file_filtered = NULL;
    char *file_origin_filtered = NULL;
    char *diff_file_filtered = NULL;
    int status = -1;

    uncompress_file_filtered = filter(diff->uncompress_file);
#ifdef WIN32
    if (is_file) {
        file_origin_filtered = utf8_GetShortPathName(diff->file_origin);
    }
    if (file_origin_filtered == NULL) {
        file_origin_filtered = filter(diff->file_origin);
    }
#else
    file_origin_filtered = filter(diff->file_origin);
#endif
    diff_file_filtered = filter(diff->diff_file);

    if (!(uncompress_file_filtered && file_origin_filtered && diff_file_filtered)) {
        mdebug1(FIM_DIFF_SKIPPED);
        os_free(uncompress_file_filtered);
        os_free(file_origin_filtered);
        os_free(diff_file_filtered);
        return NULL;
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
    os_free(uncompress_file_filtered);
    os_free(file_origin_filtered);
    os_free(diff_file_filtered);

    status = system(diff_cmd);

#ifndef WIN32
    if (status == 256){
#else
    if (status == 0){
        mdebug2(FIM_DIFF_COMMAND_OUTPUT_EQUAL);
    } else if (status == 1){
#endif
        diff_str = gen_diff_str(diff);
    } else {
        merror(FIM_DIFF_COMMAND_OUTPUT_ERROR);
    }

    return diff_str;
}

char *gen_diff_str(const diff_data *diff){
    FILE *fp;
    char buf[OS_MAXSTR + 1];
    char *diff_str;
    size_t n = 0;

    fp = wfopen(diff->diff_file, "rb");
    if (!fp) {
        merror(FIM_ERROR_GENDIFF_OPEN, diff->diff_file);
        return NULL;
    }

    n = fread(buf, 1, OS_MAXSTR - OS_SK_HEADER - 1, fp);
    fclose(fp);
    unlink(diff->diff_file);

    if (!n){
        merror(FIM_ERROR_GENDIFF_READ);
        return NULL;
    }

    buf[n] = '\0';

#ifdef WIN32
    if (diff_str = adapt_win_fc_output(buf), !diff_str) {
        return NULL;
    }
    n = strlen(diff_str);
    char *p = strchr(buf, '\n');

    if (p && p[1] != '*') {
        if (n + strlen(STR_MORE_CHANGES) >= OS_MAXSTR - OS_SK_HEADER - 1) {
            n -= strlen(STR_MORE_CHANGES);

            while (n > 0 && diff_str[n - 1] != '\n')
                n--;
        }
        strcpy(diff_str + n, STR_MORE_CHANGES);
    }
#else
    os_strdup(buf, diff_str);

    if(n >= OS_MAXSTR - OS_SK_HEADER - 1) {
        n -= strlen(STR_MORE_CHANGES);

        while (n > 0 && diff_str[n - 1] != '\n')
            n--;

        strcpy(diff_str + n, STR_MORE_CHANGES);
    }
#endif

    return diff_str;
}

void save_compress_file(const diff_data *diff){
    if (rename_ex(diff->compress_tmp_file, diff->compress_file) != 0) {
        merror(RENAME_ERROR, diff->compress_tmp_file, diff->compress_file, errno, strerror(errno));
        return;
    }
    if (syscheck.disk_quota_enabled){
        syscheck.diff_folder_size += FileSize(diff->compress_file) / 1024.0f;
    }
    return;
}

int is_file_nodiff(const char *filename){
    int i;
    if (syscheck.nodiff){
        for (i = 0; syscheck.nodiff[i] != NULL; i++){
            if ((strcmp(syscheck.nodiff[i], filename)) == 0) {
                return 1;
            }
        }
    }
    if (syscheck.nodiff_regex) {
        for (i = 0; syscheck.nodiff_regex[i] != NULL; i++) {
            if (OSMatch_Execute(filename, strlen(filename),
                                syscheck.nodiff_regex[i])) {
                 return 1;
            }
        }
    }
    return 0;
}

#ifdef WIN32
int is_registry_nodiff(const char *key_name, const char *value_name, int arch){
    char full_value_name[PATH_MAX];
    int i;

    snprintf(full_value_name, PATH_MAX, "%s\\%s", key_name, value_name);

    if (syscheck.registry_nodiff){
        for (i = 0; syscheck.registry_nodiff[i].entry != NULL; i++) {
            if (syscheck.registry_nodiff[i].arch != arch) {
                continue;
            }
            if ((strcmp(syscheck.registry_nodiff[i].entry, full_value_name)) == 0) {
                return 1;
            }
        }
    }

    if (syscheck.registry_nodiff_regex) {
        for (i = 0; syscheck.registry_nodiff_regex[i].regex != NULL; i++) {
            if (syscheck.registry_nodiff_regex[i].arch != arch) {
                continue;
            }
            if (OSMatch_Execute(full_value_name, strlen(full_value_name), syscheck.registry_nodiff_regex[i].regex)) {
                return 1;
            }
        }
    }

    return 0;
}
#endif

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

void fim_diff_process_delete_file(const char *filename){
    char *full_path;
    char buffer[PATH_MAX];
    int ret;
    os_sha1 encoded_path;
    char *path = NULL;

#ifdef WIN32
    path = auto_to_ansi(filename);
    if (!path) {
        return;
    }
#else
    os_strdup(filename, path);
#endif

    if (abspath(path, buffer, sizeof(buffer)) == NULL) {
        merror(FIM_ERROR_GET_ABSOLUTE_PATH, filename, strerror(errno), errno);
        os_free(path);
        return;
    }
    os_free(path);

    OS_SHA1_Str(buffer, -1, encoded_path);

    snprintf(buffer, PATH_MAX, "%s/file/%s", DIFF_DIR, encoded_path);
    os_strdup(buffer, full_path);

    ret = fim_diff_delete_compress_folder(full_path);
    if(ret == -1){
        merror(FIM_DIFF_DELETE_DIFF_FOLDER_ERROR, full_path);
    } else if (ret == -2){
        mdebug2(FIM_DIFF_FOLDER_NOT_EXIST, full_path);
    }

    os_free(full_path);
    return;
}

#ifdef WIN32
void fim_diff_process_delete_registry(const char *key_name, int arch){
    char full_path[PATH_MAX];
    os_sha1 encoded_key;
    int ret;

    OS_SHA1_Str(key_name, strlen(key_name), encoded_key);

    if (arch){
        snprintf(full_path, PATH_MAX, "%s/registry/[x64] %s", DIFF_DIR, encoded_key);
    } else {
        snprintf(full_path, PATH_MAX, "%s/registry/[x32] %s", DIFF_DIR, encoded_key);
    }

    ret = fim_diff_delete_compress_folder(full_path);
    if(ret == -1){
        merror(FIM_DIFF_DELETE_DIFF_FOLDER_ERROR, full_path);
    } else if (ret == -2){
        mdebug2(FIM_DIFF_FOLDER_NOT_EXIST, full_path);
    }

    return;
}

void fim_diff_process_delete_value(const char *key_name, const char *value_name, int arch){
    char full_path[PATH_MAX];
    os_sha1 encoded_key;
    os_sha1 encoded_value;
    int ret;

    OS_SHA1_Str(key_name, strlen(key_name), encoded_key);
    OS_SHA1_Str(value_name, strlen(value_name), encoded_value);

    if (arch){
        snprintf(full_path, PATH_MAX, "%s/registry/[x64] %s/%s", DIFF_DIR, encoded_key, encoded_value);
    } else {
        snprintf(full_path, PATH_MAX, "%s/registry/[x32] %s/%s", DIFF_DIR, encoded_key, encoded_value);
    }

    ret = fim_diff_delete_compress_folder(full_path);
    if(ret == -1){
        merror(FIM_DIFF_DELETE_DIFF_FOLDER_ERROR, full_path);
    } else if (ret == -2){
        mdebug2(FIM_DIFF_FOLDER_NOT_EXIST, full_path);
    }

    return;
}
#endif
