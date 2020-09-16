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

typedef struct diff_data {
    int file_size;
    int size_limit;

    char *compress_folder;
    char *compress_file;

    char *tmp_folder;
    char *file_origin;
    char *uncompress_file;
    char *compress_tmp_file;
    char *diff_file;
} diff_data;

#ifdef WIN32

/* Prototypes */

/**
 * @brief Initializes the structure with the data needed for diff
 *
 * @param encoded_key Name of the key encoded with SHA1 hashing
 * @param encoded_value Name of the value encoded with SHA1 hashing
 * @param configuration Syscheck configuration related to the key
 *
 * @return Structure with all the data necessary to compute differences
 */
diff_data *initialize_registry_diff_data(
        char *key_name,
        char *value_name,
        registry *configuration);

/**
 * @brief Creates temporal folder and file with the value, writing the data according to its type
 *
 * @param key_name Path of the registry key monitored
 * @param value_name Name of the value that has generated the alert
 * @param value_data Content of the value to be checked
 * @param data_type The type of value we are checking
 * @param diff Structure with all the data necessary to compute differences
 *
 * @return -1 on error 0 on success
 */
int fim_diff_registry_tmp(char *value_data,
                          DWORD data_type,
                          diff_data *diff);

#endif

/**
 * @brief Initializes the structure with the data needed for diff
 *
 * @param filename Path of file monitored
 *
 * @return Structure with all the data necessary to compute differences
 */
diff_data *initialize_file_diff_data(char *filename);

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
 * @param filename Path of the file/registry value
 *
 * @return true if size limits is reached
 */
bool fim_diff_check_limits(diff_data *diff, char *filename);

/**
 * @brief Deletes the folder with the compress file last-entry.gz
 *
 * @param folder Path of the folder to be removed
 *
 * @return -1 if some error ocurr. 0 if success
 */
int fim_diff_delete_compress_folder(char *folder);

/**
 * @brief Checks if diff_quota is reached with a estimation of the compressed file size
 *
 * @param file_size Size of the uncompressed file
 *
 * @return False if the compressed file doesn't fit into the quota
 */
int fim_diff_estimate_compression(const float file_size);

/**
 * @brief Compresses the file in a temporal folder and checks that it fits into the quota
 *
 * @param diff Structure with all the data necessary to compute differences
 *
 * @return -1 if file can't be compressed, or if it doesn't fit into the quota
 */
int fim_diff_create_compress_file(diff_data *diff);

/**
 * @brief Modifies the compression ratio to be used in the following estimates
 *
 * @param compressed_size Size of the compressed file
 * @param uncompressed_size Size of the uncompressed file
 */
void fim_diff_modify_compress_estimation(const float compressed_size, const float uncompressed_size);

/**
 * @brief Compares MD5 hashes of the old and new files to see if they are the same
 *
 * @param diff Structure with all the data necessary to compute differences
 *
 * @return -1 if old and new files are the same, 0 if they are different
 */
int fim_diff_compare(diff_data *diff);

/**
 * @brief Generates the diff file with the result of the diff/fc command (only if nodiff is not configured)
 *
 * @param diff Structure with all the data necessary to compute differences
 *
 * @return String with the changes to add to the alert
 */
char *fim_diff_generate(diff_data *diff);

/**
 * @brief Reads the diff file and generates the string with the differences
 *
 * @param diff Structure with all the data necessary to compute differences
 *
 * @return String with the changes to add to the alert
 */
char *gen_diff_str(diff_data *diff);

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
void save_compress_file(diff_data *diff);

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

char *fim_registry_value_diff(char *key_name,
                              char *value_name,
                              char *value_data,
                              DWORD data_type,
                              registry *configuration) {

    char *diff_changes = NULL;
    bool reach_limit;

    // Invalid types for report_changes
    if (data_type == REG_NONE || data_type == REG_BINARY || data_type == REG_LINK ||
        data_type == REG_RESOURCE_LIST || data_type == REG_FULL_RESOURCE_DESCRIPTOR ||
        data_type == REG_RESOURCE_REQUIREMENTS_LIST) {
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

    // Check for file limit and disk quota
    if (reach_limit = fim_diff_check_limits(diff, key_name), reach_limit) {
        goto cleanup;
    }

    // If the file is not there, create compressed file and return.
    if (w_uncompress_gzfile(diff->compress_file, diff->uncompress_file) != 0) {
        if (fim_diff_create_compress_file(diff) == 0){
            mkdir_ex(diff->compress_folder);
            save_compress_file(diff);
        }
        goto cleanup;
    }

    // If it exists, estimate the new compressed file
    float backup_file_size = (FileSize(diff->compress_file) / 1024);
    syscheck.diff_folder_size -= backup_file_size;
    if (fim_diff_create_compress_file(diff) == -1) {
        syscheck.diff_folder_size += backup_file_size;
        goto cleanup;
    }

    if (fim_diff_compare(diff) == -1) {
        mdebug2(FIM_DIFF_IDENTICAL_MD5_FILES);
        syscheck.diff_folder_size += backup_file_size;
        goto cleanup;
    }

    if (is_registry_nodiff(key_name, value_name, configuration->arch)) {
        diff_changes = "<Diff truncated because nodiff option>";
        syscheck.diff_folder_size += backup_file_size;
        goto cleanup;
    }

    if (diff_changes = fim_diff_generate(diff), !diff_changes){
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


diff_data *initialize_registry_diff_data(
            char *key_name,
            char *value_name,
            registry *configuration){

    diff_data *diff;
    char buffer[PATH_MAX + 1];

    os_calloc(1, sizeof(diff_data), diff);

    diff->file_size = 0;
    diff->size_limit = configuration->diff_size_limit;

    os_sha1 encoded_key;
    os_sha1 encoded_value;
    OS_SHA1_Str(key_name, strlen(key_name), encoded_key);
    OS_SHA1_Str(value_name, strlen(value_name), encoded_value);

    if (configuration->arch){
        snprintf(buffer, PATH_MAX, "%s/registry/[x64] %s/%s", DIFF_DIR_PATH, encoded_key, encoded_value);
    } else {
        snprintf(buffer, PATH_MAX, "%s/registry/[x32] %s/%s", DIFF_DIR_PATH, encoded_key, encoded_value);
    }
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

    if (configuration->arch){
        snprintf(buffer, PATH_MAX, "%s/[x64] %s%s", diff->tmp_folder, encoded_key, encoded_value);
    } else {
        snprintf(buffer, PATH_MAX, "%s/[x32] %s%s", diff->tmp_folder, encoded_key, encoded_value);
    }
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

    return diff;
}

int fim_diff_registry_tmp(char *value_data,
                          DWORD data_type,
                          diff_data *diff) {

    char *aux_data = NULL;
    FILE *fp;

    mkdir_ex(diff->tmp_folder);

    //TODO: Ensure that the content generation is correct
    if (fp = fopen(diff->file_origin, "w"), fp) {
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
                os_calloc(1, 4, aux_data);

                for (int i = 0; i < 4; i++){
                    aux_data[i] = value_data[4 - i - 1];
                }
                fprintf(fp, "%04x", *((unsigned int*)aux_data));

                os_free(aux_data);
                break;

            case REG_QWORD:
                fprintf(fp, "%05x", *((unsigned int*)value_data));
                break;

            default:
                // Wrong type
                mwarn(FIM_REG_VAL_WRONG_TYPE);
                return -1;
        }
    } else {
        merror(FOPEN_ERROR, diff->file_origin, errno, strerror(errno));
        return -1;
    }

    fclose(fp);
    return 0;
}

#endif

char *fim_file_diff(char *filename) {

    char *diff_changes = NULL;
    bool reach_limit;

    // Generate diff structure
    diff_data *diff = initialize_file_diff_data(filename);
    if (!diff){
        goto cleanup;
    }

    mkdir_ex(diff->tmp_folder);

    // Check for file limit and disk quota
    if (reach_limit = fim_diff_check_limits(diff, diff->file_origin), reach_limit) {
        goto cleanup;
    }

    // If the file is not there, create compressed file and return.
    if (w_uncompress_gzfile(diff->compress_file, diff->uncompress_file) != 0) {
        if (fim_diff_create_compress_file(diff) == 0){
            mkdir_ex(diff->compress_folder);
            save_compress_file(diff);
        }
        goto cleanup;
    }

    // If it exists, estimate the new compressed file
    float backup_file_size = (FileSize(diff->compress_file) / 1024);
    syscheck.diff_folder_size -= backup_file_size;
    if (fim_diff_create_compress_file(diff) == -1) {
        syscheck.diff_folder_size += backup_file_size;
        goto cleanup;
    }

    if (fim_diff_compare(diff) == -1) {
        mdebug2(FIM_DIFF_IDENTICAL_MD5_FILES);
        syscheck.diff_folder_size += backup_file_size;
        goto cleanup;
    }

    if (is_file_nodiff(diff->file_origin)) {
        diff_changes = "<Diff truncated because nodiff option>";
        syscheck.diff_folder_size += backup_file_size;
        goto cleanup;
    }

    if (diff_changes = fim_diff_generate(diff), !diff_changes){
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


diff_data *initialize_file_diff_data(char *filename){

    diff_data *diff;
    char buffer[PATH_MAX + 1];
    char abs_diff_dir_path[PATH_MAX + 1];

    os_calloc(1, sizeof(diff_data), diff);

    // Get diff_size_limit of filename
    diff->file_size = 0;
    if (syscheck.file_size_enabled) {
        int it = fim_configuration_directory(filename, "file");
        diff->size_limit = syscheck.diff_size_limit[it];
    }

    // Get absolute path of filename:
    if (abspath(filename, buffer, sizeof(buffer)) == NULL) {
        merror(FIM_ERROR_GET_ABSOLUTE_PATH, filename, strerror(errno), errno);
        return NULL;
    }
    os_strdup(buffer, diff->file_origin);

#ifdef WIN32
    // Remove ":" from file_origin
    filename = os_strip_char(diff->file_origin, ':');

    if (filename == NULL) {
        merror(FIM_ERROR_REMOVE_COLON, diff->file_origin);
        return NULL;
    }

    // Get cwd for Windows
    if (abspath(DIFF_DIR_PATH, abs_diff_dir_path, sizeof(abs_diff_dir_path)) == NULL) {
        merror(FIM_ERROR_GET_ABSOLUTE_PATH, DIFF_DIR_PATH, strerror(errno), errno);
        return NULL;
    }
#else
    strcpy(abs_diff_dir_path, DIFF_DIR_PATH);
#endif

    snprintf(
        buffer,
        PATH_MAX,
        "%s/local/%s",
        abs_diff_dir_path,
        filename
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
        abs_diff_dir_path
    );
    os_strdup(buffer, diff->tmp_folder);

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

    os_free(filename);
    return diff;
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

    os_free(diff);

    return;
}

bool fim_diff_check_limits(diff_data *diff, char *filename) {
    diff->file_size = (float)FileSize(diff->file_origin) / 1024;

    if (syscheck.file_size_enabled) {
        if (diff->file_size > diff->size_limit) {
            mdebug2(FIM_BIG_FILE_REPORT_CHANGES, filename);
            fim_diff_delete_compress_folder(diff->compress_folder);
            return true;
        }
    }

    // Estimate if the file could fit in the disk_quota limit. If not, return.
    if (syscheck.disk_quota_enabled && !fim_diff_estimate_compression(diff->file_size)) {
        mdebug2(FIM_DISK_QUOTA_ESTIMATION, filename);
        return true;
    }

    return false;
}

int fim_diff_delete_compress_folder(char *folder) {
    float dir_size = 0.0;

    if (IsDir(folder) == -1) {
        return -1;     // The folder does not exist
    }

    dir_size = (float)DirSize(folder) / 1024;

    if (rmdir_ex(folder) < 0) {
        mdebug2(RMDIR_ERROR, folder, errno, strerror(errno));
        return -1;
    } else {
        if (dir_size != -1) {
            syscheck.diff_folder_size -= dir_size;
            if (!syscheck.disk_quota_full_msg) {
                syscheck.disk_quota_full_msg = true;
            }
            if (syscheck.diff_folder_size < 0) {
                syscheck.diff_folder_size = 0;
            }
        }
    }

    if (remove_empty_folders(folder) == -1) {
        return -1;
    }

    return 0;
}

int fim_diff_estimate_compression(const float file_size) {
    float compressed_estimation = 0.0;
    int result = -1;

    compressed_estimation = file_size - (syscheck.comp_estimation_perc * file_size);
    result = (syscheck.diff_folder_size + compressed_estimation) <= syscheck.disk_quota_limit;

    return result;
}

int fim_diff_create_compress_file(diff_data *diff) {
    if (w_compress_gzfile(diff->file_origin, diff->compress_tmp_file) != 0) {
        mwarn(FIM_WARN_GENDIFF_SNAPSHOT, diff->file_origin);
        return -1;
    } else if (syscheck.disk_quota_enabled) {
        unsigned int zip_size = FileSize(diff->compress_tmp_file) / 1024;

        if (syscheck.diff_folder_size + zip_size > syscheck.disk_quota_limit) {
            if (syscheck.disk_quota_full_msg) {
                syscheck.disk_quota_full_msg = false;
                mdebug2(FIM_DISK_QUOTA_LIMIT_REACHED, DIFF_DIR_PATH);
            }
            fim_diff_modify_compress_estimation(zip_size, diff->file_size);
            return -1;
        }
    }

    return 0;
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

int fim_diff_compare(diff_data *diff) {
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

char *fim_diff_generate(diff_data *diff) {
    char diff_cmd[PATH_MAX * 3 + OS_SIZE_1024];
    char *diff_str = NULL;
    char *uncompress_file_filtered = NULL;
    char *file_origin_filtered = NULL;
    char *diff_file_filtered = NULL;
    int status = -1;

    uncompress_file_filtered = filter(diff->uncompress_file);
    file_origin_filtered = filter(diff->file_origin);
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

    if (status == 1){
        diff_str = gen_diff_str(diff);
    } else if (status == 0){
        mdebug2(FIM_DIFF_COMMAND_OUTPUT_EQUAL);
    } else {
        merror(FIM_DIFF_COMMAND_OUTPUT_ERROR);
    }

    return diff_str;
}

char *gen_diff_str(diff_data *diff){
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

    switch (n) {
    case 0:
        merror(FIM_ERROR_GENDIFF_READ);
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
        return NULL;
    }

    // On Windows we handle long diffs after adapting the fc output.

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

#else
    os_strdup(buf, diff_str);
#endif

    return diff_str;
}

void save_compress_file(diff_data *diff){
    if (rename_ex(diff->compress_tmp_file, diff->compress_file) != 0) {
        merror(RENAME_ERROR, diff->compress_tmp_file, diff->compress_file, errno, strerror(errno));
        return;
    }
    if (syscheck.disk_quota_enabled){
        syscheck.diff_folder_size += FileSize(diff->compress_file) / 1024;
    }
    return;
}

int is_file_nodiff(const char *filename){
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

#ifdef WIN32
int is_registry_nodiff(const char *key_name, const char *value_name, int arch){
    char *full_value_name = NULL;

    os_malloc(sizeof(char) * (strlen(key_name) + strlen(value_name) + 2), full_value_name);

    snprintf(full_value_name, PATH_MAX, "%s\\%s", key_name, value_name);

    if (syscheck.registry_nodiff){
        int i;
        for (i = 0; syscheck.registry_nodiff[i].entry != NULL; i++){
            if ((strcmp(syscheck.registry_nodiff[i].entry, full_value_name)) == 0
                && syscheck.registry_nodiff[i].arch == arch) {
                os_free(full_value_name);
                return (TRUE);
            }
        }
    }
    if (syscheck.registry_nodiff_regex) {
        int i;
        for (i = 0; syscheck.registry_nodiff_regex[i].regex != NULL; i++) {
            if (OSMatch_Execute(full_value_name, strlen(full_value_name), syscheck.registry_nodiff_regex[i].regex)
                && syscheck.registry_nodiff_regex[i].arch == arch) {
                os_free(full_value_name);
                return (TRUE);
            }
        }
    }

    os_free(full_value_name);
    return (FALSE);
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

int fim_diff_process_delete_file(char *filename){
    char *full_path;
    os_malloc(sizeof(char) * (strlen(DIFF_DIR_PATH) + strlen(filename) + 8), full_path);
    snprintf(full_path, PATH_MAX, "%s/local/", DIFF_DIR_PATH);

#ifdef WIN32
    // Remove ":" from filename
    char *buffer = NULL;
    buffer = os_strip_char(filename, ':');
    if(buffer == NULL) {
        merror(FIM_ERROR_REMOVE_COLON, filename);
        os_free(full_path);
        return -1;
    }
    strcat(full_path, buffer);
    os_free(buffer);
#else
    strcat(full_path, filename);
#endif


    if(fim_diff_delete_compress_folder(full_path) == -1){
        merror(FIM_DIFF_DELETE_DIFF_FOLDER_ERROR, full_path);
        os_free(full_path);
        return -1;
    }

    os_free(full_path);
    return 0;
}

#ifdef WIN32

int fim_diff_process_delete_registry(char *key_name, int arch){
    char *full_path;
    os_sha1 encoded_key;
    OS_SHA1_Str(key_name, strlen(key_name), encoded_key);

    os_malloc(sizeof(char) * (strlen(DIFF_DIR_PATH) + 34), full_path);

    if (arch){
        snprintf(full_path, PATH_MAX, "%s/registry/[x64] %s", DIFF_DIR_PATH, encoded_key);
    } else {
        snprintf(full_path, PATH_MAX, "%s/registry/[x32] %s", DIFF_DIR_PATH, encoded_key);
    }

    if(fim_diff_delete_compress_folder(full_path) == -1){
        os_free(full_path);
        return -1;
    }

    os_free(full_path);
    return 0;
}

int fim_diff_process_delete_value(char *key_name, char *value_name, int arch){
    char *full_path;
    os_sha1 encoded_key;
    os_sha1 encoded_value;
    OS_SHA1_Str(key_name, strlen(key_name), encoded_key);
    OS_SHA1_Str(value_name, strlen(value_name), encoded_value);

    os_malloc(sizeof(char) * (strlen(DIFF_DIR_PATH) + 55), full_path);

    if (arch){
        snprintf(full_path, PATH_MAX, "%s/registry/[x64] %s/%s", DIFF_DIR_PATH, encoded_key, encoded_value);
    } else {
        snprintf(full_path, PATH_MAX, "%s/registry/[x32] %s/%s", DIFF_DIR_PATH, encoded_key, encoded_value);
    }

    if(fim_diff_delete_compress_folder(full_path) == -1){
        os_free(full_path);
        return -1;
    }

    os_free(full_path);
    return 0;
}

#endif
