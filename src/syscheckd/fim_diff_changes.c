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
//TODO description
/**
 * @brief
 *
 * @param encoded_key
 * @param encoded_value
 * @param configuration
 *
 * @return diff_data structure
 */
diff_data *initialize_registry_diff_data(
        char *encoded_key,
        char *encoded_value,
        registry *configuration);

//TODO description
/**
 * @brief
 *
 * @param key_name
 * @param value_name
 * @param value_data
 * @param data_type
 * @param diff
 *
 * @return -1 on error 0 on success
 */
int fim_diff_registry_tmp(char *key_name,
                          char *value_name,
                          char *value_data,
                          DWORD data_type,
                          diff_data *diff);

#endif

//TODO description
/**
 * @brief
 *
 * @param filename
 *
 * @return diff_data structure
 */
diff_data *initialize_file_diff_data(char *filename);

//TODO description
/**
 * @brief
 *
 * @param diff
 *
 * @return diff_data structure
 */
void free_diff_data(diff_data *diff);

//TODO description
/**
 * @brief
 *
 * @param diff
 *
 * @return diff_data structure
 */
bool fim_diff_check_limits(diff_data *diff);

//TODO description
/**
 * @brief
 *
 * @param diff
 *
 * @return
 */
char *fim_diff_check_file(diff_data *diff);

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
int fim_diff_create_compress(diff_data *diff);

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
char *gen_diff_str(diff_data *diff, __attribute__((unused)) int status);

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

char *fim_registry_value_diff(char *key_name,
                              char *value_name,
                              char *value_data,
                              DWORD data_type,
                              registry registry) {

    os_sha1 encoded_key;
    os_sha1 encoded_value;
    char *diff_changes = NULL;
    bool reach_limit;

    // Invalid types for report_changes
    if (data_type == REG_NONE || data_type == REG_BINARY || data_type == REG_LINK ||
        data_type == REG_RESOURCE_LIST || data_type == REG_FULL_RESOURCE_DESCRIPTOR ||
        data_type == REG_RESOURCE_REQUIREMENTS_LIST) {
            return NULL;
    }

    OS_SHA1_Str(key_name, strlen(key_name), encoded_key);
    OS_SHA1_Str(value_name, strlen(value_name), encoded_value);

    // Generate diff structure
    diff_data *diff = initialize_registry_diff_data(encoded_key, encoded_value);

    // Create tmp directory and file with de content of the registry
    fim_diff_registry_tmp(key_name, value_name, value_data, data_type, diff);

    // Check for file limit and disk quota
    if (reach_limit = fim_diff_check_limits(diff), reach_limit) {
        goto cleanup;
    }

    // If the file is not there, create compressed file and return.
    if (w_uncompress_gzfile(diff->compress_file, diff->uncompress_file) != 0) {
        fim_diff_create_compress(diff);
        goto cleanup;
    } else { // If it exists, subtract the size, create the new compressed file
             // (if disk_quota allows) and continue with the comparison
        float backup_file_size = (FileSize(diff->compress_file) / 1024);
        syscheck.diff_folder_size -= backup_file_size;

        if (fim_diff_create_compress(diff) == -1) {
            syscheck.diff_folder_size += backup_file_size;
            goto cleanup;
        }

    }

    if (fim_diff_compare(diff) == -1) {
        goto cleanup;
    }

    diff_changes = fim_diff_generate(diff);


cleanup:

    if (rmdir_ex(diff->tmp_folder) < 0) {
        mdebug2(RMDIR_ERROR, diff->tmp_folder, errno, strerror(errno));
    }

    // Remove key_folder only if empty
    char key_folder[PATH_MAX + 1];

    snprintf(
        key_folder,
        PATH_MAX,
        "%s/registry/%s",
        DIFF_DIR_PATH,
        encoded_key
    );
    if (rmdir(key_folder) < 0) {
        mdebug2(RMDIR_ERROR, key_folder, errno, strerror(errno));
    }

    free_diff_data(diff);

    return diff_changes;
}


diff_data *initialize_registry_diff_data(
            char *encoded_key,
            char *encoded_value,
            registry *configuration){

    diff_data *diff;
    char buffer[PATH_MAX + 1];
    char abs_diff_dir_path[PATH_MAX + 1];

    os_calloc(1, sizeof(diff_data), diff);

    diff->file_size = 0;
    diff->size_limit = configuration->diff_size_limit;

    abspath(DIFF_DIR_PATH, abs_diff_dir_path, sizeof(abs_diff_dir_path));

    snprintf(
        buffer,
        PATH_MAX,
        "%s/registry/%s/%s",
        abs_diff_dir_path,
        encoded_key,
        encoded_value
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
        "%s/%s%s",
        diff->tmp_folder,
        encoded_key,
        encoded_value
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

    return diff;
}

int fim_diff_registry_tmp(os_sha1 encoded_key,
                          os_sha1 encoded_value,
                          char *value_data,
                          DWORD data_type,
                          diff_data *diff) {

    char buffer[PATH_MAX + 1];
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
                aux_data = value_data;
                while (*value_data) {
                    //TODO
                }
                fprintf(fp, "%04x", *((unsigned int*)aux_data));
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
        merror(FOPEN_ERROR, diff->file_origin, errno, strerror(errno));
        return -1;
    }

    fclose(fp);
    return 0;
}

#endif

//TODO: Restruct file trace
char *fim_file_diff(char *filename) {

    char *diff_changes = NULL;
    bool reach_limit;

    // Generate diff structure
    diff_data *diff = initialize_file_diff_data(filename);


    mkdir_ex(diff->tmp_folder);

    // Check for file limit and disk quota
    if (reach_limit = fim_diff_check_limits(diff), reach_limit) {
        goto cleanup;
    }

    // If the file is not there, create compressed file and return.
    if (w_uncompress_gzfile(diff->compress_file, diff->uncompress_file) != 0) {
        fim_diff_create_compress(diff);
        goto cleanup;
    } else { // If it exists, subtract the size, create the new compressed file
             // (if disk_quota allows) and continue with the comparison
        float backup_file_size = (FileSize(diff->compress_file) / 1024);
        syscheck.diff_folder_size -= backup_file_size;

        if (fim_diff_create_compress(diff) == -1) {
            syscheck.diff_folder_size += backup_file_size;
            goto cleanup;
        }

    }

    if (fim_diff_compare(diff) == -1) {
        goto cleanup;
    }

    diff_changes = fim_diff_generate(diff);


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
        merror("Cannot get absolute path of '%s': %s (%d)", filename, strerror(errno), errno);
        return NULL;
    }
    os_strdup(buffer, diff->file_origin);

#ifdef WIN32
    // Remove ":" from filename
    filename = os_strip_char(diff->file_origin, ':');

    if (filename_strip == NULL) {
        merror("Cannot remove heading colon from full path '%s'", diff->file_origin);
        return diff;
    }

    // Get cwd for Windows
    abspath(DIFF_DIR_PATH, abs_diff_dir_path, sizeof(abs_diff_dir_path));
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

bool fim_diff_check_limits(diff_data *diff) {
    float file_size = 0;

    diff->file_size = (float)FileSize(diff->file_origin) / 1024;

    if (syscheck.file_size_enabled) {
        if (diff->file_size > diff->size_limit) {
            // TODO: get real name for registry key and value
            mdebug2(FIM_BIG_FILE_REPORT_CHANGES, diff->file_origin);
            fim_diff_delete_compress_folder(diff->compress_folder);
            return true;
        }
    }

    // Estimate if the file could fit in the disk_quota limit. If not, return.
    if (syscheck.disk_quota_enabled && !fim_diff_estimate_compression(diff->file_size)) {
        // TODO: check that, when the quota is exceeded, the last backup of the file that could be stored is kept
        return true;
    }

    return false;
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

int fim_diff_estimate_compression(const float file_size) {
    float compressed_estimation = 0.0;
    int result = -1;

    compressed_estimation = file_size - (syscheck.comp_estimation_perc * file_size);
    result = (syscheck.diff_folder_size + compressed_estimation) <= syscheck.disk_quota_limit;

    return result;
}


int fim_diff_create_compress(diff_data *diff) {
    unsigned int zip_size = 0;

    if (w_compress_gzfile(diff->file_origin, diff->compress_tmp_file) != 0) {
        mwarn(FIM_WARN_GENDIFF_SNAPSHOT, diff->file_origin);
        return -1;
    } else if (syscheck.disk_quota_enabled) {
        zip_size = FileSize(diff->compress_tmp_file) / 1024;

        if (syscheck.diff_folder_size + zip_size <= syscheck.disk_quota_limit) {
            mkdir_ex(diff->compress_folder);

            if (rename_ex(diff->compress_tmp_file, diff->compress_file) != 0) {
                mdebug2(RENAME_ERROR, diff->compress_tmp_file, diff->compress_file, errno, strerror(errno));
                return -1;
            }
            syscheck.diff_folder_size += zip_size;

        } else {
            if (syscheck.disk_quota_full_msg) {
                syscheck.disk_quota_full_msg = false;
                mdebug2(FIM_DISK_QUOTA_LIMIT_REACHED, DIFF_DIR_PATH);
            }
            fim_diff_modify_compress_estimation(zip_size, diff->file_size);
            return -1;
        }
    } else {
        if (rename_ex(diff->compress_tmp_file, diff->compress_file) != 0) {
            mdebug2(RENAME_ERROR, diff->compress_tmp_file, diff->compress_file, errno, strerror(errno));
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

    if (is_nodiff(diff->file_origin)) {
        /* Dont leak sensible data with a diff hanging around */
        FILE *fdiff;
        char* nodiff_message = "<Diff truncated because nodiff option>";

        fdiff = wfopen(diff->diff_file, "wb");
        if (!fdiff){
            merror(FIM_ERROR_GENDIFF_OPEN_FILE, diff->diff_file);
            return NULL;
        }

        if (fwrite(nodiff_message, strlen(nodiff_message) + 1, 1, fdiff) < 1) {
            merror(FIM_ERROR_GENDIFF_WRITING_DATA, diff->diff_file);
            fclose(fdiff);
            return NULL;
        }

        fclose(fdiff);
        status = 1;
    } else {
        /* OK, run diff */
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
    }

    if (status == 1){
        diff_str = gen_diff_str(diff, status);
    } else if (status != 0){
        //TODO
        merror("Diff command error");
    }

    return diff_str;
}

char *gen_diff_str(diff_data *diff, int status){
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
        return NULL;
    }

    return diff_str;
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
