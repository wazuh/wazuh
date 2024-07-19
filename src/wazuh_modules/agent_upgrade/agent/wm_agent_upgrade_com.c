/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC

#ifdef WIN32
#include "unit_tests/wrappers/windows/io_wrappers.h"
#endif

#else
#define STATIC static
#endif

#include <shared.h>
#include "external/zlib/zlib.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/signature/signature.h"
#include "wazuh_modules/wmodules.h"
#include "wm_agent_upgrade_agent.h"

/**
 * Static struct to track opened file
 * */
STATIC struct {
    char path[PATH_MAX + 1];
    FILE * fp;
} file = {"\0", NULL};

typedef enum _command_error_codes {
    ERROR_OK = 0,
    ERROR_UPGRADES_NOT_ALLOWED,
    ERROR_UNKNOWN_COMMAND,
    ERROR_PARAMETERS_NOT_FOUND,
    ERROR_UNSOPPORTED_MODE,
    ERROR_INVALID_FILE_NAME,
    ERROR_FILE_OPEN,
    ERROR_FILE_NOT_OPENED,
    ERROR_FILE_NOT_OPENED2,
    ERROR_TARGET_FILE_NOT_MATCH,
    ERROR_WRITE_FILE,
    ERROR_CLOSE,
    ERROR_GEN_SHA1,
    ERROR_SIGNATURE,
    ERROR_COMPRESS,
    ERROR_CLEAN_DIRECTORY,
    ERROR_UNMERGE,
    ERROR_CHMOD,
    ERROR_EXEC,
    ERROR_CLEAR_UPGRADE_FILE
} command_error_codes;

STATIC const char * error_messages[] = {
    [ERROR_OK] = "ok",
    [ERROR_UPGRADES_NOT_ALLOWED] = "Upgrade module is disabled or not ready yet",
    [ERROR_UNKNOWN_COMMAND] = "Command not found",
    [ERROR_PARAMETERS_NOT_FOUND] = "Required parameters were not found",
    [ERROR_UNSOPPORTED_MODE] = "Unsupported file mode",
    [ERROR_INVALID_FILE_NAME] = "Invalid file name",
    [ERROR_FILE_OPEN] = "File Open Error: %s",
    [ERROR_FILE_NOT_OPENED] = "File not opened. Agent might have been auto-restarted during upgrade",
    [ERROR_FILE_NOT_OPENED2] = "No file opened",
    [ERROR_TARGET_FILE_NOT_MATCH] = "The target file doesn't match the opened file",
    [ERROR_WRITE_FILE] = "Cannot write file",
    [ERROR_CLOSE] = "Cannot close file",
    [ERROR_GEN_SHA1] = "Cannot generate SHA1",
    [ERROR_SIGNATURE] = "Could not verify signature",
    [ERROR_COMPRESS] = "Could not uncompress package",
    [ERROR_CLEAN_DIRECTORY] = "Could not clean up upgrade directory",
    [ERROR_UNMERGE] = "Error unmerging file",
    [ERROR_CHMOD] = "Could not chmod",
    [ERROR_EXEC] = "Error executing command",
    [ERROR_CLEAR_UPGRADE_FILE] = "Could not erase upgrade_result file"
};

// Variable used to allow new upgrades after confirming the result of the previous upgrade
bool allow_upgrades = false;

/**
 * Format message into the response format
 * @param error_code code error
 * @param message string message of the error
 * @return string meessage with the response format
 * Response format:
 * {
 *    "error": {error_code},
 *    "message": "message",
 *    "data": []
 * }
 * */
STATIC char* wm_agent_upgrade_command_ack(int error_code, const char* message);

/**
 * Process a command that opens a file
 * @param json_obj expected json format parameters
 * {
 *    "file":    "file_path",
 *    "mode":    "wb|w"
 * }
 * */
STATIC char* wm_agent_upgrade_com_open(const cJSON* json_object) __attribute__((nonnull));

/**
 * Process a command that writes on an already opened file
 * @param json_obj expected json format
 * {
 *    "file":    "file_path",
 *    "buffer" : "base64_data",
 *    "length" : {data_length}
 * }
 * */
STATIC char * wm_agent_upgrade_com_write(const cJSON* json_object) __attribute__((nonnull));

/**
 * Process a command the close an already opened file
 * @param json_obj expected json format
 * {
 *    "file" : "file_path"
 * }
 * */
STATIC char * wm_agent_upgrade_com_close(const cJSON* json_object) __attribute__((nonnull));

/**
 * Process a command that calculates the sha1 already opened file
 * @param json_obj expected json format
 * {
 *    "file" : "file_path"
 * }
 * */
STATIC char * wm_agent_upgrade_com_sha1(const cJSON* json_object) __attribute__((nonnull));

/**
 * Process a command that executes an upgrade script
 * @param json_obj expected json format
 * {
 *    "file" : "file_path",
 *    "installer" : "installer_path"
 * }
 * */
STATIC char * wm_agent_upgrade_com_upgrade(const cJSON* json_object) __attribute__((nonnull));

/**
 * Process a command that clears the upgrade_result file
 * */
STATIC char * wm_agent_upgrade_com_clear_result();

/* Helpers methods */
STATIC int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename);
STATIC int _unsign(const char * source, char dest[PATH_MAX + 1]);
STATIC int _uncompress(const char * source, const char *package, char dest[PATH_MAX + 1]);

size_t wm_agent_upgrade_process_command(const char *buffer, char **output) {
    cJSON *buffer_obj = cJSON_Parse(buffer);

    if (buffer_obj) {
        cJSON *command_obj = cJSON_GetObjectItem(buffer_obj, task_manager_json_keys[WM_TASK_COMMAND]);

        if (command_obj && (command_obj->type == cJSON_String)) {
            const char* command = command_obj->valuestring;

            if (strcmp(command, "clear_upgrade_result") == 0) {
                *output = wm_agent_upgrade_com_clear_result();
            } else if (allow_upgrades) {
                const cJSON *parameters = cJSON_GetObjectItem(buffer_obj, task_manager_json_keys[WM_TASK_PARAMETERS]);
                if (!parameters) {
                    *output = wm_agent_upgrade_command_ack(ERROR_PARAMETERS_NOT_FOUND, error_messages[ERROR_PARAMETERS_NOT_FOUND]);
                } else if (strcmp(command, "open") == 0) {
                    *output = wm_agent_upgrade_com_open(parameters);
                } else if (strcmp(command, "write") == 0) {
                    *output = wm_agent_upgrade_com_write(parameters);
                } else if (strcmp(command, "close") == 0) {
                    *output = wm_agent_upgrade_com_close(parameters);
                } else if (strcmp(command, "sha1") == 0) {
                    *output = wm_agent_upgrade_com_sha1(parameters);
                } else if (strcmp(command, "upgrade") == 0) {
                    *output = wm_agent_upgrade_com_upgrade(parameters);
                }
            } else {
                *output = wm_agent_upgrade_command_ack(ERROR_UPGRADES_NOT_ALLOWED, error_messages[ERROR_UPGRADES_NOT_ALLOWED]);
            }
        }

        cJSON_Delete(buffer_obj);
    }

    if (!(*output)) {
       *output = wm_agent_upgrade_command_ack(ERROR_UNKNOWN_COMMAND, error_messages[ERROR_UNKNOWN_COMMAND]);
    }

    return strlen(*output);
}

STATIC char* wm_agent_upgrade_command_ack(int error_code, const char* message) {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, task_manager_json_keys[WM_TASK_ERROR], error_code);
    cJSON_AddStringToObject(root, task_manager_json_keys[WM_TASK_ERROR_MESSAGE], message);
    cJSON_AddItemToObject(root, task_manager_json_keys[WM_TASK_DATA], cJSON_CreateArray());
    char *msg_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return msg_string;
}

STATIC char * wm_agent_upgrade_com_open(const cJSON* json_object) {
    char final_path[PATH_MAX + 1];
    const cJSON *mode_obj = cJSON_GetObjectItem(json_object, "mode");
    const cJSON *file_path_obj = cJSON_GetObjectItem(json_object, "file");

    if (*file.path) {
        mtwarn(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_FILE_OPENED, "open", file.path);
        fclose(file.fp);
        *file.path = '\0';
    }

    if (!mode_obj || (mode_obj->type != cJSON_String) || (strcmp(mode_obj->valuestring, "w") && strcmp(mode_obj->valuestring, "wb"))) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNSUPPORTED_MODE, "open");
        return wm_agent_upgrade_command_ack(ERROR_UNSOPPORTED_MODE, error_messages[ERROR_UNSOPPORTED_MODE]);
    }

    if (!file_path_obj || (file_path_obj->type != cJSON_String) || _jailfile(final_path, INCOMING_DIR, file_path_obj->valuestring) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "open");
        return wm_agent_upgrade_command_ack(ERROR_INVALID_FILE_NAME, error_messages[ERROR_INVALID_FILE_NAME]);
    }

    if (file.fp = wfopen(final_path, mode_obj->valuestring), file.fp) {
        snprintf(file.path, sizeof(file.path), "%s", final_path);
        return wm_agent_upgrade_command_ack(ERROR_OK, error_messages[ERROR_OK]);
    } else {
        mterror(WM_AGENT_UPGRADE_LOGTAG, FOPEN_ERROR, file_path_obj->valuestring, errno, strerror(errno));
        char *output;
        os_malloc(OS_MAXSTR + 1, output);
        snprintf(output, OS_MAXSTR + 1, error_messages[ERROR_FILE_OPEN], strerror(errno));
        char *response = wm_agent_upgrade_command_ack(ERROR_FILE_OPEN, output);
        os_free(output);
        return response;
    }
}

STATIC char * wm_agent_upgrade_com_write(const cJSON* json_object) {
    const cJSON *file_path_obj = cJSON_GetObjectItem(json_object, "file");
    const cJSON *buffer_obj = cJSON_GetObjectItem(json_object, "buffer");
    const cJSON *value_obj = cJSON_GetObjectItem(json_object, "length");
    char final_path[PATH_MAX + 1];

    if (!*file.path) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_FILE_NOT_OPENED_AUTO, "write");
        return wm_agent_upgrade_command_ack(ERROR_FILE_NOT_OPENED, error_messages[ERROR_FILE_NOT_OPENED]);
    }

    if (!file_path_obj || (file_path_obj->type != cJSON_String) || _jailfile(final_path, INCOMING_DIR, file_path_obj->valuestring) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "write");
        return wm_agent_upgrade_command_ack(ERROR_INVALID_FILE_NAME, error_messages[ERROR_INVALID_FILE_NAME]);
    }

    if (strcmp(file.path, final_path) != 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_DIFFERENT_FILE, "write", file.path);
        return wm_agent_upgrade_command_ack(ERROR_TARGET_FILE_NOT_MATCH, error_messages[ERROR_TARGET_FILE_NOT_MATCH]);
    }

    char *base64_string = decode_base64(buffer_obj->valuestring);
    if (value_obj && (value_obj->type == cJSON_Number) && base64_string && fwrite(base64_string, 1, value_obj->valueint, file.fp) == (unsigned)value_obj->valueint) {
        os_free(base64_string);
        return wm_agent_upgrade_command_ack(ERROR_OK, error_messages[ERROR_OK]);
    } else {
        os_free(base64_string);
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_CANNOT_WRITE, "write", final_path);
        return wm_agent_upgrade_command_ack(ERROR_WRITE_FILE, error_messages[ERROR_WRITE_FILE]);
    }
}

STATIC char * wm_agent_upgrade_com_close(const cJSON* json_object) {
    const cJSON *file_path_obj = cJSON_GetObjectItem(json_object, "file");
    char final_path[PATH_MAX + 1];

    if (!*file.path) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_FILE_NOT_OPENED, "close");
        return wm_agent_upgrade_command_ack(ERROR_FILE_NOT_OPENED2, error_messages[ERROR_FILE_NOT_OPENED2]);
    }

    if (!file_path_obj || (file_path_obj->type != cJSON_String) || _jailfile(final_path, INCOMING_DIR, file_path_obj->valuestring) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "close");
        return wm_agent_upgrade_command_ack(ERROR_INVALID_FILE_NAME, error_messages[ERROR_INVALID_FILE_NAME]);
    }

    if (strcmp(file.path, final_path) != 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_DIFFERENT_FILE, "close", file.path);
        return wm_agent_upgrade_command_ack(ERROR_TARGET_FILE_NOT_MATCH, error_messages[ERROR_TARGET_FILE_NOT_MATCH]);
    }

    *file.path = '\0';

    if (fclose(file.fp)) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_GERENIC_ERROR, "close", strerror(errno));
        return wm_agent_upgrade_command_ack(ERROR_CLOSE, error_messages[ERROR_CLOSE]);
    }

    return wm_agent_upgrade_command_ack(ERROR_OK, error_messages[ERROR_OK]);
}

STATIC char * wm_agent_upgrade_com_sha1(const cJSON* json_object) {
    const cJSON *file_path_obj = cJSON_GetObjectItem(json_object, "file");
    char final_path[PATH_MAX + 1];
    os_sha1 sha1;

    if (!file_path_obj || (file_path_obj->type != cJSON_String) || _jailfile(final_path, INCOMING_DIR, file_path_obj->valuestring) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "sha1");
        return wm_agent_upgrade_command_ack(ERROR_INVALID_FILE_NAME, error_messages[ERROR_INVALID_FILE_NAME]);
    }

    if (OS_SHA1_File(final_path, sha1, OS_BINARY) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_GENERATING_SHA1_ERROR, "sha1");
        return wm_agent_upgrade_command_ack(ERROR_GEN_SHA1, error_messages[ERROR_GEN_SHA1]);
    }

    return wm_agent_upgrade_command_ack(ERROR_OK, sha1);
}

STATIC char * wm_agent_upgrade_com_upgrade(const cJSON* json_object) {
    char compressed[PATH_MAX + 1];
    char merged[PATH_MAX + 1];
    char installer_j[PATH_MAX + 1];
    const cJSON *package_obj = cJSON_GetObjectItem(json_object, "file");
    const cJSON *installer_obj = cJSON_GetObjectItem(json_object, "installer");
    int status = 0;
    char *out;

    int req_timeout = getDefine_Int("execd", "request_timeout", 1, 3600);

    // Unsign
    if (!package_obj || (package_obj->type != cJSON_String) || _unsign(package_obj->valuestring, compressed) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_GERENIC_ERROR, "upgrade", error_messages[ERROR_SIGNATURE]);
        return wm_agent_upgrade_command_ack(ERROR_SIGNATURE, error_messages[ERROR_SIGNATURE]);
    }

    // Uncompress
    if (_uncompress(compressed, package_obj->valuestring, merged) < 0) {
        unlink(compressed);
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_GERENIC_ERROR, "upgrade", error_messages[ERROR_COMPRESS]);
        return wm_agent_upgrade_command_ack(ERROR_COMPRESS, error_messages[ERROR_COMPRESS]);
    }

    // Clean up upgrade folder
    if (cldir_ex(UPGRADE_DIR)) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_GERENIC_ERROR, "upgrade", error_messages[ERROR_CLEAN_DIRECTORY]);
        return wm_agent_upgrade_command_ack(ERROR_CLEAN_DIRECTORY, error_messages[ERROR_CLEAN_DIRECTORY]);
    }

    //Unmerge
    if (UnmergeFiles(merged, UPGRADE_DIR, OS_BINARY, NULL) == 0) {
        unlink(merged);
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNMERGING_FILE_ERROR, "upgrade", merged);
        return wm_agent_upgrade_command_ack(ERROR_UNMERGE, error_messages[ERROR_UNMERGE]);
    }

    unlink(merged);

    // Installer executable file
    if (!installer_obj || (installer_obj->type != cJSON_String) || _jailfile(installer_j, UPGRADE_DIR, installer_obj->valuestring) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "upgrade");
        return wm_agent_upgrade_command_ack(ERROR_INVALID_FILE_NAME, error_messages[ERROR_INVALID_FILE_NAME]);
    }

    // Execute
#ifndef WIN32
    if (chmod(installer_j, 0750) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_CHMOD_ERROR, "upgrade", installer_j);
        return wm_agent_upgrade_command_ack(ERROR_CHMOD, error_messages[ERROR_CHMOD]);
    }
#endif

    if (wm_exec(installer_j, &out, &status, req_timeout, NULL) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMMAND_ERROR, "upgrade", installer_j);
        os_free(out);
        return wm_agent_upgrade_command_ack(ERROR_EXEC, error_messages[ERROR_EXEC]);
    } else {
        char status_str[5];
        sprintf(status_str, "%d", status);
        os_free(out);
        return wm_agent_upgrade_command_ack(ERROR_OK, status_str);
    }
}

STATIC char * wm_agent_upgrade_com_clear_result() {
    const char * PATH = WM_AGENT_UPGRADE_RESULT_FILE;
    if (remove(PATH) == 0) {
        allow_upgrades = true;
        return wm_agent_upgrade_command_ack(ERROR_OK, error_messages[ERROR_OK]);
    } else {
        mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_ERASE_FILE_ERROR, "clear_upgrade_result", PATH);
        return wm_agent_upgrade_command_ack(ERROR_CLEAR_UPGRADE_FILE, error_messages[ERROR_CLEAR_UPGRADE_FILE]);
    }
}

STATIC int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename) {

    if (w_ref_parent_folder(filename)) {
        return -1;
    }

#ifndef WIN32
    return snprintf(finalpath, PATH_MAX + 1, "%s/%s", basedir, filename) > PATH_MAX ? -1 : 0;
#else
    return snprintf(finalpath, PATH_MAX + 1, "%s\\%s", basedir, filename) > PATH_MAX ? -1 : 0;
#endif
}

STATIC int _unsign(const char * source, char dest[PATH_MAX + 1]) {
    const char TEMPLATE[] = ".gz.XXXXXX";
    char source_j[PATH_MAX + 1];
    size_t length;
    int output = 0;

    if (_jailfile(source_j, INCOMING_DIR, source) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "unsign()");
        return -1;
    }

    if (_jailfile(dest, TMP_DIR, source) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "unsign()");
        return -1;
    }

    // Skipping coverage: In the linux case, the difference between TMP_DIR and INCOMING_DIR is exactly 10
    // which causes an error in the _jailfile instead of here
    // LCOV_EXCL_START
    if (length = strlen(dest), length + 10 > PATH_MAX) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_TOO_LONG_TEMP_FILE, "unsign()");
        return -1;
    }
    // LCOV_EXCL_STOP

    memcpy(dest + length, TEMPLATE, sizeof(TEMPLATE));
    mode_t old_mask = umask(0022);
#ifndef WIN32
    int fd;

    if (fd = mkstemp(dest), fd >= 0) {
        close(fd);

        if (chmod(dest, 0640) < 0) {
            unlink(dest);
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_CHMOD_ERROR, "unsign()", dest);
            output = -1;
        }
    } else {
#else
    if (_mktemp_s(dest, strlen(dest) + 1)) {
#endif
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_COMPRESSED_FILE_ERROR, "unsign()");
        output = -1;
    }

    if ((output == 0) && w_wpk_unsign(source_j, dest, (const char **)wcom_ca_store) < 0) {
        unlink(dest);
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_UNSIGN_FILE_ERROR, "unsign()", source_j);
        output = -1;
    }
    umask(old_mask);
    unlink(source);
    return output;
}

STATIC int _uncompress(const char * source, const char *package, char dest[PATH_MAX + 1]) {
    const char TEMPLATE[] = ".mg.XXXXXX";
    char buffer[4096];
    gzFile fsource;
    FILE *ftarget;

    if (_jailfile(dest, TMP_DIR, package) < 0) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INVALID_FILE_NAME, "uncompress()");
        return -1;
    }

    {
        size_t length;

        if (length = strlen(dest), length + 10 > PATH_MAX) {
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_TOO_LONG_TEMP_FILE, "uncompress()");
            return -1;
        }

        memcpy(dest + length, TEMPLATE, sizeof(TEMPLATE));
    }

    if (fsource = gzopen(source, "rb"), !fsource) {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_FILE_OPEN_ERROR, "uncompress()", source);
        return -1;
    }

    if (ftarget = wfopen(dest, "wb"), !ftarget) {
        gzclose(fsource);
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_FILE_OPEN_ERROR, "uncompress()", dest);
        return -1;
    }

    {
        int length;

        while (length = gzread(fsource, buffer, sizeof(buffer)), length > 0) {
            if ((int)fwrite(buffer, 1, length, ftarget) != length) {
                unlink(dest);
                gzclose(fsource);
                fclose(ftarget);
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_CANNOT_WRITE, "uncompress()", source);
                return -1;
            }
        }

        gzclose(fsource);
        fclose(ftarget);

        if (length < 0) {
            unlink(dest);
            mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_CANNOT_READ, "uncompress()", source);
            return -1;
        }
    }

    unlink(source);
    return 0;
}
