/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "os_crypto/sha1/sha1_op.h"
#include "wazuh_modules/wmodules.h"
#include "wm_agent_upgrade_agent.h"

static struct {
    char path[PATH_MAX + 1];
    FILE * fp;
} file;

typedef enum _command_error_codes {
    ERROR_OK = 0,
    ERROR_UNSOPPORTED_MODE,
    ERROR_INVALID_FILE_NAME,
    ERROR_FILE_OPEN,
    ERROR_FILE_NOT_OPENED,
    ERROR_FILE_NOT_OPENED2,
    ERROR_TARGET_FILE_NOT_MATCH,
    ERROR_WRITE_FILE,
    ERROR_CLOSE,
    ERROR_GEN_SHA1
} command_error_codes;

static const char * error_messages[] = {
    [ERROR_OK] = "ok",
    [ERROR_UNSOPPORTED_MODE] = "Unsupported file mode",
    [ERROR_INVALID_FILE_NAME] = "Invalid File name",
    [ERROR_FILE_OPEN] = "File Open Error: %s",
    [ERROR_FILE_NOT_OPENED] = "File not opened. Agent might have been auto-restarted during upgrade",
    [ERROR_FILE_NOT_OPENED2] = "No file opened",
    [ERROR_TARGET_FILE_NOT_MATCH] = "The target file doesn't match the opened file",
    [ERROR_WRITE_FILE] = "Cannot write file",
    [ERROR_CLOSE] = "Cannot close file",
    [ERROR_GEN_SHA1] = "Cannot generate SHA1"
};

/**
 * Format message into the response format
 * @param error_code code error
 * @param message string message of the error
 * @return string meessage with the response format
 * Response format:
 * {
 *  "error": {error_code},
 *  "data": {message},
 * }
 * */
static char* wm_agent_upgrade_command_ack(int error_code, const char* message);

/**
 * Process a command that opens a file
 * @param json_obj expected json format
 * {
 *  "command": "open",
 *  "file":    "file_path",
 *  "mode":    "wb|w"
 * }
 * */
static char* wm_agent_upgrade_com_open(const cJSON* json_object);

/**
 * Process a command that writes on an already opened file
 * @param json_obj expected json format
 * {
 *  "command": "write",
 *  "buffer" : "{binary_data}",
 *  "length" : "{data_length}"
 * }
 * */
static char * wm_agent_upgrade_com_write(const cJSON* json_object);

/**
 * Process a command the close an already opened file
 * @param json_obj expected json format
 * {
 *  "command": "close",
 *  "file" : "file_path",
 * }
 * */
static char * wm_agent_upgrade_com_close(const cJSON* json_object);

/**
 * Process a command that calculates the sha1 already opened file
 * @param json_obj expected json format
 * {
 *  "command": "sha1",
 *  "file" : "file_path",
 * }
 * */
static char * wm_agent_upgrade_com_sha1(const cJSON* json_object);


/* Helpers methods */
static int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename);

char *wm_agent_upgrade_process_command(const char* buffer) {
    cJSON *buffer_obj = cJSON_Parse(buffer);
    if (buffer_obj) {
        cJSON *command_obj = cJSON_GetObjectItem(buffer_obj, "command");

        if (command_obj && (command_obj->type == cJSON_String)) {
            const char* command = command_obj->valuestring;
            if (strcmp(command, "open") == 0) {
                return wm_agent_upgrade_com_open(buffer_obj);
            } else if(strcmp(command, "write") == 0) { 
                return wm_agent_upgrade_com_write(buffer_obj);
            } else if(strcmp(command, "close") == 0) { 
                return wm_agent_upgrade_com_close(buffer_obj);
            } else if(strcmp(command, "sha1") == 0) {
                return wm_agent_upgrade_com_sha1(buffer_obj);
            }
        }
    }
    cJSON_Delete(buffer_obj);
}

static char* wm_agent_upgrade_command_ack(int error_code, const char* message) {
    cJSON* root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, task_manager_json_keys[WM_TASK_ERROR], error_code);
    cJSON_AddStringToObject(root, task_manager_json_keys[WM_TASK_DATA], strdup(message));
    char *msg_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return msg_string;
}

static char * wm_agent_upgrade_com_open(const cJSON* json_object) {
    char final_path[PATH_MAX + 1];
    const cJSON *mode_obj = cJSON_GetObjectItem(json_object, "mode");
    const cJSON *file_path_obj = cJSON_GetObjectItem(json_object, "file");

    if (*file.path) {
        merror("File '%s' was opened. Closing.", file.path);
        fclose(file.fp);
        *file.path = '\0';
    }

    if (!mode_obj || (mode_obj->type != cJSON_String) || (strcmp(mode_obj->valuestring, "w") && strcmp(mode_obj->valuestring, "wb"))) {
        merror("At WCOM open: Unsupported mode '%s'", mode_obj->valuestring);
        return wm_agent_upgrade_command_ack(ERROR_UNSOPPORTED_MODE, error_messages[ERROR_UNSOPPORTED_MODE]);
    }

    if (!file_path_obj || (file_path_obj->type != cJSON_String) || _jailfile(final_path, INCOMING_DIR, file_path_obj->valuestring) < 0) {
        merror("At WCOM open: Invalid file name");
        return wm_agent_upgrade_command_ack(ERROR_INVALID_FILE_NAME, error_messages[ERROR_INVALID_FILE_NAME]);
    }

    if (file.fp = fopen(file_path_obj->valuestring, mode_obj->valuestring), file.fp) {
        strncpy(file.path, file_path_obj->valuestring, PATH_MAX);
        return wm_agent_upgrade_command_ack(ERROR_OK, error_messages[ERROR_OK]);
    } else {
        merror(FOPEN_ERROR, file_path_obj->valuestring, errno, strerror(errno));
        char *output;
        os_malloc(OS_MAXSTR + 1, output);
        snprintf(output, OS_MAXSTR + 1, error_messages[ERROR_FILE_OPEN], strerror(errno));
        char *response = wm_agent_upgrade_command_ack(ERROR_FILE_OPEN, output);
        os_free(output);
        return response;
    }
}

static char * wm_agent_upgrade_com_write(const cJSON* json_object) {
    const cJSON *file_path_obj = cJSON_GetObjectItem(json_object, "file");
    const cJSON *buffer_obj = cJSON_GetObjectItem(json_object, "buffer");
    const cJSON *value_obj = cJSON_GetObjectItem(json_object, "length");
    char final_path[PATH_MAX + 1];

    if (!*file.path) {
        if (file_path_obj && (file_path_obj->type == cJSON_String) && file_path_obj->valuestring) {
            merror("At WCOM write: File not opened. Agent might have been auto-restarted during upgrade.");
            return wm_agent_upgrade_command_ack(ERROR_FILE_NOT_OPENED, error_messages[ERROR_FILE_NOT_OPENED]);
        }
        merror("At WCOM write: No file is opened.");
        return wm_agent_upgrade_command_ack(ERROR_FILE_NOT_OPENED2, error_messages[ERROR_FILE_NOT_OPENED2]);
    }

    if (!file_path_obj || (file_path_obj->type != cJSON_String) || _jailfile(final_path, INCOMING_DIR, file_path_obj->valuestring) < 0) {
        merror("At WCOM write: Invalid file name");
        return wm_agent_upgrade_command_ack(ERROR_INVALID_FILE_NAME, error_messages[ERROR_INVALID_FILE_NAME]);
    }

    if (strcmp(file.path, final_path) != 0) {
        merror("At WCOM write: The target file doesn't match the opened file (%s).", file.path);
        return wm_agent_upgrade_command_ack(ERROR_TARGET_FILE_NOT_MATCH, error_messages[ERROR_TARGET_FILE_NOT_MATCH]);
    }


    if (value_obj && (value_obj->type == cJSON_Number) && fwrite(buffer_obj->valuestring, 1, value_obj->valueint, file.fp) == (unsigned)value_obj->valueint) {
        return wm_agent_upgrade_command_ack(ERROR_OK, error_messages[ERROR_OK]);
    } else {
        merror("At WCOM write: Cannot write on '%s'", final_path);
        return wm_agent_upgrade_command_ack(ERROR_WRITE_FILE, error_messages[ERROR_WRITE_FILE]);
    }
}

static char * wm_agent_upgrade_com_close(const cJSON* json_object) {
    const cJSON *file_path_obj = cJSON_GetObjectItem(json_object, "file");

    if (!*file.path) {
        merror("At WCOM close: No file is opened.");
        return wm_agent_upgrade_command_ack(ERROR_FILE_NOT_OPENED2, error_messages[ERROR_FILE_NOT_OPENED2]);
    }
    
    if (!file_path_obj || (file_path_obj->type != cJSON_String) || _jailfile(file_path_obj->valuestring, INCOMING_DIR, file_path_obj->valuestring) < 0) {
        merror("At WCOM open: Invalid file name");
        return wm_agent_upgrade_command_ack(ERROR_INVALID_FILE_NAME, error_messages[ERROR_INVALID_FILE_NAME]);
    }

    if (strcmp(file.path, file_path_obj->valuestring) != 0) {
        merror("At WCOM close: The target file doesn't match the opened file (%s).", file.path);
        return wm_agent_upgrade_command_ack(ERROR_TARGET_FILE_NOT_MATCH, error_messages[ERROR_TARGET_FILE_NOT_MATCH]);
    }
     
    *file.path = '\0';

    if (fclose(file.fp)) {
        merror("At WCOM close: %s", strerror(errno));
        return wm_agent_upgrade_command_ack(ERROR_CLOSE, error_messages[ERROR_CLOSE]);
    }

    return wm_agent_upgrade_command_ack(ERROR_OK, error_messages[ERROR_OK]);
}

static char * wm_agent_upgrade_com_sha1(const cJSON* json_object) {
    const cJSON *file_path_obj = cJSON_GetObjectItem(json_object, "file");
    os_sha1 sha1;

    if (!file_path_obj || (file_path_obj->type != cJSON_String) || _jailfile(file_path_obj->valuestring, INCOMING_DIR, file_path_obj->valuestring) < 0) {
        merror("At WCOM open: Invalid file name");
        return wm_agent_upgrade_command_ack(ERROR_INVALID_FILE_NAME, error_messages[ERROR_INVALID_FILE_NAME]);
    }

    if (OS_SHA1_File(file_path_obj->valuestring, sha1, OS_BINARY) < 0) {
        merror("At WCOM sha1: Error generating SHA1.");
        return wm_agent_upgrade_command_ack(ERROR_GEN_SHA1, error_messages[ERROR_GEN_SHA1]);
    }

    return wm_agent_upgrade_command_ack(ERROR_OK, sha1);
}

static int _jailfile(char finalpath[PATH_MAX + 1], const char * basedir, const char * filename) {

    if (w_ref_parent_folder(filename)) {
        return -1;
    }

#ifndef WIN32
    return snprintf(finalpath, PATH_MAX + 1, "%s/%s/%s", isChroot() ? "" : DEFAULTDIR, basedir, filename) > PATH_MAX ? -1 : 0;
#else
    return snprintf(finalpath, PATH_MAX + 1, "%s\\%s", basedir, filename) > PATH_MAX ? -1 : 0;
#endif
}
