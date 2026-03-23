/* Remote request listener
 * Copyright (C) 2015, Wazuh Inc.
 * Mar 14, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "syscheck.h"
#include "rootcheck.h"
#include "os_net.h"
#include "wmodules.h"
#include "module_query_errors.h"
#include "db.h"
#include "agent_sync_protocol_c_interface.h"

#ifdef WAZUH_UNIT_TESTING
/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

/* FIM Agent Info Commands Implementation */

int fim_execute_pause(void) {
    mdebug1("FIM agent info: pause command received");

    // Check if already paused (atomic read, no mutex needed)
    if (atomic_int_get(&syscheck.fim_pause_requested)) {
        mdebug1("FIM scans are already paused or pause is in progress");
        return 0;
    }

    // Request pause (atomic write, no mutex needed)
    atomic_int_set(&syscheck.fim_pause_requested, 1);

    mdebug1("FIM pause requested (async), fim_pause_requested=1");
    return 0;
}

int fim_execute_is_pause_completed(void) {
    mdebug2("FIM agent info: is_pause_completed command received");

    // Read pause state atomically (no mutex needed)
    int pause_requested = atomic_int_get(&syscheck.fim_pause_requested);
    int pausing_is_allowed = atomic_int_get(&syscheck.fim_pausing_is_allowed);

    // If no pause was requested, return completed successfully (not in pause)
    if (!pause_requested) {
        mdebug2("No pause request active");
        return 0;  // Completed (not paused)
    }

    // Check if fim_run_integrity has acknowledged the pause
    if (!pausing_is_allowed) {
        mdebug2("Pause still in progress, waiting for fim_run_integrity to acknowledge");
        return 1;  // In progress
    }

    // Double-check pause state under mutex
    if (atomic_int_get(&syscheck.fim_pause_requested) && atomic_int_get(&syscheck.fim_pausing_is_allowed)) {
        w_mutex_lock(&syscheck.fim_scan_mutex);
        w_mutex_lock(&syscheck.fim_realtime_mutex);
#ifdef WIN32
        w_mutex_lock(&syscheck.fim_registry_scan_mutex);
#endif

        mdebug1("FIM scans successfully paused");
        return 0;  // Completed
    }

    return 1;  // State changed, still in progress
}

int fim_execute_flush(void) {
    mdebug1("FIM agent info: flush command received");

    if (!syscheck.enable_synchronization) {
        mdebug1("FIM synchronization is disabled, flush command skipped");
        return 0;
    }

    // Check if there's already a flush in progress (thread-safe read)
    if (atomic_int_get(&fim_flush_in_progress)) {
        mdebug1("Flush already in progress, request ignored");
        return 0;
    }

    // Reset previous result and activate flush (thread-safe write)
    atomic_int_set(&fim_flush_result, 0);
    atomic_int_set(&fim_flush_in_progress, 1);

    mdebug1("FIM flush requested (async), fim_flush_in_progress=1");
    return 0;
}

int fim_execute_is_flush_completed(void) {
    mdebug2("FIM agent info: is_flush_completed command received");

    if (!syscheck.enable_synchronization) {
        mdebug1("FIM synchronization is disabled");
        return 0;  // Return completed successfully (sync disabled)
    }

    // Read atomic variables (thread-safe read operations)
    int in_progress = atomic_int_get(&fim_flush_in_progress);
    int result = atomic_int_get(&fim_flush_result);

    mdebug2("Flush status check: fim_flush_in_progress=%d, fim_flush_result=%d",
            in_progress, result);

    if (in_progress) {
        mdebug2("Flush still in progress");
        return 1;  // In progress
    } else {
        mdebug1("Flush completed with result=%d", result);
        // Return the result directly: 0 = success, -1 = error
        return result;  // 0 = success, -1 = error
    }
}

int fim_execute_get_version(void) {
    mdebug1("FIM agent info: get_version command received");

    int max_version_file = fim_db_get_max_version_file();
    int max_version = max_version_file;

#ifdef WIN32
    int max_version_registry = fim_db_get_max_version_registry();
    max_version = (max_version_registry > max_version) ? max_version_registry : max_version;
#endif

    return max_version;
}

int fim_execute_set_version(int version) {
    mdebug1("FIM agent info: set_version command received, version=%d", version);

    int result_file = fim_db_set_version_file(version);

    if (result_file != 0) {
        merror("Failed to set version for file_entry table");
        return -1;
    }

#ifdef WIN32
    int result_registry = fim_db_set_version_registry(version);

    if (result_registry != 0) {
        merror("Failed to set version for registry tables");
        return -1;
    }
#endif

    mdebug1("FIM version set successfully to %d", version);
    return 0;
}

int fim_execute_resume(void) {
    mdebug1("FIM agent info: resume command received");

    // Check if actually paused (atomic read)
    if (!atomic_int_get(&syscheck.fim_pause_requested)) {
        mdebug1("FIM scans are not paused, resume command ignored");
        return 0;
    }

    // Double-check
    if (!atomic_int_get(&syscheck.fim_pause_requested)) {
        mdebug1("FIM scans are not paused, resume command ignored");
        return 0;
    }

    // Release all scan mutexes
#ifdef WIN32
    w_mutex_unlock(&syscheck.fim_registry_scan_mutex);
#endif
    w_mutex_unlock(&syscheck.fim_realtime_mutex);
    w_mutex_unlock(&syscheck.fim_scan_mutex);

    // Clear pause flags atomically
    atomic_int_set(&syscheck.fim_pausing_is_allowed, 0);
    atomic_int_set(&syscheck.fim_pause_requested, 0);

    mdebug1("FIM scans successfully resumed");
    return 0;
}

size_t syscom_getconfig(const char * section, char ** output) {
    assert(section != NULL);
    assert(output != NULL);

    cJSON *cfg;
    char *json_str;

    if (strcmp(section, "syscheck") == 0){
        if (cfg = getSyscheckConfig(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "rootcheck") == 0){
        if (cfg = getRootcheckConfig(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal") == 0){
        if (cfg = getSyscheckInternalOptions(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else {
        goto error;
    }
error:
    mdebug1(FIM_SYSCOM_FAIL_GETCONFIG, section);
    os_strdup("err Could not get requested section", *output);
    return strlen(*output);
}

size_t syscom_handle_agent_info_query(char * json_command, char ** output) {
    assert(json_command != NULL);
    assert(output != NULL);

    // Log received query
    mdebug1("Received query: %s", json_command);

    // Parse JSON command
    cJSON *json_obj = cJSON_Parse(json_command);
    if (!json_obj) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"%s\"}",
                 MQ_ERR_INVALID_JSON, MQ_MSG_INVALID_JSON);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }

    cJSON *command_item = cJSON_GetObjectItem(json_obj, "command");
    if (!command_item || !cJSON_IsString(command_item)) {
        cJSON_Delete(json_obj);
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"%s\"}",
                 MQ_ERR_INVALID_PARAMS, MQ_MSG_INVALID_PARAMS);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }

    const char *command = cJSON_GetStringValue(command_item);
    cJSON *param_item = cJSON_GetObjectItem(json_obj, "parameters");

    mdebug1("Processing FIM JSON command: %s", command);

    cJSON *response_json = cJSON_CreateObject();
    if (!response_json) {
        cJSON_Delete(json_obj);
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"Failed to create response\"}",
                 MQ_ERR_INTERNAL);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }

    int result = 0;
    cJSON *status_item = NULL;
    cJSON *message_item = NULL;
    cJSON *data_item = NULL;

    if (strcmp(command, "pause") == 0) {
        // Call pause function
        result = fim_execute_pause();

        if (result == 0) {
            status_item = cJSON_CreateNumber(MQ_SUCCESS);
            message_item = cJSON_CreateString("FIM module paused successfully");
            data_item = cJSON_CreateObject();
            if (data_item) {
                cJSON_AddStringToObject(data_item, "module", "fim");
                cJSON_AddStringToObject(data_item, "action", "pause");
            }
        } else {
            status_item = cJSON_CreateNumber(MQ_ERR_INTERNAL);
            message_item = cJSON_CreateString("Failed to pause FIM module");
            data_item = cJSON_CreateObject();
        }
    } else if (strcmp(command, "flush") == 0) {
        // Call flush function
        result = fim_execute_flush();

        if (result == 0) {
            status_item = cJSON_CreateNumber(MQ_SUCCESS);
            message_item = cJSON_CreateString("FIM module flush requested");
            data_item = cJSON_CreateObject();
            if (data_item) {
                cJSON_AddStringToObject(data_item, "module", "fim");
                cJSON_AddStringToObject(data_item, "action", "flush");
            }
        } else {
            status_item = cJSON_CreateNumber(MQ_ERR_INTERNAL);
            message_item = cJSON_CreateString("Failed to request FIM module flush");
            data_item = cJSON_CreateObject();
        }
    } else if (strcmp(command, "is_flush_completed") == 0) {
        // Call is_flush_completed function
        result = fim_execute_is_flush_completed();

        if (result == 1) {
            // Flush in progress
            status_item = cJSON_CreateNumber(MQ_SUCCESS);
            message_item = cJSON_CreateString("FIM flush in progress");
            data_item = cJSON_CreateObject();
            if (data_item) {
                cJSON_AddStringToObject(data_item, "module", "fim");
                cJSON_AddStringToObject(data_item, "status", "in_progress");
            }
        } else if (result == 0) {
            // Flush completed successfully
            status_item = cJSON_CreateNumber(MQ_SUCCESS);
            message_item = cJSON_CreateString("FIM flush completed successfully");
            data_item = cJSON_CreateObject();
            if (data_item) {
                cJSON_AddStringToObject(data_item, "module", "fim");
                cJSON_AddStringToObject(data_item, "status", "completed");
                cJSON_AddStringToObject(data_item, "result", "success");
            }
        } else if (result == -1) {
            // Flush completed with error
            status_item = cJSON_CreateNumber(MQ_SUCCESS);
            message_item = cJSON_CreateString("FIM flush completed with error");
            data_item = cJSON_CreateObject();
            if (data_item) {
                cJSON_AddStringToObject(data_item, "module", "fim");
                cJSON_AddStringToObject(data_item, "status", "completed");
                cJSON_AddStringToObject(data_item, "result", "error");
            }
        } else {
            // Unexpected result
            status_item = cJSON_CreateNumber(MQ_ERR_INTERNAL);
            message_item = cJSON_CreateString("Unexpected result from is_flush_completed");
            data_item = cJSON_CreateObject();
        }
    } else if (strcmp(command, "is_pause_completed") == 0) {
        // Call is_pause_completed function
        result = fim_execute_is_pause_completed();

        if (result == 1) {
            // Pause in progress
            status_item = cJSON_CreateNumber(MQ_SUCCESS);
            message_item = cJSON_CreateString("FIM pause in progress");
            data_item = cJSON_CreateObject();
            if (data_item) {
                cJSON_AddStringToObject(data_item, "module", "fim");
                cJSON_AddStringToObject(data_item, "status", "in_progress");
            }
        } else if (result == 0) {
            // Pause completed successfully
            status_item = cJSON_CreateNumber(MQ_SUCCESS);
            message_item = cJSON_CreateString("FIM pause completed successfully");
            data_item = cJSON_CreateObject();
            if (data_item) {
                cJSON_AddStringToObject(data_item, "module", "fim");
                cJSON_AddStringToObject(data_item, "status", "completed");
                cJSON_AddStringToObject(data_item, "result", "success");
            }
        } else {
            // Unexpected result
            status_item = cJSON_CreateNumber(MQ_ERR_INTERNAL);
            message_item = cJSON_CreateString("Unexpected result from is_pause_completed");
            data_item = cJSON_CreateObject();
        }
    } else if (strcmp(command, "get_version") == 0) {
        // Call get_version function
        result = fim_execute_get_version();

        if (result >= 0) {
            status_item = cJSON_CreateNumber(MQ_SUCCESS);
            message_item = cJSON_CreateString("FIM version retrieved");
            data_item = cJSON_CreateObject();
            if (data_item) {
                cJSON_AddNumberToObject(data_item, "version", result);
            }
        } else {
            status_item = cJSON_CreateNumber(MQ_ERR_INTERNAL);
            message_item = cJSON_CreateString("Failed to get FIM version");
            data_item = cJSON_CreateObject();
        }
    } else if (strcmp(command, "set_version") == 0) {
        // Extract version from parameters
        int version = -1;
        if (param_item && cJSON_IsObject(param_item)) {
            cJSON *version_item = cJSON_GetObjectItem(param_item, "version");
            if (version_item && cJSON_IsNumber(version_item)) {
                version = (int)cJSON_GetNumberValue(version_item);
            }
        }

        if (version < 0) {
            status_item = cJSON_CreateNumber(MQ_ERR_INVALID_PARAMS);
            message_item = cJSON_CreateString("Invalid or missing version parameter");
            data_item = cJSON_CreateObject();
        } else {
            // Call set_version function
            result = fim_execute_set_version(version);

            if (result == 0) {
                status_item = cJSON_CreateNumber(MQ_SUCCESS);
                message_item = cJSON_CreateString("FIM version set successfully");
                data_item = cJSON_CreateObject();
                if (data_item) {
                    cJSON_AddNumberToObject(data_item, "version", version);
                }
            } else {
                status_item = cJSON_CreateNumber(MQ_ERR_INTERNAL);
                message_item = cJSON_CreateString("Failed to set FIM version");
                data_item = cJSON_CreateObject();
            }
        }
    } else if (strcmp(command, "resume") == 0) {
        // Call resume function
        result = fim_execute_resume();

        if (result == 0) {
            status_item = cJSON_CreateNumber(MQ_SUCCESS);
            message_item = cJSON_CreateString("FIM module resumed successfully");
            data_item = cJSON_CreateObject();
            if (data_item) {
                cJSON_AddStringToObject(data_item, "module", "fim");
                cJSON_AddStringToObject(data_item, "action", "resume");
            }
        } else {
            status_item = cJSON_CreateNumber(MQ_ERR_INTERNAL);
            message_item = cJSON_CreateString("Failed to resume FIM module");
            data_item = cJSON_CreateObject();
        }
    } else {
        status_item = cJSON_CreateNumber(MQ_ERR_UNKNOWN_COMMAND);
        message_item = cJSON_CreateString("Unknown FIM command");
        data_item = cJSON_CreateObject();
        if (data_item) {
            cJSON_AddStringToObject(data_item, "command", command);
        }
    }

    // Ensure all items were created
    if (!status_item || !message_item || !data_item) {
        if (status_item) cJSON_Delete(status_item);
        if (message_item) cJSON_Delete(message_item);
        if (data_item) cJSON_Delete(data_item);
        cJSON_Delete(response_json);
        cJSON_Delete(json_obj);

        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"Failed to create response items\"}",
                 MQ_ERR_INTERNAL);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }

    cJSON_AddItemToObject(response_json, "error", status_item);
    cJSON_AddItemToObject(response_json, "message", message_item);
    cJSON_AddItemToObject(response_json, "data", data_item);

    char *json_string = cJSON_PrintUnformatted(response_json);
    if (!json_string) {
        cJSON_Delete(response_json);
        cJSON_Delete(json_obj);

        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"Failed to serialize response\"}",
                 MQ_ERR_INTERNAL);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }

    os_strdup(json_string, *output);

    os_free(json_string);
    cJSON_Delete(response_json);
    cJSON_Delete(json_obj);

    return strlen(*output);
}

size_t syscom_handle_json_query(char * json_command, char ** output) {
    assert(json_command != NULL);
    assert(output != NULL);

    if (syscheck.disabled) {
        mdebug1("FIM module is disabled");
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"%s\"}",
                 MQ_ERR_MODULE_DISABLED, MQ_MSG_MODULE_DISABLED);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }

    cJSON *json_obj = cJSON_Parse(json_command);
    if (!json_obj) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"%s\"}",
                 MQ_ERR_INVALID_JSON, MQ_MSG_INVALID_JSON);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }

    cJSON *command_item = cJSON_GetObjectItem(json_obj, "command");
    if (!command_item || !cJSON_IsString(command_item)) {
        cJSON_Delete(json_obj);
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"%s\"}",
                 MQ_ERR_INVALID_PARAMS, MQ_MSG_INVALID_PARAMS);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }

    const char *command = cJSON_GetStringValue(command_item);
    mdebug1("Processing JSON FIM command: %s", command);

    // Check if command is one of the coordination commands
    if (strcmp(command, "pause") == 0 ||
        strcmp(command, "flush") == 0 ||
        strcmp(command, "is_flush_completed") == 0 ||
        strcmp(command, "is_pause_completed") == 0 ||
        strcmp(command, "get_version") == 0 ||
        strcmp(command, "set_version") == 0 ||
        strcmp(command, "resume") == 0) {
        // Handle coordination commands
        size_t result = syscom_handle_agent_info_query(json_command, output);
        cJSON_Delete(json_obj);
        return result;
    } else {
        // Unknown command
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg), "{\"error\":%d,\"message\":\"Unknown command: %s\"}",
                 MQ_ERR_UNKNOWN_COMMAND, command);
        cJSON_Delete(json_obj);
        os_strdup(error_msg, *output);
        return strlen(*output);
    }
}

size_t syscom_dispatch(char * command, size_t command_len, char ** output){
    assert(command != NULL);
    assert(output != NULL);

    // Check if this is a JSON command
    if (command[0] == '{') {
        mdebug1("Detected JSON command, routing to JSON handler");
        return syscom_handle_json_query(command, output);
    }

    if (strncmp(command, HC_SK, strlen(HC_SK)) == 0 ||
               strncmp(command, HC_GETCONFIG, strlen(HC_GETCONFIG)) == 0 ||
               strncmp(command, HC_RESTART, strlen(HC_RESTART)) == 0) {
        char *rcv_comm = NULL;
        char *rcv_args = NULL;

        if (strncmp(command, HC_SK, strlen(HC_SK)) == 0) {
            rcv_comm = command + strlen(HC_SK);
        } else {
            rcv_comm = command;
        }

        if ((rcv_args = strchr(rcv_comm, ' '))){
            *rcv_args = '\0';
            rcv_args++;
        }

        if (strcmp(rcv_comm, "getconfig") == 0){
            // getconfig section
            if (!rcv_args){
                mdebug1(FIM_SYSCOM_ARGUMENTS, "getconfig");
                os_strdup("err SYSCOM getconfig needs arguments", *output);
                return strlen(*output);
            }
            return syscom_getconfig(rcv_args, output);
        } else if (strcmp(rcv_comm, "restart") == 0) {
            os_set_restart_syscheck();
            return 0;
        }
    } else if (strncmp(command, FIM_SYNC_HEADER, strlen(FIM_SYNC_HEADER)) == 0) {
        if (syscheck.enable_synchronization) {
            size_t header_len = strlen(FIM_SYNC_HEADER);
            const uint8_t *data = (const uint8_t *)(command + header_len);
            size_t data_len = command_len - header_len;

            bool ret = false;
            ret = asp_parse_response_buffer(syscheck.sync_handle, data, data_len);

            if (!ret) {
                mdebug1("WMCOM Error syncing module");
                os_strdup("err Error syncing module", *output);
                return strlen(*output);
            }

            return 0;
        } else {
            mdebug1("FIM synchronization is disabled");
            os_strdup("err FIM synchronization is disabled", *output);
            return strlen(*output);
        }
    }

    mdebug1(FIM_SYSCOM_UNRECOGNIZED_COMMAND, command);
    os_strdup("err Unrecognized command", *output);
    return strlen(*output);
}

// LCOV_EXCL_START
#ifndef WIN32
void * syscom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    mdebug1(FIM_SYSCOM_REQUEST_READY);

    if (sock = OS_BindUnixDomain(SYS_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror(FIM_ERROR_SYSCOM_BIND_SOCKET, SYS_LOCAL_SOCK, errno, strerror(errno));
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit(FIM_CRITICAL_ERROR_SELECT, "syscom_main()", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror(FIM_ERROR_SYSCOM_ACCEPT, strerror(errno));
            }

            continue;
        }

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer,OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror(FIM_ERROR_SYSCOM_RECV_TOOLONG);
            break;

        case -1:
            merror(FIM_ERROR_SYSCOM_RECV, strerror(errno));
            break;

        case 0:
            mdebug1(FIM_SYSCOM_EMPTY_MESSAGE);
            close(peer);
            break;

        case OS_MAXLEN:
            merror(FIM_ERROR_SYSCOM_RECV_MAXLEN, MAX_DYN_STR);
            close(peer);
            break;

        default:
            length = syscom_dispatch(buffer, length, &response);

            if (length > 0) {
                OS_SendSecureTCP(peer, length, response);
            }
            os_free(response);

            close(peer);
        }
        free(buffer);
    }

    mdebug1(FIM_SYSCOM_THREAD_FINISED);

    close(sock);
    return NULL;
}

#endif
// LCOV_EXCL_STOP
