/* Remote request listener
 * Copyright (C) 2015, Wazuh Inc.
 * May 16, 2022.
 *
 * This program is os_free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#include <shared.h>
#include "os_net/os_net.h"
#include "remoted.h"
#include "state.h"

typedef enum _error_codes {
    ERROR_OK = 0,
    ERROR_DUE,
    ERROR_INVALID_INPUT,
    ERROR_EMPTY_COMMAND,
    ERROR_UNRECOGNIZED_COMMAND,
    ERROR_EMPTY_PARAMATERS,
    ERROR_EMPTY_SECTION,
    ERROR_UNRECOGNIZED_SECTION,
    ERROR_INVALID_AGENTS,
    ERROR_EMPTY_AGENTS,
    ERROR_EMPTY_LASTID,
    ERROR_TOO_MANY_AGENTS,
    ERROR_EMPTY_AGENT_OR_MD5
} error_codes;

const char * error_messages[] = {
    [ERROR_OK] = "ok",
    [ERROR_DUE] = "due",
    [ERROR_INVALID_INPUT] = "Invalid JSON input",
    [ERROR_EMPTY_COMMAND] = "Empty command",
    [ERROR_UNRECOGNIZED_COMMAND] = "Unrecognized command",
    [ERROR_EMPTY_PARAMATERS] = "Empty parameters",
    [ERROR_EMPTY_SECTION] = "Empty section",
    [ERROR_UNRECOGNIZED_SECTION] = "Unrecognized or not configured section",
    [ERROR_INVALID_AGENTS] = "Invalid agents parameter",
    [ERROR_EMPTY_AGENTS] = "Error getting agents from DB",
    [ERROR_EMPTY_LASTID] = "Empty last id",
    [ERROR_TOO_MANY_AGENTS] = "Too many agents",
    [ERROR_EMPTY_AGENT_OR_MD5] = "Invalid agent or md5 parameter"
};

/**
 * Format message into the response format
 * @param error_code code error
 * @param message string message of the error
 * @param data_json data to return from request
 * @return string meessage with the response format
 * */
STATIC char* remcom_output_builder(int error_code, const char* message, cJSON* data_json);

/**
 * @brief Check and dexecute the input request
 * @param request message received from api
 * @param output the response to send
 * @return the size of the string "output" containing the configuration
 */
STATIC size_t remcom_dispatch(char* request, char** output);

/**
 * @brief Process the message received to send the configuration requested
 * @param section contains the name of configuration requested
 * @return JSON string
 */
STATIC cJSON* remcom_getconfig(const char* section);


STATIC char* remcom_output_builder(int error_code, const char* message, cJSON* data_json) {
    cJSON* root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "error", error_code);
    cJSON_AddStringToObject(root, "message", message);
    cJSON_AddItemToObject(root, "data", data_json ? data_json : cJSON_CreateObject());

    char *msg_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return msg_string;
}

STATIC size_t remcom_dispatch(char* request, char** output) {
    cJSON *request_json = NULL;
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    cJSON *section_json = NULL;
    cJSON *config_json = NULL;
    cJSON *agents_json = NULL;
    cJSON *last_id_json = NULL;
    cJSON *agent_json = NULL;
    cJSON *md5_json = NULL;
    const char *json_err;
    int *agents_ids;
    int count;
    int sock = -1;

    if (request_json = cJSON_ParseWithOpts(request, &json_err, 0), !request_json) {
        *output = remcom_output_builder(ERROR_INVALID_INPUT, error_messages[ERROR_INVALID_INPUT], NULL);
        return strlen(*output);
    }

    if (command_json = cJSON_GetObjectItem(request_json, "command"), cJSON_IsString(command_json)) {
        if (strcmp(command_json->valuestring, "getstats") == 0) {
            *output = remcom_output_builder(ERROR_OK, error_messages[ERROR_OK], rem_create_state_json());
        } else if (strcmp(command_json->valuestring, "getagentsstats") == 0) {
            if (parameters_json = cJSON_GetObjectItem(request_json, "parameters"), cJSON_IsObject(parameters_json)) {
                agents_json = cJSON_GetObjectItem(parameters_json, "agents");
                if (cJSON_IsArray(agents_json)) {
                    if (cJSON_GetArraySize(agents_json) <  REM_MAX_NUM_AGENTS_STATS) {
                        agents_ids = json_parse_agents(agents_json);
                        if (agents_ids != NULL) {
                            *output = remcom_output_builder(ERROR_OK, error_messages[ERROR_OK], rem_create_agents_state_json(agents_ids));
                            os_free(agents_ids);
                        } else {
                            *output = remcom_output_builder(ERROR_EMPTY_AGENTS, error_messages[ERROR_EMPTY_AGENTS], NULL);
                        }
                    } else {
                        *output = remcom_output_builder(ERROR_TOO_MANY_AGENTS, error_messages[ERROR_TOO_MANY_AGENTS], NULL);
                    }
                } else if ((cJSON_IsString(agents_json) && strcmp(agents_json->valuestring, "all") == 0)) {
                    last_id_json = cJSON_GetObjectItem(parameters_json, "last_id");
                    if (cJSON_IsNumber(last_id_json) && (last_id_json->valueint >= 0)) {
                        agents_ids = wdb_get_agents_ids_of_current_node(AGENT_CS_ACTIVE, &sock, last_id_json->valueint, REM_MAX_NUM_AGENTS_STATS);
                        if (agents_ids != NULL) {
                            for (count = 0; agents_ids[count] != -1; count++);
                            if (count < REM_MAX_NUM_AGENTS_STATS) {
                                *output = remcom_output_builder(ERROR_OK, error_messages[ERROR_OK], rem_create_agents_state_json(agents_ids));
                            } else {
                                *output = remcom_output_builder(ERROR_DUE, error_messages[ERROR_DUE], rem_create_agents_state_json(agents_ids));
                            }
                            os_free(agents_ids);
                        } else {
                            *output = remcom_output_builder(ERROR_EMPTY_AGENTS, error_messages[ERROR_EMPTY_AGENTS], NULL);
                        }
                    } else {
                        *output = remcom_output_builder(ERROR_EMPTY_LASTID, error_messages[ERROR_EMPTY_LASTID], NULL);
                    }
                } else {
                    *output = remcom_output_builder(ERROR_INVALID_AGENTS, error_messages[ERROR_INVALID_AGENTS], NULL);
                }
            } else {
                *output = remcom_output_builder(ERROR_EMPTY_PARAMATERS, error_messages[ERROR_EMPTY_PARAMATERS], NULL);
            }
        } else if (strcmp(command_json->valuestring, "getconfig") == 0) {
            if (parameters_json = cJSON_GetObjectItem(request_json, "parameters"), cJSON_IsObject(parameters_json)) {
                if (section_json = cJSON_GetObjectItem(parameters_json, "section"), cJSON_IsString(section_json)) {
                    if (config_json = remcom_getconfig(section_json->valuestring), config_json) {
                        *output = remcom_output_builder(ERROR_OK, error_messages[ERROR_OK], config_json);
                    } else {
                        *output = remcom_output_builder(ERROR_UNRECOGNIZED_SECTION, error_messages[ERROR_UNRECOGNIZED_SECTION], NULL);
                    }
                } else {
                    *output = remcom_output_builder(ERROR_EMPTY_SECTION, error_messages[ERROR_EMPTY_SECTION], NULL);
                }
            } else {
                *output = remcom_output_builder(ERROR_EMPTY_PARAMATERS, error_messages[ERROR_EMPTY_PARAMATERS], NULL);
            }
        } else if (strcmp(command_json->valuestring, "assigngroup") == 0) {
            if (parameters_json = cJSON_GetObjectItem(request_json, "parameters"), cJSON_IsObject(parameters_json)) {
                agent_json = cJSON_GetObjectItem(parameters_json, "agent");
                md5_json = cJSON_GetObjectItem(parameters_json, "md5");
                if (cJSON_IsString(agent_json) && cJSON_IsString(md5_json)) {
                    *output = remcom_output_builder(ERROR_OK, error_messages[ERROR_OK], assign_group_to_agent(agent_json->valuestring, md5_json->valuestring));
                } else {
                    *output = remcom_output_builder(ERROR_EMPTY_AGENT_OR_MD5, error_messages[ERROR_EMPTY_AGENT_OR_MD5], NULL);
                }
            } else {
                *output = remcom_output_builder(ERROR_EMPTY_PARAMATERS, error_messages[ERROR_EMPTY_PARAMATERS], NULL);
            }
        } else {
            *output = remcom_output_builder(ERROR_UNRECOGNIZED_COMMAND, error_messages[ERROR_UNRECOGNIZED_COMMAND], NULL);
        }
    } else {
        *output = remcom_output_builder(ERROR_EMPTY_COMMAND, error_messages[ERROR_EMPTY_COMMAND], NULL);
    }

    cJSON_Delete(request_json);

    return strlen(*output);
}

STATIC cJSON* remcom_getconfig(const char* section) {
    if (strcmp(section, "remote") == 0) {
        return getRemoteConfig();
    }
    else if (strcmp(section, "internal") == 0) {
        return getRemoteInternalConfig();
    }
    else if (strcmp(section, "global") == 0) {
        return getRemoteGlobalConfig();
    }
    return NULL;
}

void * remcom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    mdebug1("Local requests thread ready");

    if (sock = OS_BindUnixDomain(REMOTE_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': (%d) '%s'", REMOTE_LOCAL_SOCK, errno, strerror(errno));
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("At select(): '%s'", strerror(errno));
            }
            continue;
        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At accept(): '%s'", strerror(errno));
            }
            continue;
        }
        os_calloc(OS_MAXSTR, sizeof(char), buffer);

        switch (length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror("At OS_RecvSecureTCP(): response size is bigger than expected");
            break;

        case -1:
            merror("At OS_RecvSecureTCP(): '%s'", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client");
            close(peer);
            break;

        case OS_MAXLEN:
            merror("Received message > '%i'", MAX_DYN_STR);
            close(peer);
            break;

        default:
            if (buffer[0] == '{') {
                length = remcom_dispatch(buffer, &response);
                OS_SendSecureTCP(peer, length, response);
                os_free(response);
                close(peer);
            } else {
                req_sender(peer, buffer, length);
            }
        }
        os_free(buffer);

    #ifdef WAZUH_UNIT_TESTING
        break;
    #endif
    }

    mdebug1("Local requests thread finished");

    close(sock);
    return NULL;
}
