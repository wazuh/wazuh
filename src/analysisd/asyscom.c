/* Remote request listener
 * Copyright (C) 2015, Wazuh Inc.
 * Mar 26, 2018.
 *
 * This program is free software; you can redistribute it
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
#include "analysisd.h"
#include "state.h"
#include "config.h"

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
    ERROR_TOO_MANY_AGENTS
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
    [ERROR_TOO_MANY_AGENTS] = "Too many agents"
};

/**
 * Format message into the response format
 * @param error_code code error
 * @param message string message of the error
 * @param data_json data to return from request
 * @return string meessage with the response format
 * */
STATIC char* asyscom_output_builder(int error_code, const char* message, cJSON* data_json);

/**
 * @brief Check that request is to get a configuration
 * @param request message received from api
 * @param output the configuration to send
 * @return the size of the string "output" containing the configuration
 */
STATIC size_t asyscom_dispatch(char* request, char** output);

/**
 * @brief Process the message received to send the configuration requested
 * @param section contains the name of configuration requested
 * @return JSON string
 */
STATIC cJSON* asyscom_getconfig(const char* section);


STATIC char* asyscom_output_builder(int error_code, const char* message, cJSON* data_json) {
    cJSON* root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "error", error_code);
    cJSON_AddStringToObject(root, "message", message);
    cJSON_AddItemToObject(root, "data", data_json ? data_json : cJSON_CreateObject());

    char *msg_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return msg_string;
}

STATIC size_t asyscom_dispatch(char* request, char** output) {
    cJSON *request_json = NULL;
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    cJSON *section_json = NULL;
    cJSON *config_json = NULL;
    cJSON *agents_json = NULL;
    cJSON *last_id_json = NULL;
    const char *json_err;
    int *agents_ids;
    int count;
    int sock = -1;

    if (request_json = cJSON_ParseWithOpts(request, &json_err, 0), !request_json) {
        *output = asyscom_output_builder(ERROR_INVALID_INPUT, error_messages[ERROR_INVALID_INPUT], NULL);
        return strlen(*output);
    }

    if (command_json = cJSON_GetObjectItem(request_json, "command"), cJSON_IsString(command_json)) {
        if (strcmp(command_json->valuestring, "getstats") == 0) {
            *output = asyscom_output_builder(ERROR_OK, error_messages[ERROR_OK], asys_create_state_json());
        } else if (strcmp(command_json->valuestring, "getagentsstats") == 0) {
            if (parameters_json = cJSON_GetObjectItem(request_json, "parameters"), cJSON_IsObject(parameters_json)) {
                agents_json = cJSON_GetObjectItem(parameters_json, "agents");
                if (cJSON_IsArray(agents_json)) {
                    if (cJSON_GetArraySize(agents_json) <  ASYS_MAX_NUM_AGENTS_STATS) {
                        agents_ids = json_parse_agents(agents_json);
                        if (agents_ids != NULL) {
                            *output = asyscom_output_builder(ERROR_OK, error_messages[ERROR_OK], asys_create_agents_state_json(agents_ids));
                            os_free(agents_ids);
                        } else {
                            *output = asyscom_output_builder(ERROR_EMPTY_AGENTS, error_messages[ERROR_EMPTY_AGENTS], NULL);
                        }
                    } else {
                        *output = asyscom_output_builder(ERROR_TOO_MANY_AGENTS, error_messages[ERROR_TOO_MANY_AGENTS], NULL);
                    }
                } else if ((cJSON_IsString(agents_json) && strcmp(agents_json->valuestring, "all") == 0)) {
                    last_id_json = cJSON_GetObjectItem(parameters_json, "last_id");
                    if (cJSON_IsNumber(last_id_json) && (last_id_json->valueint >= 0)) {
                        agents_ids = wdb_get_agents_ids_of_current_node(AGENT_CS_ACTIVE, &sock, last_id_json->valueint, ASYS_MAX_NUM_AGENTS_STATS);
                        if (agents_ids != NULL) {
                            for (count = 0; agents_ids[count] != -1; count++);
                            if (count < ASYS_MAX_NUM_AGENTS_STATS) {
                                *output = asyscom_output_builder(ERROR_OK, error_messages[ERROR_OK], asys_create_agents_state_json(agents_ids));
                            } else {
                                *output = asyscom_output_builder(ERROR_DUE, error_messages[ERROR_DUE], asys_create_agents_state_json(agents_ids));
                            }
                            os_free(agents_ids);
                        } else {
                            *output = asyscom_output_builder(ERROR_EMPTY_AGENTS, error_messages[ERROR_EMPTY_AGENTS], NULL);
                        }
                    } else {
                        *output = asyscom_output_builder(ERROR_EMPTY_LASTID, error_messages[ERROR_EMPTY_LASTID], NULL);
                    }
                } else {
                    *output = asyscom_output_builder(ERROR_INVALID_AGENTS, error_messages[ERROR_INVALID_AGENTS], NULL);
                }
            } else {
                *output = asyscom_output_builder(ERROR_EMPTY_PARAMATERS, error_messages[ERROR_EMPTY_PARAMATERS], NULL);
            }
        } else if (strcmp(command_json->valuestring, "getconfig") == 0) {
            if (parameters_json = cJSON_GetObjectItem(request_json, "parameters"), cJSON_IsObject(parameters_json)) {
                if (section_json = cJSON_GetObjectItem(parameters_json, "section"), cJSON_IsString(section_json)) {
                    if (config_json = asyscom_getconfig(section_json->valuestring), config_json) {
                        *output = asyscom_output_builder(ERROR_OK, error_messages[ERROR_OK], config_json);
                    } else {
                        *output = asyscom_output_builder(ERROR_UNRECOGNIZED_SECTION, error_messages[ERROR_UNRECOGNIZED_SECTION], NULL);
                    }
                } else {
                    *output = asyscom_output_builder(ERROR_EMPTY_SECTION, error_messages[ERROR_EMPTY_SECTION], NULL);
                }
            } else {
                *output = asyscom_output_builder(ERROR_EMPTY_PARAMATERS, error_messages[ERROR_EMPTY_PARAMATERS], NULL);
            }
        } else if (strcmp(command_json->valuestring, "reload-ruleset") == 0) {
            OSList* list_msg = OSList_Create();
            OSList_SetMaxSize(list_msg, ERRORLIST_MAXSIZE);
            OSList_SetFreeDataPointer(list_msg, (void (*)(void*))os_analysisd_free_log_msg);

            bool fail_reload = w_hotreload_reload(list_msg);
            cJSON* data_json = cJSON_CreateArray();

            // Get the error messages
            OSListNode* node_log_msg = OSList_GetFirstNode(list_msg);
            while (node_log_msg != NULL) {
                os_analysisd_log_msg_t* raw_msj = node_log_msg->data;
                char* msg = os_analysisd_string_log_msg(raw_msj);
                cJSON_AddItemToArray(data_json, cJSON_CreateString(msg));
                os_free(msg);
                node_log_msg = OSList_GetNextNode(list_msg);
            }
            OSList_Destroy(list_msg);

            if (fail_reload) {
                *output = asyscom_output_builder(ERROR_DUE, error_messages[ERROR_DUE], data_json);
            } else {
                *output = asyscom_output_builder(ERROR_OK, error_messages[ERROR_OK], data_json);
            }

        } else {
            *output = asyscom_output_builder(ERROR_UNRECOGNIZED_COMMAND, error_messages[ERROR_UNRECOGNIZED_COMMAND], NULL);
        }
    } else {
        *output = asyscom_output_builder(ERROR_EMPTY_COMMAND, error_messages[ERROR_EMPTY_COMMAND], NULL);
    }

    cJSON_Delete(request_json);

    return strlen(*output);
}

STATIC cJSON* asyscom_getconfig(const char* section) {
    if (strcmp(section, "global") == 0) {
        return getGlobalConfig();
    }
    else if (strcmp(section, "active_response") == 0) {
        return getARManagerConfig();
    }
    else if (strcmp(section, "alerts") == 0) {
        return getAlertsConfig();
    }
    else if (strcmp(section, "decoders") == 0) {
        return getDecodersConfig();
    }
    else if (strcmp(section, "rules") == 0) {
        return getRulesConfig();
    }
    else if (strcmp(section, "internal") == 0) {
        return getAnalysisInternalOptions();
    }
    else if (strcmp(section, "command") == 0) {
        return getARCommandsConfig();
    }
    else if (strcmp(section, "labels") == 0) {
        return getManagerLabelsConfig();
    }
    else if (strcmp(section, "rule_test") == 0) {
        return getRuleTestConfig();
    }
    return NULL;
}

void * asyscom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    mdebug1("Local requests thread ready");

    if (sock = OS_BindUnixDomain(ANLSYS_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': (%d) '%s'", ANLSYS_LOCAL_SOCK, errno, strerror(errno));
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

        switch (length = OS_RecvSecureTCP(peer, buffer,OS_MAXSTR), length) {
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
            length = asyscom_dispatch(buffer, &response);
            OS_SendSecureTCP(peer, length, response);
            os_free(response);
            close(peer);
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
