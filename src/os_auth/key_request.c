/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "auth.h"
#include "key_request.h"

static OSHash *request_hash = NULL;
/* Key request queue */
static w_queue_t * request_queue;

const char *exec_params[2] = { "id", "ip" };

key_request_agent_info * key_request_agent_info_init() {
    key_request_agent_info *agent;
    os_malloc(sizeof(key_request_agent_info), agent);
    agent->id = NULL;
    agent->name = NULL;
    agent->key = NULL;
    agent->ip = NULL;
    return agent;
}

void key_request_agent_info_destroy(key_request_agent_info *agent) {
    os_free(agent->id);
    os_free(agent->name);
    os_free(agent->key);
    os_free(agent->ip);
    os_free(agent);
}

key_request_agent_info * get_agent_info_from_json(cJSON *agent_infoJSON, char **error_msg) {
    key_request_agent_info *agent = key_request_agent_info_init();
    int error = 0;
    cJSON *error_message = NULL;
    cJSON *data_json = NULL;
    cJSON *agent_id = NULL;
    cJSON *agent_name = NULL;
    cJSON *agent_address = NULL;
    cJSON *agent_key = NULL;

    cJSON *json_field;

    if (json_field = cJSON_GetObjectItem(agent_infoJSON, "error"), !json_field) {
        mdebug1("Malformed JSON output received. No 'error' field found.");
        goto error;
    }

    error = json_field->valueint;

    if (error) {
        error_message = cJSON_GetObjectItem(agent_infoJSON, "message");
        if (!error_message) {
            mdebug1("Malformed JSON output received. No 'message' field found.");
        } else {
            *error_msg = error_message->valuestring;
        }
        goto error;
    }

    data_json = cJSON_GetObjectItem(agent_infoJSON, "data");
    if (!data_json) {
        mdebug1("Agent data not found.");
        goto error;
    }

    agent_id = cJSON_GetObjectItem(data_json, "id");
    if (!agent_id) {
        mdebug1("Agent ID not found.");
        goto error;
    } else {
        os_strdup(agent_id->valuestring, agent->id);
    }

    agent_name = cJSON_GetObjectItem(data_json, "name");
    if (!agent_name) {
        mdebug1("Agent name not found.");
        goto error;
    } else {
        os_strdup(agent_name->valuestring, agent->name);
    }

    agent_address = cJSON_GetObjectItem(data_json, "ip");
    if (!agent_address) {
        mdebug1("Agent address not found.");
        goto error;
    } else {
        os_strdup(agent_address->valuestring, agent->ip);
    }

    agent_key = cJSON_GetObjectItem(data_json, "key");
    if (!agent_key) {
        mdebug1("Agent key not found.");
        goto error;
    } else {
        os_strdup(agent_key->valuestring, agent->key);
    }

    return agent;

error:
    key_request_agent_info_destroy(agent);
    return NULL;
}

char * key_request_socket_output(request_type_t type, char *request) {
    int sock = 0;
    int i = 0;
    char msg[OS_SIZE_128] = {0};
    int msg_len = 0;
    ssize_t length = 0;
    char *output = NULL;

    // Connect to the socket
    // Three attempts
    for (i = 1; i <= 3; ++i) {
        if (sock = external_socket_connect(config.key_request.socket, config.key_request.timeout), sock >= 0) {
            break;
        } else {
            mdebug1("Could not connect to external socket: %s (%d)", strerror(errno), errno);
            sleep(i);
        }
    }

    if (sock < 0) {
        mwarn("Could not connect to external integration: %s (%d). Discarding request.", strerror(errno), errno);
        return NULL;
    }

    msg_len = snprintf(msg, OS_SIZE_128, "%s:%s", exec_params[type], request);

    if (msg_len > OS_SIZE_128) {
        mdebug1("Request is too long for socket.");
        close(sock);
        return NULL;
    }

    if (send(sock, msg, msg_len, 0) < 0) {
        close(sock);
        return NULL;
    }

    os_calloc(OS_MAXSTR + 1, sizeof(char), output);

    if (length = recv(sock, output, OS_MAXSTR, 0), length < 0) {
        mdebug1("No data received from external socket.");
        os_free(output);
        close(sock);
        return NULL;
    } else if (length == 0) {
        os_free(output);
        close(sock);
        return NULL;
    } else {
        output[length] = '\0';
    }

    close(sock);

    return output;
}

char * key_request_exec_output(request_type_t type, char *request) {
    char *command = NULL;
    os_calloc(OS_MAXSTR + 1, sizeof(char), command);
    int result_code = 0;
    int error_flag = 0;
    char *output = NULL;

    if (snprintf(command, OS_MAXSTR, "%s %s %s", config.key_request.exec_path, exec_params[type], request) >= OS_MAXSTR) {
        mdebug1("Request is too long.");
        os_free(command);
        return NULL;
    }

    switch (wm_exec(command, &output, &result_code, config.key_request.timeout, NULL)) {
        case 0:
            if (result_code != 0) {
                error_flag = 1;
                mwarn("Key request integration (%s) returned code %d.", config.key_request.exec_path, result_code);
            }
        break;
        case KR_ERROR_TIMEOUT:
            error_flag = 1;
            mwarn("Timeout received while running key request integration (%s)", config.key_request.exec_path);
        break;
        default:
            error_flag = 1;
            if (result_code == EXECVE_ERROR) {
                mwarn("Cannot run key request integration (%s): path is invalid or file has insufficient permissions.", config.key_request.exec_path);
            } else {
                mwarn("Error executing [%s]", config.key_request.exec_path);
            }
    }

    os_free(command);

    if (error_flag) {
        os_free(output);
        return NULL;
    }

    return output;
}

void* run_key_request_main(__attribute__((unused)) void *arg) {
    int sock;
    unsigned int i;
    char buffer[OS_MAXSTR + 1] = {0};
    char * copy;

    authd_sigblock();

    minfo("Key Request module started.");

    /* Init the request hash table */
    request_hash = OSHash_Create();

    if (!request_hash) {
        merror(LIST_ERROR);
        pthread_exit(NULL);
    }

    /* Init the queue input */
    request_queue = queue_init(config.key_request.queue_size);

    if ((sock = StartMQ(KEY_REQUEST_SOCK, READ, 0)) < 0) {
        merror(QUEUE_ERROR, KEY_REQUEST_SOCK, strerror(errno));
        pthread_exit(NULL);
    }

    for(i = 0; i < config.key_request.threads; i++){
        w_create_thread(key_request_dispatch_thread, NULL);
    }

    while (running) {
        if (config.timeout_sec || config.timeout_usec) {
            if (OS_SetRecvTimeout(sock, config.timeout_sec, config.timeout_usec) < 0) {
                static int reported = 0;

                if (!reported) {
                    int error = errno;
                    merror("Could not set timeout to internal socket: %s (%d)", strerror(error), error);
                    reported = 1;
                }
            }
        }

        if (OS_RecvUnix(sock, OS_MAXSTR, buffer) > 0) {
            if(OSHash_Get_ex(request_hash, buffer)){
                mdebug2("Request '%s' already being processed. Discarding request.", buffer);
                continue;
            }

            OSHash_Add_ex(request_hash, buffer, (void *)1);

            os_strdup(buffer, copy);

            if(queue_full(request_queue)){
                mdebug1("Request queue is full. Discarding request.");
                os_free(copy);
                OSHash_Delete_ex(request_hash, buffer);
                continue;
            }

            int result = queue_push_ex(request_queue, copy);

            if(result < 0){
                mdebug1("Request queue is full. Discarding request.");
                os_free(copy);
                OSHash_Delete_ex(request_hash, buffer);
                continue;
            }
        }
    }
    close(sock);
    return NULL;
}

/* Thread for key request connection pool */
int key_request_dispatch(char * buffer) {
    char * request;
    char * tmp_buffer;
    char *output = NULL;
    int header_length = 3;
    cJSON *agent_infoJSON;
    request_type_t type;

    tmp_buffer = buffer;

    // Get the type of request
    if(strncmp("ip:", tmp_buffer, header_length) == 0) {
        type = K_TYPE_IP;
    } else if(strncmp("id:", tmp_buffer, header_length) == 0) {
        type = K_TYPE_ID;
    } else {
        type = K_TYPE_UNKNOWN;
    }

    switch (type) {
        case K_TYPE_ID:
            tmp_buffer += header_length;
            request = tmp_buffer;

            if(strlen(request) > 8) {
                mdebug1("Agent ID is too long.");
                OSHash_Delete_ex(request_hash, buffer);
                return OS_INVALID;
            }
            break;

        case K_TYPE_IP:
            tmp_buffer += header_length;
            request = tmp_buffer;

            if (strlen(request) > 19) {
                mdebug1("Agent IP is too long.");
                OSHash_Delete_ex(request_hash, buffer);
                return OS_INVALID;
            }
            break;

        default:
            merror("Invalid request '%s' received in Agent key request.", buffer);
            OSHash_Delete_ex(request_hash, buffer);
            return OS_INVALID;
    }

    /* Send request to external executable by socket */
    if (config.key_request.socket) {

        output = key_request_socket_output(type, request);

        if (output) {
            mdebug2("Socket output: %s", output);
        } else {
            if (config.key_request.exec_path) {
                minfo("Socket connect fail. Trying to run 'exec_path'");
                output = key_request_exec_output(type, request);
            }
            if (output) {
                mdebug2("Exec output: %s", output);
            } else {
                OSHash_Delete_ex(request_hash, buffer);
                return OS_INVALID;
            }
        }
    } else {

        output = key_request_exec_output(type, request);

        if (output) {
            mdebug2("Exec output: %s", output);
        } else {
            OSHash_Delete_ex(request_hash, buffer);
            return OS_INVALID;
        }
    }

    const char *jsonErrPtr = NULL;
    agent_infoJSON = cJSON_ParseWithOpts(output, &jsonErrPtr, 0);
    os_free(output);

    if (!agent_infoJSON) {
        mdebug1("Error parsing JSON event (%s)", jsonErrPtr ? jsonErrPtr : "");
    } else {
        char *error_msg = NULL;
        key_request_agent_info *agent = get_agent_info_from_json(agent_infoJSON, &error_msg);

        if (!agent) {
            if (error_msg) {
                mdebug1("Could not get a key from %s %s. Error: '%s'", type == K_TYPE_ID ? "ID" : "IP",
                        request, error_msg && *error_msg != '\0' ? error_msg : "unknown");
            }
            cJSON_Delete(agent_infoJSON);
            OSHash_Delete_ex(request_hash, buffer);
            return OS_INVALID;
        }

        char response[OS_SIZE_2048] = {'\0'};

        if (config.worker_node) {
            char *new_id = NULL;
            char *new_key = NULL;

            mdebug1("Forwarding agent key request response to the master node for agent '%s'", agent->id);
            if (0 == w_request_agent_add_clustered(response, agent->name, agent->ip, NULL, agent->key, &new_id, &new_key, &config.force_options, agent->id)) {
                mdebug1("Agent key request response forwarded to the master node for agent '%s'", agent->id);
                os_free(new_id);
                os_free(new_key);
            }
        } else {
            cJSON * json_response = NULL;
            mdebug1("Requesting local addition for agent '%s' from the agent key request.", agent->id);
            json_response = local_add(agent->id, agent->name, agent->ip, NULL, agent->key, NULL, &config.force_options);
            if (json_response) {
                output = cJSON_PrintUnformatted(json_response);
                cJSON_Delete(json_response);
                mdebug2("Agent key request addition response: '%s'", output);
                os_free(output);
            }
        }

        cJSON_Delete(agent_infoJSON);
        key_request_agent_info_destroy(agent);
    }

    OSHash_Delete_ex(request_hash, buffer);
    return 0;
}

void * key_request_dispatch_thread(__attribute__((unused)) void *arg) {
    char *msg = NULL;

    authd_sigblock();

    while (running) {

        /* Receive request from queue */
        if (msg = queue_pop_ex(request_queue), msg) {
            if (key_request_dispatch(msg) < 0) {
                mdebug1("Error getting external key.");
            }
            os_free(msg);
        }
    }
    return NULL;
}
