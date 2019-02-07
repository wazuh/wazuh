/*
 * Wazuh Module for remote key requests
 * Copyright (C) 2015-2019, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include "wmodules.h"
#include <os_net/os_net.h>
#include "shared.h"

#define RELAUNCH_TIME 300

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

static void * wm_key_request_main(wm_krequest_t * data);   // Module main function. It won't return
static void wm_key_request_destroy(wm_krequest_t * data);  // Destroy data
cJSON *wm_key_request_dump(const wm_krequest_t * data);     // Read config

void * w_request_thread(const wm_krequest_t *data);

// Dispatch request. Write the output into the same input buffer.
static int wm_key_request_dispatch(char * buffer,const wm_krequest_t * data);

static int external_socket_connect(char *socket_path, int repsonse_timeout);
void * w_socket_launcher(void * args);

/* Decode rootcheck input queue */
static w_queue_t * request_queue;

static OSHash *request_hash = NULL;

const char *exec_params[2] = { "id", "ip" };

const wm_context WM_KEY_REQUEST_CONTEXT = {
    KEY_WM_NAME,
    (wm_routine)wm_key_request_main,
    (wm_routine)wm_key_request_destroy,
    (cJSON * (*)(const void *))wm_key_request_dump
};

typedef enum _request_type{
    W_TYPE_ID,W_TYPE_IP
} _request_type_t;

// Module main function. It won't return
void * wm_key_request_main(wm_krequest_t * data) {
    int sock;
    int recv;
    unsigned int i;
    char buffer[OS_MAXSTR + 1];
    char * copy;

    // If module is disabled, exit
    if (data->enabled) {
        minfo("Module started");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    /* Init the request hash table */
    request_hash = OSHash_Create();

    if (!request_hash) {
        merror(LIST_ERROR);
        pthread_exit(NULL);
    }

    /* Init the queue input */
    request_queue = queue_init(data->queue_size);

    if ((sock = StartMQ(WM_KEY_REQUEST_SOCK_PATH, READ)) < 0) {
        merror(QUEUE_ERROR, WM_KEY_REQUEST_SOCK_PATH, strerror(errno));
        pthread_exit(NULL);
    }

    // Run integration daemon, if socket is defined and not available

    if (data->socket && data->exec_path) {
        int sock_int = external_socket_connect(data->socket, data->timeout);

        if (sock_int < 0) {
            minfo("Integration connection is down. Running integration.");
            w_create_thread(w_socket_launcher, data->exec_path);
        } else {
            close(sock_int);
            minfo("Integration connection is up.");
        }
    }

    for(i = 0; i < data->threads;i++){
        w_create_thread(w_request_thread,data);
    }

    while (1) {

        if (recv = OS_RecvUnix(sock, OS_MAXSTR, buffer),recv) {

            if(OSHash_Get_ex(request_hash,buffer)){
                mdebug2("Request '%s' already being processed. Discarding...",buffer);
                continue;
            }

            OSHash_Add_ex(request_hash,buffer,(void *)1);

            os_strdup(buffer, copy);

            if(queue_full(request_queue)){
                mdebug1("Request queue is full. Discarding...");
                os_free(copy);
                OSHash_Delete_ex(request_hash,buffer);
                continue;
            }

            int result = queue_push_ex(request_queue,copy);

            if(result < 0){
                mdebug1("Request queue is full. Discarding...");
                os_free(copy);
                OSHash_Delete_ex(request_hash,buffer);
                continue;
            }
        }
    }
    return NULL;
}

int wm_key_request_dispatch(char * buffer, const wm_krequest_t * data) {
    char * request;
    char * tmp_buffer;
    char *output = NULL;
    int result_code = 0;
    int header_length = 3;
    cJSON *agent_infoJSON;
    _request_type_t type;

    tmp_buffer = buffer;

    // Get the type of request
    if(strncmp("ip:",tmp_buffer,header_length) == 0) {
        type = W_TYPE_IP;
    }else if(strncmp("id:",tmp_buffer,header_length) == 0){
        type = W_TYPE_ID;
    } else {
        mdebug1("Wrong type of request");
        OSHash_Delete_ex(request_hash,buffer);
        return -1;
    }

    switch (type) {
        case W_TYPE_ID:
            tmp_buffer+=header_length;
            request = tmp_buffer;

            if(strlen(request) > 8) {
                mdebug1(" Agent ID is too long");
                OSHash_Delete_ex(request_hash,buffer);
                return -1;
            }
            break;

        case W_TYPE_IP:
            tmp_buffer+=header_length;
            request = tmp_buffer;

            if(strlen(request) > 19) {
                mdebug1("Agent IP is too long");
                OSHash_Delete_ex(request_hash,buffer);
                return -1;
            }
            break;

        default:
            mdebug1("Invalid request");
            OSHash_Delete_ex(request_hash,buffer);
            return -1;
    }

    /* Send request to external executable by socket */
    if(data->socket) {
        int sock;
        int i;
        char msg[OS_SIZE_128] = {0};
        int msg_len;
        ssize_t length;

        // Connect to the socket
        // Three attempts

        for (i = 1; i <= 3; ++i) {
            if (sock = external_socket_connect(data->socket, data->timeout), sock >= 0) {
                break;
            } else {
                mdebug1("Could not connect to external socket: %s (%d)", strerror(errno), errno);
                sleep(i);
            }
        }

        if (sock < 0) {
            mwarn("Could not connect to external integration: %s (%d). Discarding request.", strerror(errno), errno);
            OSHash_Delete_ex(request_hash,buffer);
            return -1;
        }

        msg_len = snprintf(msg, OS_SIZE_128,"%s:%s", exec_params[type], request);

        if (msg_len > OS_SIZE_128) {
            mdebug1("Request is too long for socket.");
            OSHash_Delete_ex(request_hash,buffer);
            close(sock);
            return -1;
        }

        if (send(sock, msg, msg_len, 0) < 0) {
            OSHash_Delete_ex(request_hash,buffer);
            close(sock);
            return -1;
        }

        os_calloc(OS_MAXSTR + 1,sizeof(char),output);

        if (length = recv(sock, output, OS_MAXSTR,0), length < 0) {
            mdebug1("No data received from external socket");
            os_free(output);
            OSHash_Delete_ex(request_hash,buffer);
            close(sock);
            return -1;
        } else if (length == 0) {
            os_free(output);
            OSHash_Delete_ex(request_hash,buffer);
            close(sock);
            return -1;
        } else {
            output[length] = '\0';
        }

        close(sock);
    } else {
        /* Execute external program */

        char *command = NULL;
        os_calloc(OS_MAXSTR + 1, sizeof(char), command);

        if (snprintf(command, OS_MAXSTR, "%s %s %s", data->exec_path, exec_params[type], request) >= OS_MAXSTR) {
            mdebug1("Request is too long.");
            os_free(command);
            OSHash_Delete_ex(request_hash, buffer);
            return -1;
        }

        if (wm_exec(command, &output, &result_code, data->timeout, NULL) < 0) {
            if (result_code == EXECVE_ERROR) {
                mwarn("Cannot run key pulling integration (%s): path is invalid or file has insufficient permissions.", data->exec_path);
            } else {
                mwarn("Error executing [%s]", data->exec_path);
            }

            os_free(command);
            OSHash_Delete_ex(request_hash,buffer);
            return -1;
        } else if (result_code != 0) {
            mwarn("Key pulling integration (%s) returned code %d.", data->exec_path, result_code);
            os_free(command);
            OSHash_Delete_ex(request_hash,buffer);
            return -1;
        } else {
            os_free(command);
        }
    }

    agent_infoJSON = cJSON_Parse(output);

    if (!agent_infoJSON) {
        mdebug1("Error parsing JSON event. %s", cJSON_GetErrorPtr());
    } else {

        int error = 0;
        cJSON *error_message = NULL;
        cJSON *data_json = NULL;
        cJSON *agent_id = NULL;
        cJSON *agent_name = NULL;
        cJSON *agent_address = NULL;
        cJSON *agent_key = NULL;
        char id[257 + 1] = { '\0' };

        cJSON *json_field;

        if (json_field = cJSON_GetObjectItem(agent_infoJSON,"error"), !json_field) {
            mdebug1("Malformed JSON output received. No 'error' field found");
            cJSON_Delete (agent_infoJSON);
            OSHash_Delete_ex(request_hash,buffer);
            os_free(output);
            return -1;
        }

        error = json_field->valueint;

        if(error) {
            error_message = cJSON_GetObjectItem(agent_infoJSON, "message");
            if (!error_message) {
                mdebug1("Malformed JSON output received. No 'message' field found");
                cJSON_Delete (agent_infoJSON);
                OSHash_Delete_ex(request_hash,buffer);
                os_free(output);
                return -1;
            }
            mdebug1("Could not get a key from %s %s. Error: '%s'.", type == W_TYPE_ID ? "ID" : "IP",
                    request, error_message->valuestring && *error_message->valuestring != '\0' ? error_message->valuestring : "unknown");
            cJSON_Delete (agent_infoJSON);
            OSHash_Delete_ex(request_hash,buffer);
            os_free(output);
            return -1;
        }

        data_json = cJSON_GetObjectItem(agent_infoJSON, "data");
        if (!data_json) {
            mdebug1("Agent data not found.");
            cJSON_Delete (agent_infoJSON);
            OSHash_Delete_ex(request_hash,buffer);
            os_free(output);
            return -1;
        }

        agent_id = cJSON_GetObjectItem(data_json, "id");
        if (!agent_id) {
            mdebug1("Agent ID not found.");
            cJSON_Delete (agent_infoJSON);
            OSHash_Delete_ex(request_hash,buffer);
            os_free(output);
            return -1;
        }

        agent_name = cJSON_GetObjectItem(data_json, "name");
        if (!agent_name) {
            mdebug1("Agent name not found.");
            cJSON_Delete (agent_infoJSON);
            OSHash_Delete_ex(request_hash,buffer);
            os_free(output);
            return -1;
        }

        agent_address = cJSON_GetObjectItem(data_json, "ip");
        if (!agent_address) {
            mdebug1("Agent address not found.");
            cJSON_Delete (agent_infoJSON);
            OSHash_Delete_ex(request_hash,buffer);
            os_free(output);
            return -1;
        }

        agent_key = cJSON_GetObjectItem(data_json, "key");
        if (!agent_key) {
            mdebug1("Agent key not found.");
            cJSON_Delete (agent_infoJSON);
            OSHash_Delete_ex(request_hash,buffer);
            os_free(output);
            return -1;
        }

        int sock;
        if (sock = auth_connect(), sock < 0) {
            mwarn("Could not connect to authd socket. Is authd running?");
        } else {
            auth_add_agent(sock, id, agent_name->valuestring, agent_address->valuestring, agent_key->valuestring, data->force_insert, 1, agent_id->valuestring, 0);
            close(sock);
        }
        cJSON_Delete(agent_infoJSON);
    }

    os_free(output);
    OSHash_Delete_ex(request_hash,buffer);
    return 0;
}

// Destroy data
void wm_key_request_destroy(wm_krequest_t * data) {
    os_free(data);
}

cJSON *wm_key_request_dump(const wm_krequest_t *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd,"enabled","yes");

    if(data->timeout){
        cJSON_AddNumberToObject(wm_wd,"timeout",data->timeout);
    }

    if(data->exec_path){
        cJSON_AddStringToObject(wm_wd,"exec_path",data->exec_path);
    }

    if(data->threads){
        cJSON_AddNumberToObject(wm_wd,"threads",data->threads);
    }

    if(data->queue_size){
        cJSON_AddNumberToObject(wm_wd,"queue_size",data->queue_size);
    }

    cJSON_AddStringToObject(wm_wd, "force_insert", data->force_insert ? "yes" : "no");

    cJSON_AddItemToObject(root,"key-polling",wm_wd);
    return root;
}

void * w_request_thread(const wm_krequest_t *data) {
    char *msg = NULL;

    while(1){

        /* Receive request from queue */
        if (msg = queue_pop_ex(request_queue), msg) {
            if(wm_key_request_dispatch(msg,data) < 0) {
                mdebug1("At w_request_thread(): Error getting external key");
            }
            os_free(msg);
        }
    }
}

static int external_socket_connect(char *socket_path, int repsonse_timeout) {
#ifndef WIN32
    int sock =  OS_ConnectUnixDomain(socket_path, SOCK_STREAM, OS_MAXSTR);

    if (sock < 0) {
        return sock;
    }

    if(OS_SetSendTimeout(sock, 5) < 0) {
        close(sock);
        return -1;
    }

    if(OS_SetRecvTimeout(sock, repsonse_timeout, 0) < 0) {
        close(sock);
        return -1;
    }

    return sock;
#else
    return -1;
#endif
}

void * w_socket_launcher(void * args) {
    char * exec_path = (char *)args;
    char ** argv;
    char buffer[1024];
    time_t time_started;
    wfd_t * wfd;
    int wstatus;
    char * end;

    mdebug1("Running integration daemon: %s", exec_path);

    if (argv = wm_strtok(exec_path), !argv) {
        merror("Could not split integration command: %s", exec_path);
        pthread_exit(NULL);
    }

    // We check that the process is up, otherwise we run it again.

    while (1) {

        // Run integration

        if (wfd = wpopenv(argv[0], argv, W_BIND_STDERR | W_APPEND_POOL), !wfd) {
            mwarn("Couldn not execute '%s'. Trying again in %d seconds.", exec_path, RELAUNCH_TIME);
            sleep(RELAUNCH_TIME);
            continue;
        }

        time_started = time(NULL);

        // Pick stderr

        while (fgets(buffer, sizeof(buffer), wfd->file)) {

            // Remove newline

            if (end = strchr(buffer, '\n'), end) {
                *end = '\0';
            }

            // Dump into the log
            mdebug1("Integration STDERR: %s", buffer);
        }

        // At this point, the process exited

        wstatus = wpclose(wfd);
        wstatus = WEXITSTATUS(wstatus);

        if (wstatus == EXECVE_ERROR) {
            // 0x7F means error in exec
            merror("Cannot run key pulling integration (%s): path is invalid or file has insufficient permissions. Retrying in %d seconds.", exec_path, RELAUNCH_TIME);
            sleep(RELAUNCH_TIME);
        } else if (time(NULL) - time_started < 10) {
            mwarn("Key pulling integration (%s) returned code %d. Retrying in %d seconds.", exec_path, wstatus, RELAUNCH_TIME);
            sleep(RELAUNCH_TIME);
        } else {
            mwarn("Key pulling integration (%s) returned code %d. Restarting.", exec_path, wstatus);
        }
    }


    free_strarray(argv);
    return NULL;
}

#endif
